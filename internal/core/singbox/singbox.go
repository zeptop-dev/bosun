// Package singbox drives an upstream sing-box binary as a child process.
//
// sing-box has no runtime user API, so every change (inbounds or users) is a
// full config rewrite plus process restart. The agent batches changes so this
// happens at most once per pull interval.
package singbox

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/zeptop-dev/bosun/internal/runas"

	"google.golang.org/grpc"

	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/core/grpcraw"
	"github.com/zeptop-dev/bosun/internal/core/subprocess"
	"github.com/zeptop-dev/bosun/internal/core/v2stats"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Options configures the sing-box adapter.
type Options struct {
	Distribution string // empty = official singbox; singbox-extended is a separate instance
	Binary       string // path to the sing-box executable
	WorkDir      string // where config.json is written
	StatsListen  string // v2ray_api listen address, e.g. 127.0.0.1:9101
	LogLevel     string
	// ConnSink receives each accepted connection parsed from the log
	// (user "name|tag", client IP, destination); nil = off.
	ConnSink func(user, clientIP, host string, port int, network string)
}

// Core is the sing-box adapter.
type Core struct {
	opt Options
	log *slog.Logger

	mu             sync.Mutex
	sup            *subprocess.Supervisor
	conn           *grpc.ClientConn
	aliases        map[string]string // wire login -> immutable accounting name
	inboundAliases map[string]string // internal UDP listener -> logical inbound
	applied        []byte            // the config the running process was started with

	online *onlineTracker // client IPs per user, from the log (see online.go)
}

type accountingState struct {
	names          map[string]bool
	aliases        map[string]string
	inboundAliases map[string]string
}

func (c *Core) commitAccounting(b *core.Bundle) {
	if st, ok := b.Payload.(*accountingState); ok {
		c.mu.Lock()
		c.aliases, c.inboundAliases = st.aliases, st.inboundAliases
		c.mu.Unlock()
		c.online.setUsers(st.names)
	}
}

// New returns an adapter; the binary must exist but is not started.
func New(opt Options, log *slog.Logger) (*Core, error) {
	if opt.Distribution == "" {
		opt.Distribution = "singbox"
	}
	if opt.Distribution != "singbox" && opt.Distribution != "singbox-extended" {
		return nil, fmt.Errorf("unknown sing-box distribution")
	}
	if opt.Binary == "" {
		return nil, fmt.Errorf("singbox: binary path is required")
	}
	if _, err := os.Stat(opt.Binary); err != nil {
		return nil, fmt.Errorf("singbox: binary: %w", err)
	}
	if opt.WorkDir == "" {
		return nil, fmt.Errorf("singbox: work dir is required")
	}
	if opt.StatsListen == "" {
		opt.StatsListen = "127.0.0.1:9101"
		if opt.Distribution == "singbox-extended" {
			opt.StatsListen = "127.0.0.1:9105"
		}
	}
	if opt.LogLevel == "" {
		opt.LogLevel = "info"
	}
	if err := os.MkdirAll(opt.WorkDir, 0o750); err != nil {
		return nil, err
	}
	// The work dir stays owned by bosun (0755, traversable): a core that
	// owned it could plant a symlink for a later root-run write.
	if err := runas.MkdirRoot(opt.WorkDir); err != nil {
		return nil, err
	}
	c := &Core{opt: opt, log: log.With("core", opt.Distribution)}
	c.online = newOnlineTracker(func(user, clientIP, host string, port int, network string) {
		c.mu.Lock()
		mapped := c.aliases[user]
		c.mu.Unlock()
		if mapped != "" {
			user = mapped
		}
		if opt.ConnSink != nil {
			opt.ConnSink(user, clientIP, host, port, network)
		}
	})
	return c, nil
}

func (c *Core) Name() string { return c.opt.Distribution }

// Capabilities lists what an unmodified upstream sing-box can serve. mieru is
// deliberately absent: upstream sing-box has no mieru inbound.
func (c *Core) Capabilities() core.Capabilities {
	return spec.CapabilitiesForCore(c.Name())
}

func (c *Core) Render(node *spec.Node, inbounds []spec.Inbound, users []spec.User) (*core.Bundle, error) {
	// The log tracker only believes lines naming a user this node serves.
	names := map[string]bool{}
	aliases := map[string]string{}
	inboundAliases := map[string]string{}
	for _, ib := range inbounds {
		if !c.Capabilities().Supports(ib) {
			return nil, fmt.Errorf("%s: incompatible inbound %q", c.Name(), ib.Tag)
		}
		if ib.Protocol == spec.Mieru && strings.EqualFold(ib.MieruTransport, "BOTH") {
			inboundAliases[mieruUDPTag(ib.Tag)] = ib.Tag
		}
		for _, u := range ib.EffectiveUsers(users) {
			names[spec.InboundAuthName(ib, u)] = true
			aliases[spec.InboundAuthName(ib, u)] = spec.InboundUser(u.Name, ib.Tag)
			names[u.Name] = true
		}
	}
	// Device limits need the per-connection log lines, which only exist at
	// level info; raise the level while any user carries a limit.
	limited := false
	for _, u := range users {
		if u.DeviceLimit > 0 {
			limited = true
			break
		}
	}
	cfg, err := render(node, inbounds, users, renderOptions{Distribution: c.Name(), LogLevel: effectiveLogLevel(c.opt.LogLevel, limited), StatsListen: c.opt.StatsListen})
	if err != nil {
		return nil, err
	}
	return &core.Bundle{Files: map[string][]byte{"config.json": cfg}, Main: "config.json", Payload: &accountingState{names, aliases, inboundAliases}}, nil
}

func (c *Core) configPath(b *core.Bundle) string { return filepath.Join(c.opt.WorkDir, b.Main) }

func (c *Core) write(b *core.Bundle) error {
	for name, content := range b.Files {
		p := filepath.Join(c.opt.WorkDir, name)
		if err := runas.WriteFile(p, content, 0o640, true); err != nil {
			return err
		}
	}
	return nil
}

// check runs `sing-box check` so a bad config never takes the process down.
func (c *Core) check(ctx context.Context, path string) error {
	cmd := exec.CommandContext(ctx, c.opt.Binary, "check", "-c", path, "--disable-color")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("singbox: config check failed: %s", bytes.TrimSpace(out.Bytes()))
	}
	return nil
}

func (c *Core) Start(ctx context.Context, b *core.Bundle) error {
	if err := c.write(b); err != nil {
		return err
	}
	path := c.configPath(b)
	if err := c.check(ctx, path); err != nil {
		return err
	}
	c.mu.Lock()
	if c.sup == nil {
		c.sup = subprocess.New("sing-box", c.opt.Binary, []string{"run", "-c", path, "-D", c.opt.WorkDir, "--disable-color"}, c.opt.WorkDir, c.log).WithMarking().WithLineHook(c.online.feed).WithLogFilter(c.keepLine)
	}
	sup := c.sup
	c.mu.Unlock()
	if err := sup.Start(ctx); err != nil {
		return err
	}
	c.commitAccounting(b)
	c.mu.Lock()
	c.applied = b.Files[b.Main]
	c.mu.Unlock()
	return nil
}

var levelRe = regexp.MustCompile(`\b(TRACE|DEBUG|INFO|WARN|ERROR|FATAL|PANIC)\b`)

var levelRank = map[string]int{"trace": 0, "debug": 1, "info": 2, "warn": 3, "error": 4, "fatal": 5, "panic": 6}

// keepLine reports whether a sing-box output line is at or above the
// configured log_level (sing-box itself runs at info for the tracker).
func (c *Core) keepLine(line string) bool {
	want, ok := levelRank[strings.ToLower(c.opt.LogLevel)]
	if !ok {
		return true
	}
	m := levelRe.FindStringSubmatch(line)
	if m == nil {
		return true // startup banners and panics without a level tag
	}
	return levelRank[strings.ToLower(m[1])] >= want
}

func (c *Core) Apply(ctx context.Context, b *core.Bundle) error {
	if err := c.write(b); err != nil {
		return err
	}
	if err := c.check(ctx, c.configPath(b)); err != nil {
		return err
	}
	c.mu.Lock()
	sup, applied := c.sup, c.applied
	c.mu.Unlock()
	if sup == nil {
		return c.Start(ctx, b)
	}
	// sing-box has no hot reload, so any real change is a restart; an
	// identical config must not cut every user's connections just
	// because another core's apply keeps failing and the agent retries.
	if next := b.Files[b.Main]; applied != nil && bytes.Equal(applied, next) && sup.Running() {
		c.commitAccounting(b)
		c.log.Info("config unchanged, keeping the running process")
		return nil
	}
	c.log.Info("applying new config (restart)")
	if err := sup.Restart(ctx); err != nil {
		return err
	}
	c.commitAccounting(b)
	c.mu.Lock()
	c.applied = b.Files[b.Main]
	c.mu.Unlock()
	return nil
}

func (c *Core) Stop(ctx context.Context) error {
	c.mu.Lock()
	sup := c.sup
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	if sup == nil {
		return nil
	}
	return sup.Stop(ctx)
}

func (c *Core) Running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sup != nil && c.sup.Running()
}

func (c *Core) Stats(ctx context.Context, reset bool) (map[string]spec.Traffic, error) {
	c.mu.Lock()
	if c.conn == nil {
		conn, err := grpcraw.Dial(c.opt.StatsListen)
		if err != nil {
			c.mu.Unlock()
			return nil, err
		}
		c.conn = conn
	}
	conn := c.conn
	c.mu.Unlock()
	stats, err := queryUserStats(ctx, conn, reset)
	c.mu.Lock()
	defer c.mu.Unlock()
	return translateTraffic(stats, c.aliases), err
}

// InboundStats implements core.InboundStatser.
func (c *Core) InboundStats(ctx context.Context, reset bool) (map[string]spec.Traffic, error) {
	c.mu.Lock()
	if c.conn == nil {
		conn, err := grpcraw.Dial(c.opt.StatsListen)
		if err != nil {
			c.mu.Unlock()
			return nil, err
		}
		c.conn = conn
	}
	conn := c.conn
	c.mu.Unlock()
	stats, err := v2stats.QueryInbounds(ctx, conn, queryStatsMethod, "inbound>>>", reset)
	c.mu.Lock()
	defer c.mu.Unlock()
	return translateTraffic(stats, c.inboundAliases), err
}

// OutboundStats implements core.OutboundStatser.
func (c *Core) OutboundStats(ctx context.Context, reset bool) (map[string]spec.Traffic, error) {
	c.mu.Lock()
	if c.conn == nil {
		conn, err := grpcraw.Dial(c.opt.StatsListen)
		if err != nil {
			c.mu.Unlock()
			return nil, err
		}
		c.conn = conn
	}
	conn := c.conn
	c.mu.Unlock()
	return v2stats.QueryOutbounds(ctx, conn, queryStatsMethod, "outbound>>>", reset)
}

// effectiveLogLevel returns the sing-box log level to run with: the
// configured one, raised to info when device limits are in use.
func effectiveLogLevel(configured string, limited bool) string {
	if !limited {
		return configured
	}
	switch strings.ToLower(configured) {
	case "trace", "debug", "info":
		return configured
	}
	return "info"
}

// Online implements core.OnlineTracker.
func (c *Core) Online(_ context.Context) (map[string][]string, error) {
	online := c.online.online()
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string][]string{}
	for name, ips := range online {
		if mapped := c.aliases[name]; mapped != "" {
			name = mapped
		}
		out[name] = append(out[name], ips...)
	}
	return out, nil
}

// Check validates a staged bundle without stopping the currently active core.
func (c *Core) Check(ctx context.Context, b *core.Bundle) error {
	if err := c.write(b); err != nil {
		return err
	}
	return c.check(ctx, c.configPath(b))
}

func translateTraffic(in map[string]spec.Traffic, aliases map[string]string) map[string]spec.Traffic {
	out := map[string]spec.Traffic{}
	for key, v := range in {
		if name := aliases[key]; name != "" {
			key = name
		}
		old := out[key]
		old.Up += v.Up
		old.Down += v.Down
		out[key] = old
	}
	return out
}

// ListenerPIDs exposes only the currently supervised generation.
func (c *Core) ListenerPIDs() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sup == nil {
		return nil
	}
	return map[string]int{"*": c.sup.PID()}
}

// Use the same wildcard-family mapping as the actual rendered listener.
func (c *Core) ListenerInbounds(inbounds []spec.Inbound) []spec.Inbound {
	out := append([]spec.Inbound(nil), inbounds...)
	for i := range out {
		out[i].Listen = listenAddr(out[i].Listen)
	}
	return out
}
