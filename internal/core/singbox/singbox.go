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
	Binary      string // path to the sing-box executable
	WorkDir     string // where config.json is written
	StatsListen string // v2ray_api listen address, e.g. 127.0.0.1:9101
	LogLevel    string
}

// Core is the sing-box adapter.
type Core struct {
	opt Options
	log *slog.Logger

	mu   sync.Mutex
	sup  *subprocess.Supervisor
	conn *grpc.ClientConn

	online *onlineTracker // client IPs per user, from the log (see online.go)
}

// New returns an adapter; the binary must exist but is not started.
func New(opt Options, log *slog.Logger) (*Core, error) {
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
	}
	if opt.LogLevel == "" {
		opt.LogLevel = "info"
	}
	if err := os.MkdirAll(opt.WorkDir, 0o750); err != nil {
		return nil, err
	}
	if err := runas.ChownTree(opt.WorkDir); err != nil {
		return nil, err
	}
	return &Core{opt: opt, log: log.With("core", "singbox"), online: newOnlineTracker()}, nil
}

func (c *Core) Name() string { return "singbox" }

// Capabilities lists what an unmodified upstream sing-box can serve. mieru is
// deliberately absent: upstream sing-box has no mieru inbound.
func (c *Core) Capabilities() core.Capabilities {
	return core.Capabilities{
		Protocols: []spec.Protocol{
			spec.VLESS, spec.VMess, spec.Trojan, spec.Shadowsocks,
			spec.Hysteria2, spec.TUIC, spec.AnyTLS, spec.SOCKS, spec.HTTP, spec.Naive, spec.Snell,
		},
		SnellMultiUser:  true,
		Transports:      []string{"ws", "grpc", "httpupgrade", "http"},
		Shadowsocks2022: true,
		HotUserReload:   false,
	}
}

func (c *Core) Render(node *spec.Node, inbounds []spec.Inbound, users []spec.User) (*core.Bundle, error) {
	// Device limits need the per-connection log lines, which only exist at
	// level info; raise the level while any user carries a limit.
	limited := false
	for _, u := range users {
		if u.DeviceLimit > 0 {
			limited = true
			break
		}
	}
	cfg, err := render(node, inbounds, users, renderOptions{LogLevel: effectiveLogLevel(c.opt.LogLevel, limited), StatsListen: c.opt.StatsListen})
	if err != nil {
		return nil, err
	}
	return &core.Bundle{Files: map[string][]byte{"config.json": cfg}, Main: "config.json"}, nil
}

func (c *Core) configPath(b *core.Bundle) string { return filepath.Join(c.opt.WorkDir, b.Main) }

func (c *Core) write(b *core.Bundle) error {
	for name, content := range b.Files {
		p := filepath.Join(c.opt.WorkDir, name)
		tmp := p + ".tmp"
		if err := os.WriteFile(tmp, content, 0o640); err != nil {
			return err
		}
		if err := os.Rename(tmp, p); err != nil {
			return err
		}
		if err := runas.Chown(p); err != nil {
			return err
		}
	}
	return nil
}

// check runs `sing-box check` so a bad config never takes the process down.
func (c *Core) check(ctx context.Context, path string) error {
	cmd := exec.CommandContext(ctx, c.opt.Binary, "check", "-c", path)
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
	defer c.mu.Unlock()
	if c.sup == nil {
		c.sup = subprocess.New("sing-box", c.opt.Binary, []string{"run", "-c", path, "-D", c.opt.WorkDir, "--disable-color"}, c.opt.WorkDir, c.log).WithLineHook(c.online.feed).WithLogFilter(c.keepLine)
	}
	return c.sup.Start(ctx)
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
	sup := c.sup
	c.mu.Unlock()
	if sup == nil {
		return c.Start(ctx, b)
	}
	c.log.Info("applying new config (restart)")
	return sup.Restart(ctx)
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
	return queryUserStats(ctx, conn, reset)
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
	return v2stats.QueryInbounds(ctx, conn, queryStatsMethod, "inbound>>>", reset)
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
	return c.online.online(), nil
}
