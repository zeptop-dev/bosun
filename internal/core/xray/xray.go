// Package xray drives an upstream Xray-core binary as a child process.
//
// Xray's HandlerService supports adding and removing users at runtime, so a
// users-only change on VLESS/VMess/Trojan inbounds is applied without a
// restart. Anything else rewrites the config and restarts the process.
package xray

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"

	"gitlab.com/boyang-hu/bosun/internal/core"
	"gitlab.com/boyang-hu/bosun/internal/core/grpcraw"
	"gitlab.com/boyang-hu/bosun/internal/core/subprocess"
	"gitlab.com/boyang-hu/bosun/internal/core/v2stats"
	"gitlab.com/boyang-hu/bosun/pkg/spec"
)

// Options configures the Xray adapter.
type Options struct {
	Binary    string // path to the xray executable
	WorkDir   string // where config.json is written
	APIListen string // gRPC API listen address, e.g. 127.0.0.1:9102
	LogLevel  string // xray loglevel: debug, info, warning, error, none
}

// Core is the Xray adapter.
type Core struct {
	opt Options
	log *slog.Logger

	mu      sync.Mutex
	sup     *subprocess.Supervisor
	conn    *grpc.ClientConn
	applied *state
}

const rpcTimeout = 10 * time.Second

// New returns an adapter; the binary must exist but is not started.
func New(opt Options, log *slog.Logger) (*Core, error) {
	if opt.Binary == "" {
		return nil, fmt.Errorf("xray: binary path is required")
	}
	if _, err := os.Stat(opt.Binary); err != nil {
		return nil, fmt.Errorf("xray: binary: %w", err)
	}
	if opt.WorkDir == "" {
		return nil, fmt.Errorf("xray: work dir is required")
	}
	if opt.APIListen == "" {
		opt.APIListen = "127.0.0.1:9102"
	}
	if opt.LogLevel == "" {
		opt.LogLevel = "warning"
	}
	if err := os.MkdirAll(opt.WorkDir, 0o750); err != nil {
		return nil, err
	}
	return &Core{opt: opt, log: log.With("core", "xray")}, nil
}

func (c *Core) Name() string { return "xray" }

func (c *Core) Capabilities() core.Capabilities {
	return core.Capabilities{
		Protocols:     []spec.Protocol{spec.VLESS, spec.VMess, spec.Trojan, spec.Shadowsocks, spec.SOCKS, spec.HTTP},
		Transports:    []string{"ws", "grpc", "httpupgrade", "xhttp"},
		HotUserReload: true,
	}
}

func (c *Core) Render(node *spec.Node, inbounds []spec.Inbound, users []spec.User) (*core.Bundle, error) {
	cfg, st, err := render(node, inbounds, users, renderOptions{LogLevel: c.opt.LogLevel, APIListen: c.opt.APIListen})
	if err != nil {
		return nil, err
	}
	return &core.Bundle{Files: map[string][]byte{"config.json": cfg}, Main: "config.json", Payload: st}, nil
}

func (c *Core) configPath(b *core.Bundle) string { return filepath.Join(c.opt.WorkDir, b.Main) }

func (c *Core) write(b *core.Bundle) error {
	for name, content := range b.Files {
		p := filepath.Join(c.opt.WorkDir, name)
		if err := os.WriteFile(p+".tmp", content, 0o640); err != nil {
			return err
		}
		if err := os.Rename(p+".tmp", p); err != nil {
			return err
		}
	}
	return nil
}

// check runs `xray run -test` so a bad config never takes the process down.
func (c *Core) check(ctx context.Context, path string) error {
	cmd := exec.CommandContext(ctx, c.opt.Binary, "run", "-test", "-c", path)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("xray: config check failed: %s", bytes.TrimSpace(out.Bytes()))
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
		c.sup = subprocess.New("xray", c.opt.Binary, []string{"run", "-c", path}, c.opt.WorkDir, c.log)
	}
	sup := c.sup
	c.applied, _ = b.Payload.(*state)
	c.mu.Unlock()
	return sup.Start(ctx)
}

// Apply writes the new config, then either hot-updates users or restarts.
func (c *Core) Apply(ctx context.Context, b *core.Bundle) error {
	if err := c.write(b); err != nil {
		return err
	}
	if err := c.check(ctx, c.configPath(b)); err != nil {
		return err
	}
	next, _ := b.Payload.(*state)
	c.mu.Lock()
	sup := c.sup
	prev := c.applied
	c.mu.Unlock()
	if sup == nil || !sup.Running() {
		return c.Start(ctx, b)
	}
	if prev != nil && next != nil && prev.inboundsKey == next.inboundsKey && c.hotCapable(next) {
		if err := c.hotUpdate(ctx, prev, next); err == nil {
			c.mu.Lock()
			c.applied = next
			c.mu.Unlock()
			return nil
		} else {
			c.log.Warn("hot user update failed, restarting instead", "err", err)
		}
	}
	c.log.Info("applying new config (restart)")
	c.mu.Lock()
	c.applied = next
	c.mu.Unlock()
	return sup.Restart(ctx)
}

func (c *Core) hotCapable(st *state) bool {
	for _, p := range st.inbounds {
		if !hotProtocols[p] {
			return false
		}
	}
	return true
}

// hotUpdate diffs each inbound's users and applies adds/removes.
func (c *Core) hotUpdate(ctx context.Context, prev, next *state) error {
	conn, err := c.dial()
	if err != nil {
		return err
	}
	var added, removed int
	for tag, proto := range next.inbounds {
		adds, removes := diffUsers(prev.users[tag], next.users[tag])
		for _, name := range removes {
			rctx, cancel := context.WithTimeout(ctx, rpcTimeout)
			err := removeUser(rctx, conn, tag, name)
			cancel()
			if err != nil {
				return fmt.Errorf("remove %s from %s: %w", name, tag, err)
			}
			removed++
		}
		for _, u := range adds {
			rctx, cancel := context.WithTimeout(ctx, rpcTimeout)
			err := addUser(rctx, conn, tag, proto, u, next.flows[tag])
			cancel()
			if err != nil {
				return fmt.Errorf("add %s to %s: %w", u.Name, tag, err)
			}
			added++
		}
	}
	c.log.Info("users hot-updated", "added", added, "removed", removed)
	return nil
}

// diffUsers returns users to add (new or with changed credentials, which
// are also listed in removes first) and names to remove.
func diffUsers(prev, next map[string]spec.User) (adds []spec.User, removes []string) {
	for name, u := range next {
		old, ok := prev[name]
		if ok && old.UUID == u.UUID && old.Password == u.Password {
			continue
		}
		if ok {
			removes = append(removes, name)
		}
		adds = append(adds, u)
	}
	for name := range prev {
		if _, keep := next[name]; !keep {
			removes = append(removes, name)
		}
	}
	return adds, removes
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
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	rctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	return v2stats.QueryUsers(rctx, conn, methodQueryStats, "user>>>", reset)
}

func (c *Core) dial() (*grpc.ClientConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn, nil
	}
	conn, err := grpcraw.Dial(c.opt.APIListen)
	if err != nil {
		return nil, err
	}
	c.conn = conn
	return conn, nil
}
