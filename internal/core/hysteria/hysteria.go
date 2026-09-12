// Package hysteria drives the official Hysteria 2 server as a child process.
//
// Users never appear in the server config: hysteria asks bosun's HTTP auth
// endpoint on every connection, so user changes are instant and need no
// restart. Traffic comes from hysteria's trafficStats API, keyed by the user
// name bosun returns from auth. Only inbound changes restart the process.
package hysteria

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/core/subprocess"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Options configures the Hysteria adapter.
type Options struct {
	Binary      string
	WorkDir     string
	AuthListen  string // bosun's auth endpoint, e.g. 127.0.0.1:9103
	StatsListen string // hysteria's traffic stats API, e.g. 127.0.0.1:9104
	LogLevel    string // hysteria log level: debug, info, warn, error
}

// Core is the Hysteria adapter.
type Core struct {
	opt    Options
	log    *slog.Logger
	secret string
	stats  *statsClient

	mu      sync.Mutex
	auth    *authServer
	sup     *subprocess.Supervisor
	applied *state
}

const (
	configFile   = "config.yaml"
	readyTimeout = 15 * time.Second
	rpcTimeout   = 10 * time.Second
)

// New returns an adapter; the binary must exist but is not started.
func New(opt Options, log *slog.Logger) (*Core, error) {
	if opt.Binary == "" {
		return nil, fmt.Errorf("hysteria: binary path is required")
	}
	if _, err := os.Stat(opt.Binary); err != nil {
		return nil, fmt.Errorf("hysteria: binary: %w", err)
	}
	if opt.WorkDir == "" {
		return nil, fmt.Errorf("hysteria: work dir is required")
	}
	if opt.AuthListen == "" {
		opt.AuthListen = "127.0.0.1:9103"
	}
	if opt.StatsListen == "" {
		opt.StatsListen = "127.0.0.1:9104"
	}
	if opt.LogLevel == "" {
		opt.LogLevel = "warn"
	}
	if err := os.MkdirAll(opt.WorkDir, 0o750); err != nil {
		return nil, err
	}
	secret := randomSecret()
	return &Core{
		opt:    opt,
		log:    log.With("core", "hysteria"),
		secret: secret,
		stats:  &statsClient{base: "http://" + opt.StatsListen, secret: secret, http: &http.Client{Timeout: rpcTimeout}},
	}, nil
}

func (c *Core) Name() string { return "hysteria" }

func (c *Core) Capabilities() core.Capabilities {
	return core.Capabilities{Protocols: []spec.Protocol{spec.Hysteria2}, HotUserReload: true}
}

func (c *Core) Render(_ *spec.Node, inbounds []spec.Inbound, users []spec.User) (*core.Bundle, error) {
	cfg, st, err := render(inbounds, users, renderOptions{
		AuthURL:     "http://" + c.opt.AuthListen + "/auth",
		StatsListen: c.opt.StatsListen,
		StatsSecret: c.secret,
	})
	if err != nil {
		return nil, err
	}
	return &core.Bundle{Files: map[string][]byte{configFile: cfg}, Main: configFile, Payload: st}, nil
}

func (c *Core) write(b *core.Bundle) error {
	for name, content := range b.Files {
		p := filepath.Join(c.opt.WorkDir, name)
		if err := os.WriteFile(p+".tmp", content, 0o600); err != nil {
			return err
		}
		if err := os.Rename(p+".tmp", p); err != nil {
			return err
		}
	}
	return nil
}

func (c *Core) Start(ctx context.Context, b *core.Bundle) error {
	st, _ := b.Payload.(*state)
	if st == nil {
		return fmt.Errorf("hysteria: bundle without state")
	}
	if err := c.write(b); err != nil {
		return err
	}
	c.mu.Lock()
	if c.auth == nil {
		a, err := newAuthServer(c.opt.AuthListen, c.log)
		if err != nil {
			c.mu.Unlock()
			return fmt.Errorf("hysteria: auth endpoint: %w", err)
		}
		c.auth = a
	}
	c.auth.setUsers(st.users)
	if c.sup == nil {
		c.sup = subprocess.New("hysteria", c.opt.Binary,
			[]string{"server", "-c", filepath.Join(c.opt.WorkDir, configFile), "--log-level", c.opt.LogLevel, "--disable-update-check"},
			c.opt.WorkDir, c.log)
	}
	sup := c.sup
	c.applied = st
	c.mu.Unlock()
	if err := sup.Start(ctx); err != nil {
		return err
	}
	return c.waitReady(ctx)
}

// Apply swaps the user set (no restart) and restarts only if the server
// config itself changed. Users that disappeared are kicked.
func (c *Core) Apply(ctx context.Context, b *core.Bundle) error {
	next, _ := b.Payload.(*state)
	if next == nil {
		return fmt.Errorf("hysteria: bundle without state")
	}
	c.mu.Lock()
	sup, auth, prev := c.sup, c.auth, c.applied
	c.mu.Unlock()
	if sup == nil || !sup.Running() || auth == nil {
		return c.Start(ctx, b)
	}
	auth.setUsers(next.users)
	var gone []string
	if prev != nil {
		for pw, u := range prev.users {
			if _, keep := next.users[pw]; !keep {
				gone = append(gone, u.Name)
			}
		}
	}
	if len(gone) > 0 {
		rctx, cancel := context.WithTimeout(ctx, rpcTimeout)
		if err := c.stats.kick(rctx, gone); err != nil {
			c.log.Warn("kick failed", "users", len(gone), "err", err)
		}
		cancel()
	}
	c.mu.Lock()
	c.applied = next
	c.mu.Unlock()
	if prev != nil && prev.key == next.key {
		c.log.Info("users updated without restart", "users", len(next.users), "kicked", len(gone))
		return nil
	}
	if err := c.write(b); err != nil {
		return err
	}
	c.log.Info("applying new server config (restart)")
	if err := sup.Restart(ctx); err != nil {
		return err
	}
	return c.waitReady(ctx)
}

func (c *Core) Stop(ctx context.Context) error {
	c.mu.Lock()
	sup, auth := c.sup, c.auth
	c.auth = nil
	c.mu.Unlock()
	var err error
	if sup != nil {
		err = sup.Stop(ctx)
	}
	if auth != nil {
		_ = auth.close(ctx)
	}
	return err
}

func (c *Core) Running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sup != nil && c.sup.Running()
}

// Online implements core.OnlineTracker from auth-time client addresses.
func (c *Core) Online(_ context.Context) (map[string][]string, error) {
	c.mu.Lock()
	auth := c.auth
	c.mu.Unlock()
	if auth == nil {
		return nil, nil
	}
	return auth.online(), nil
}

func (c *Core) Stats(ctx context.Context, reset bool) (map[string]spec.Traffic, error) {
	rctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	return c.stats.traffic(rctx, reset)
}

// waitReady polls the traffic stats API until hysteria answers.
func (c *Core) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(readyTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, lastErr = c.stats.online(rctx)
		cancel()
		if lastErr == nil {
			return nil
		}
		if !c.Running() {
			return fmt.Errorf("hysteria: process exited during startup; check the config")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	return fmt.Errorf("hysteria: not ready after %s: %w", readyTimeout, lastErr)
}
