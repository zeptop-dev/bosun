// Package mita drives the official mieru server (mita) as a child process.
//
// mita keeps its own config file and exposes a gRPC control plane on a unix
// socket. Bosun writes the config file, runs `mita run`, and uses the RPC for
// hot user reloads (Reload), port changes (Stop/Start) and per-user counters
// (GetUsers). Counters are cumulative, so Stats returns deltas since the last
// call.
package mita

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"

	"gitlab.com/boyang-hu/bosun/internal/core"
	"gitlab.com/boyang-hu/bosun/internal/core/grpcraw"
	"gitlab.com/boyang-hu/bosun/internal/core/subprocess"
	"gitlab.com/boyang-hu/bosun/pkg/spec"
)

// Options configures the mita adapter.
type Options struct {
	Binary   string // path to the mita executable
	WorkDir  string // config file lives here; the unix socket too unless the path is too long
	Socket   string // optional explicit unix socket path
	LogLevel string // mita logging level: INFO, WARN, ...
}

// Core is the mita adapter.
type Core struct {
	opt    Options
	log    *slog.Logger
	cfg    string // config file path
	socket string

	mu       sync.Mutex
	sup      *subprocess.Supervisor
	conn     *grpc.ClientConn
	bindings string                  // bindingsKey of the running config
	last     map[string]spec.Traffic // last cumulative counters, for deltas
}

const (
	configFile   = "server_config.json"
	socketFile   = "mita.sock"
	readyTimeout = 15 * time.Second
	rpcTimeout   = 10 * time.Second
)

// New returns an adapter; the binary must exist but is not started.
func New(opt Options, log *slog.Logger) (*Core, error) {
	if opt.Binary == "" {
		return nil, fmt.Errorf("mita: binary path is required")
	}
	if _, err := os.Stat(opt.Binary); err != nil {
		return nil, fmt.Errorf("mita: binary: %w", err)
	}
	if opt.WorkDir == "" {
		return nil, fmt.Errorf("mita: work dir is required")
	}
	if opt.LogLevel == "" {
		opt.LogLevel = "INFO"
	}
	if err := os.MkdirAll(opt.WorkDir, 0o750); err != nil {
		return nil, err
	}
	socket := opt.Socket
	if socket == "" {
		socket = socketPath(opt.WorkDir)
	}
	return &Core{
		opt:    opt,
		log:    log.With("core", "mita"),
		cfg:    filepath.Join(opt.WorkDir, configFile),
		socket: socket,
		last:   map[string]spec.Traffic{},
	}, nil
}

// maxSocketPath is the portable limit for a unix socket path (sun_path is
// 108 bytes on Linux and 104 on macOS, including the terminating NUL).
const maxSocketPath = 100

// socketPath keeps the socket next to the config when the path is short
// enough, otherwise falls back to the system temp dir with a name derived
// from the work dir so two bosun instances never collide.
func socketPath(workDir string) string {
	p := filepath.Join(workDir, socketFile)
	if len(p) <= maxSocketPath {
		return p
	}
	sum := sha256.Sum256([]byte(workDir))
	return filepath.Join(os.TempDir(), fmt.Sprintf("bosun-mita-%x.sock", sum[:6]))
}

func (c *Core) Name() string { return "mita" }

func (c *Core) Capabilities() core.Capabilities {
	return core.Capabilities{Protocols: []spec.Protocol{spec.Mieru}, HotUserReload: true}
}

func (c *Core) Render(_ *spec.Node, inbounds []spec.Inbound, users []spec.User) (*core.Bundle, error) {
	b, err := render(inbounds, users, c.opt.LogLevel)
	if err != nil {
		return nil, err
	}
	return &core.Bundle{
		Files: map[string][]byte{configFile: b},
		Main:  configFile,
		Meta:  map[string]string{"bindings": bindingsKey(inbounds)},
	}, nil
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
	if err := c.write(b); err != nil {
		return err
	}
	c.mu.Lock()
	if c.sup == nil {
		c.sup = subprocess.New("mita", c.opt.Binary, []string{"run"}, c.opt.WorkDir, c.log).WithEnv(
			"MITA_CONFIG_JSON_FILE="+c.cfg,
			"MITA_UDS_PATH="+c.socket,
			"MITA_INSECURE_UDS=1", // bosun owns the work dir; skip mita's group chown
			"MITA_LOG_NO_TIMESTAMP=1",
		)
	}
	sup := c.sup
	c.bindings = b.Meta["bindings"]
	c.mu.Unlock()

	if err := sup.Start(ctx); err != nil {
		return err
	}
	// mita starts the proxy itself once the config validates; wait for RUNNING.
	return c.waitStatus(ctx, statusRunning, readyTimeout)
}

// Apply writes the new config, then hot-reloads if only users changed, or
// cycles the proxy (not the daemon) if port bindings changed.
func (c *Core) Apply(ctx context.Context, b *core.Bundle) error {
	if err := c.write(b); err != nil {
		return err
	}
	c.mu.Lock()
	sup := c.sup
	prev := c.bindings
	c.bindings = b.Meta["bindings"]
	c.mu.Unlock()
	if sup == nil || !sup.Running() {
		return c.Start(ctx, b)
	}
	conn, err := c.dial()
	if err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	if prev == b.Meta["bindings"] {
		c.log.Info("applying user changes (hot reload)")
		return rpcEmpty(rctx, conn, methodReload)
	}
	c.log.Info("applying port changes (proxy restart)")
	if st, _ := rpcStatus(rctx, conn); st == statusRunning {
		if err := rpcEmpty(rctx, conn, methodStop); err != nil {
			return fmt.Errorf("mita: stop: %w", err)
		}
	}
	if err := rpcEmpty(rctx, conn, methodStart); err != nil {
		return fmt.Errorf("mita: start: %w", err)
	}
	return c.waitStatus(ctx, statusRunning, readyTimeout)
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

// Stats returns per-user traffic since the previous call. The reset flag is
// ignored: mita counters are cumulative and bosun keeps the baseline. A
// counter that went backwards (mita restarted) is treated as starting from
// zero.
func (c *Core) Stats(ctx context.Context, _ bool) (map[string]spec.Traffic, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	rctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	cur, err := rpcUserCounters(rctx, conn)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]spec.Traffic, len(cur))
	for name, now := range cur {
		prev := c.last[name]
		d := spec.Traffic{Up: now.Up - prev.Up, Down: now.Down - prev.Down}
		if d.Up < 0 {
			d.Up = now.Up
		}
		if d.Down < 0 {
			d.Down = now.Down
		}
		if d.Up != 0 || d.Down != 0 {
			out[name] = d
		}
	}
	c.last = cur
	return out, nil
}

func (c *Core) dial() (*grpc.ClientConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn, nil
	}
	conn, err := grpcraw.Dial("unix://" + c.socket)
	if err != nil {
		return nil, err
	}
	c.conn = conn
	return conn, nil
}

// waitStatus polls GetStatus until mita reports want or the timeout passes.
func (c *Core) waitStatus(ctx context.Context, want appStatus, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	var lastStatus appStatus
	for time.Now().Before(deadline) {
		conn, err := c.dial()
		if err == nil {
			rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			lastStatus, err = rpcStatus(rctx, conn)
			cancel()
			if err == nil && lastStatus == want {
				return nil
			}
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	if lastErr != nil {
		return fmt.Errorf("mita: not %s after %s: %w", want, timeout, lastErr)
	}
	return fmt.Errorf("mita: not %s after %s (status %s); check the config", want, timeout, lastStatus)
}
