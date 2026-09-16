// Package mita drives the official mieru server (mita) as child processes.
//
// mita's users are global to a process, so bosun runs one mita instance per
// inbound: each has its own work dir, config file, unix socket and user
// list. Inside an instance, user changes are hot-reloaded (Reload), port
// changes cycle the proxy (Stop/Start), and per-user counters come from
// GetUsers; counters are cumulative, so Stats returns deltas.
package mita

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc"

	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/core/grpcraw"
	"github.com/zeptop-dev/bosun/internal/core/subprocess"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Options configures the mita adapter.
type Options struct {
	Binary   string // path to the mita executable
	WorkDir  string // one sub dir per inbound is created under it
	LogLevel string // mita logging level: INFO, WARN, ...
}

// Core is the mita adapter.
type Core struct {
	opt Options
	log *slog.Logger

	version string // from "mita version", "" when unknown
	native  bool   // binary supports listenIPAddress

	mu        sync.Mutex
	instances map[string]*instance // by inbound tag
}

// instance is one running mita process serving one inbound.
type instance struct {
	tag      string
	dir      string
	cfg      string
	socket   string
	log      *slog.Logger
	sup      *subprocess.Supervisor
	conn     *grpc.ClientConn
	bindings string
	last     map[string]spec.Traffic
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
	c := &Core{opt: opt, log: log.With("core", "mita"), instances: map[string]*instance{}}
	c.version = binaryVersion(opt.Binary)
	c.native = supportsListen(c.version)
	if c.version == "" {
		c.log.Warn("mita version unknown; listening on every address (ingress guard applies)")
	} else {
		c.log.Info("mita", "version", c.version, "native_listen", c.native)
	}
	return c, nil
}

func (c *Core) Name() string { return "mita" }

// NativeListen reports whether the binary binds inbound addresses itself
// (listenIPAddress, mita >= 3.37.0); when false the agent's ingress guard
// enforces line-bound inbounds with nftables.
func (c *Core) NativeListen() bool { return c.native }

// binaryVersion runs "<mita> version" and returns the x.y.z it prints,
// or "" when the binary cannot be run.
func binaryVersion(bin string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, bin, "version").CombinedOutput()
	return versionRe.FindString(string(out))
}

var versionRe = regexp.MustCompile(`\d+\.\d+\.\d+`)

// supportsListen: listenIPAddress arrived in mieru v3.37.0.
func supportsListen(version string) bool {
	m := versionRe.FindString(version)
	if m == "" {
		return false
	}
	var a, b, c int
	fmt.Sscanf(m, "%d.%d.%d", &a, &b, &c)
	return a > 3 || (a == 3 && b >= 37)
}

func (c *Core) Capabilities() core.Capabilities {
	return core.Capabilities{Protocols: []spec.Protocol{spec.Mieru}, HotUserReload: true}
}

// Render produces one config per inbound under Files["<tag>/server_config.json"].
func (c *Core) Render(node *spec.Node, inbounds []spec.Inbound, users []spec.User) (*core.Bundle, error) {
	if len(inbounds) == 0 {
		return nil, fmt.Errorf("mita: nothing to render")
	}
	b := &core.Bundle{Files: map[string][]byte{}, Meta: map[string]string{}}
	for _, ib := range inbounds {
		if ib.Tag == "" {
			return nil, fmt.Errorf("mita: inbound without tag")
		}
		cfg, err := render([]spec.Inbound{ib}, ib.EffectiveUsers(users), c.opt.LogLevel, c.native)
		if err != nil {
			return nil, err
		}
		if node != nil && len(node.Overrides["mita"]) > 0 {
			var obj map[string]any
			if err := json.Unmarshal(cfg, &obj); err == nil {
				if err := core.ApplyOverride("mita", obj, node.Overrides["mita"]); err != nil {
					return nil, fmt.Errorf("mita: %w", err)
				}
				cfg, _ = json.MarshalIndent(obj, "", "  ")
			}
		}
		b.Files[filepath.Join(ib.Tag, configFile)] = cfg
		b.Meta[ib.Tag] = bindingsKey([]spec.Inbound{ib}, c.native)
	}
	return b, nil
}

// maxSocketPath is the portable limit for a unix socket path (sun_path is
// 108 bytes on Linux and 104 on macOS, including the terminating NUL).
const maxSocketPath = 100

// socketPath keeps the socket next to the config when the path is short
// enough, otherwise falls back to the system temp dir with a name derived
// from the work dir so instances never collide.
func socketPath(workDir string) string {
	p := filepath.Join(workDir, socketFile)
	if len(p) <= maxSocketPath {
		return p
	}
	sum := sha256.Sum256([]byte(workDir))
	return filepath.Join(os.TempDir(), fmt.Sprintf("bosun-mita-%x.sock", sum[:6]))
}

func (c *Core) newInstance(tag string) (*instance, error) {
	dir := filepath.Join(c.opt.WorkDir, tag)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	in := &instance{tag: tag, dir: dir, cfg: filepath.Join(dir, configFile), socket: socketPath(dir), log: c.log.With("inbound", tag), last: map[string]spec.Traffic{}}
	in.sup = subprocess.New("mita:"+tag, c.opt.Binary, []string{"run"}, dir, in.log).WithEnv(
		"MITA_CONFIG_JSON_FILE="+in.cfg,
		"MITA_UDS_PATH="+in.socket,
		"MITA_INSECURE_UDS=1", // bosun owns the work dir; skip mita's group chown
		"MITA_LOG_NO_TIMESTAMP=1",
	)
	return in, nil
}

func writeFile(path string, content []byte) error {
	if err := os.WriteFile(path+".tmp", content, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

// tags returns the inbound tags present in a bundle, sorted.
func tags(b *core.Bundle) []string {
	out := make([]string, 0, len(b.Meta))
	for t := range b.Meta {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Start launches an instance for every inbound in the bundle.
func (c *Core) Start(ctx context.Context, b *core.Bundle) error {
	return c.Apply(ctx, b)
}

// Apply reconciles instances with the bundle: new tags start, missing tags
// stop, existing ones hot-reload users or cycle the proxy on port change.
func (c *Core) Apply(ctx context.Context, b *core.Bundle) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	want := map[string]bool{}
	for _, tag := range tags(b) {
		want[tag] = true
	}
	for tag, in := range c.instances {
		if !want[tag] {
			c.log.Info("inbound removed, stopping instance", "inbound", tag)
			_ = in.stop(ctx)
			delete(c.instances, tag)
		}
	}
	var firstErr error
	for _, tag := range tags(b) {
		cfg := b.Files[filepath.Join(tag, configFile)]
		in, exists := c.instances[tag]
		if !exists {
			var err error
			if in, err = c.newInstance(tag); err != nil {
				return err
			}
			c.instances[tag] = in
		}
		if err := writeFile(in.cfg, cfg); err != nil {
			return err
		}
		var err error
		switch {
		case !in.sup.Running():
			in.bindings = b.Meta[tag]
			if err = in.sup.Start(ctx); err == nil {
				err = in.waitStatus(ctx, statusRunning, readyTimeout)
			}
		case in.bindings == b.Meta[tag]:
			in.log.Info("applying user changes (hot reload)")
			err = in.rpc(ctx, methodReload)
		default:
			in.log.Info("applying port changes (proxy restart)")
			in.bindings = b.Meta[tag]
			err = in.cycle(ctx)
		}
		if err != nil {
			in.log.Error("apply failed", "err", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("mita[%s]: %w", tag, err)
			}
		}
	}
	return firstErr
}

func (c *Core) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var firstErr error
	for tag, in := range c.instances {
		if err := in.stop(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(c.instances, tag)
	}
	return firstErr
}

// Running reports whether any instance is alive.
func (c *Core) Running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, in := range c.instances {
		if in.sup.Running() {
			return true
		}
	}
	return false
}

// Stats sums per-user deltas across instances. The reset flag is ignored:
// mita counters are cumulative and bosun keeps the baseline. A counter that
// went backwards (mita restarted) is treated as starting from zero.
func (c *Core) Stats(ctx context.Context, _ bool) (map[string]spec.Traffic, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]spec.Traffic{}
	var firstErr error
	for tag, in := range c.instances {
		if !in.sup.Running() {
			continue
		}
		deltas, err := in.deltas(ctx)
		if err != nil {
			in.log.Warn("stats failed", "err", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for name, d := range deltas {
			key := spec.InboundUser(name, tag) // one instance per inbound
			t := out[key]
			t.Up += d.Up
			t.Down += d.Down
			out[key] = t
		}
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// --- instance ---

func (in *instance) dial() (*grpc.ClientConn, error) {
	if in.conn != nil {
		return in.conn, nil
	}
	conn, err := grpcraw.Dial("unix://" + in.socket)
	if err != nil {
		return nil, err
	}
	in.conn = conn
	return conn, nil
}

func (in *instance) rpc(ctx context.Context, method string) error {
	conn, err := in.dial()
	if err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	return rpcEmpty(rctx, conn, method)
}

func (in *instance) cycle(ctx context.Context) error {
	conn, err := in.dial()
	if err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	if st, _ := rpcStatus(rctx, conn); st == statusRunning {
		if err := rpcEmpty(rctx, conn, methodStop); err != nil {
			return fmt.Errorf("stop: %w", err)
		}
	}
	if err := rpcEmpty(rctx, conn, methodStart); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	return in.waitStatus(ctx, statusRunning, readyTimeout)
}

func (in *instance) stop(ctx context.Context) error {
	if in.conn != nil {
		_ = in.conn.Close()
		in.conn = nil
	}
	return in.sup.Stop(ctx)
}

func (in *instance) deltas(ctx context.Context) (map[string]spec.Traffic, error) {
	conn, err := in.dial()
	if err != nil {
		return nil, err
	}
	rctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	cur, err := rpcUserCounters(rctx, conn)
	if err != nil {
		return nil, err
	}
	out := make(map[string]spec.Traffic, len(cur))
	for name, now := range cur {
		prev := in.last[name]
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
	in.last = cur
	return out, nil
}

// waitStatus polls GetStatus until mita reports want or the timeout passes.
func (in *instance) waitStatus(ctx context.Context, want appStatus, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	var lastStatus appStatus
	for time.Now().Before(deadline) {
		conn, err := in.dial()
		if err == nil {
			rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			lastStatus, err = rpcStatus(rctx, conn)
			cancel()
			if err == nil && lastStatus == want {
				return nil
			}
		}
		lastErr = err
		if !in.sup.Running() {
			return fmt.Errorf("mita exited during startup; check the config")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	if lastErr != nil {
		return fmt.Errorf("not %s after %s: %w", want, timeout, lastErr)
	}
	return fmt.Errorf("not %s after %s (status %s); check the config", want, timeout, lastStatus)
}
