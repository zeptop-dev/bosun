// Package snell drives Surge's snell-server as child processes, one per
// inbound. Snell has no user concept: every listener carries one shared
// PSK, so per-user accounting is impossible and Stats reports nothing.
// Any config change restarts that inbound's process (snell-server has no
// reload API).
package snell

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/core/subprocess"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Options configures the adapter.
type Options struct {
	Binary  string // path to snell-server
	WorkDir string // one sub dir per inbound
}

// Core is the snell-server adapter.
type Core struct {
	opt Options
	log *slog.Logger

	mu        sync.Mutex
	instances map[string]*instance
}

type instance struct {
	tag  string
	cfg  string
	sup  *subprocess.Supervisor
	last []byte // config currently running
}

const configFile = "snell-server.conf"

// New returns an adapter; the binary must exist but is not started.
func New(opt Options, log *slog.Logger) (*Core, error) {
	if opt.Binary == "" {
		return nil, fmt.Errorf("snell: binary path is required")
	}
	if _, err := os.Stat(opt.Binary); err != nil {
		return nil, fmt.Errorf("snell: binary: %w", err)
	}
	if opt.WorkDir == "" {
		return nil, fmt.Errorf("snell: work dir is required")
	}
	if err := os.MkdirAll(opt.WorkDir, 0o750); err != nil {
		return nil, err
	}
	return &Core{opt: opt, log: log.With("core", "snell"), instances: map[string]*instance{}}, nil
}

func (c *Core) Name() string { return "snell" }

func (c *Core) Capabilities() core.Capabilities {
	return core.Capabilities{Protocols: []spec.Protocol{spec.Snell}}
}

// Render produces one config per inbound under Files["<tag>/snell-server.conf"].
func (c *Core) Render(_ *spec.Node, inbounds []spec.Inbound, _ []spec.User) (*core.Bundle, error) {
	if len(inbounds) == 0 {
		return nil, fmt.Errorf("snell: nothing to render")
	}
	b := &core.Bundle{Files: map[string][]byte{}, Meta: map[string]string{}}
	for _, ib := range inbounds {
		if ib.Tag == "" {
			return nil, fmt.Errorf("snell: inbound without tag")
		}
		cfg, err := render(ib)
		if err != nil {
			return nil, err
		}
		b.Files[filepath.Join(ib.Tag, configFile)] = cfg
		b.Meta[ib.Tag] = "snell"
	}
	return b, nil
}

func (c *Core) newInstance(tag string) (*instance, error) {
	dir := filepath.Join(c.opt.WorkDir, tag)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	in := &instance{tag: tag, cfg: filepath.Join(dir, configFile)}
	in.sup = subprocess.New("snell:"+tag, c.opt.Binary, []string{"-c", in.cfg}, dir, c.log.With("inbound", tag))
	return in, nil
}

func tags(b *core.Bundle) []string {
	out := make([]string, 0, len(b.Meta))
	for t := range b.Meta {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func writeFile(path string, content []byte) error {
	if err := os.WriteFile(path+".tmp", content, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

// Start launches an instance for every inbound in the bundle.
func (c *Core) Start(ctx context.Context, b *core.Bundle) error { return c.Apply(ctx, b) }

// Apply reconciles instances with the bundle: removed tags stop, new tags
// start, changed configs restart their process.
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
			_ = in.sup.Stop(ctx)
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
		if in.sup.Running() && bytes.Equal(in.last, cfg) {
			continue
		}
		if err := writeFile(in.cfg, cfg); err != nil {
			return err
		}
		in.last = cfg
		var err error
		if in.sup.Running() {
			c.log.Info("config changed, restarting snell-server", "inbound", tag)
			err = in.sup.Restart(ctx)
		} else {
			err = in.sup.Start(ctx)
		}
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("snell[%s]: %w", tag, err)
		}
	}
	return firstErr
}

func (c *Core) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var firstErr error
	for tag, in := range c.instances {
		if err := in.sup.Stop(ctx); err != nil && firstErr == nil {
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

// Stats has nothing to report: snell-server exposes no per-user counters
// and has no users to attribute traffic to.
func (c *Core) Stats(context.Context, bool) (map[string]spec.Traffic, error) {
	return map[string]spec.Traffic{}, nil
}
