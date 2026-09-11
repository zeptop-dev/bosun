// Package core defines the interface every proxy core adapter implements and
// the registry that assigns inbounds to cores.
package core

import (
	"context"
	"fmt"
	"sort"

	"gitlab.com/zeptop-group/bosun/internal/spec"
)

// Bundle is a rendered set of configuration files for one core.
type Bundle struct {
	Files map[string][]byte // relative file name -> content
	Main  string            // entry file name inside Files
}

// Capabilities advertises what a core can serve.
type Capabilities struct {
	Protocols     []spec.Protocol
	HotUserReload bool // true if users can change without a process restart
}

// Supports reports whether the core can serve protocol p.
func (c Capabilities) Supports(p spec.Protocol) bool {
	for _, x := range c.Protocols {
		if x == p {
			return true
		}
	}
	return false
}

// Core drives one upstream proxy binary as a child process.
//
// Lifecycle: Render -> Start; on change Render -> Apply; finally Stop.
// Stats returns per-user counters keyed by spec.User.Name.
type Core interface {
	Name() string
	Capabilities() Capabilities
	Render(node *spec.Node, inbounds []spec.Inbound, users []spec.User) (*Bundle, error)
	Start(ctx context.Context, b *Bundle) error
	Apply(ctx context.Context, b *Bundle) error
	Stop(ctx context.Context) error
	Running() bool
	Stats(ctx context.Context, reset bool) (map[string]spec.Traffic, error)
}

// Registry holds the enabled cores in registration order.
type Registry struct {
	cores map[string]Core
	order []string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{cores: map[string]Core{}}
}

// Register adds a core. Registration order is the default preference order.
func (r *Registry) Register(c Core) {
	if _, dup := r.cores[c.Name()]; dup {
		panic("core registered twice: " + c.Name())
	}
	r.cores[c.Name()] = c
	r.order = append(r.order, c.Name())
}

// Get returns a core by name.
func (r *Registry) Get(name string) (Core, bool) {
	c, ok := r.cores[name]
	return c, ok
}

// Names returns core names in registration order.
func (r *Registry) Names() []string {
	return append([]string(nil), r.order...)
}

// Assign splits inbounds by the core that will serve each one. An inbound's
// explicit Core wins if that core supports the protocol; otherwise the first
// registered core that supports it is used. Unsatisfiable inbounds are an error.
func (r *Registry) Assign(inbounds []spec.Inbound) (map[string][]spec.Inbound, error) {
	out := map[string][]spec.Inbound{}
	for _, ib := range inbounds {
		name, err := r.pick(ib)
		if err != nil {
			return nil, err
		}
		out[name] = append(out[name], ib)
	}
	return out, nil
}

func (r *Registry) pick(ib spec.Inbound) (string, error) {
	if ib.Core != "" {
		c, ok := r.cores[ib.Core]
		if !ok {
			return "", fmt.Errorf("inbound %q wants core %q which is not enabled", ib.Tag, ib.Core)
		}
		if !c.Capabilities().Supports(ib.Protocol) {
			return "", fmt.Errorf("inbound %q: core %q does not support %s", ib.Tag, ib.Core, ib.Protocol)
		}
		return ib.Core, nil
	}
	for _, name := range r.order {
		if r.cores[name].Capabilities().Supports(ib.Protocol) {
			return name, nil
		}
	}
	enabled := r.Names()
	sort.Strings(enabled)
	return "", fmt.Errorf("inbound %q: no enabled core supports %s (enabled: %v)", ib.Tag, ib.Protocol, enabled)
}
