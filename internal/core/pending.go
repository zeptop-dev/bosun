package core

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Pending reserves a configured adapter's identity and priority while its
// executable is unavailable. It cannot start traffic or hold desired state.
// Prepared adapters are published by the agent loop, never by the worker.
type Pending struct {
	name     string
	load     func(context.Context) (Core, error)
	mu       sync.Mutex
	ready    Core
	err      string
	busy     bool
	attempts uint
	next     time.Time
	cancel   context.CancelFunc
}

// At most the six supported configured distributions prepare concurrently.
// A slow missing package must not prevent a cached adapter from becoming ready.
var preparationSlots = make(chan struct{}, 6)

func NewPending(name string, load func(context.Context) (Core, error)) *Pending {
	return &Pending{name: name, load: load, err: "core binary is being prepared"}
}
func (p *Pending) Name() string               { return p.name }
func (p *Pending) Capabilities() Capabilities { return spec.CapabilitiesForCore(p.name) }
func (p *Pending) Error() string              { p.mu.Lock(); defer p.mu.Unlock(); return p.err }
func (p *Pending) Render(*spec.Node, []spec.Inbound, []spec.User) (*Bundle, error) {
	return nil, fmt.Errorf("%s unavailable: %s", p.name, p.Error())
}
func (p *Pending) Start(context.Context, *Bundle) error                         { return errors.New("core binary unavailable") }
func (p *Pending) Apply(ctx context.Context, b *Bundle) error                   { return p.Start(ctx, b) }
func (p *Pending) Running() bool                                                { return false }
func (p *Pending) Stats(context.Context, bool) (map[string]spec.Traffic, error) { return nil, nil }
func (p *Pending) Stop(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cancel != nil {
		p.cancel()
	}
	return nil
}
func (p *Pending) Take() Core {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.ready
	p.ready = nil
	return c
}
func (p *Pending) Prepare(ctx context.Context) {
	p.mu.Lock()
	if p.busy || p.ready != nil || time.Now().Before(p.next) || ctx.Err() != nil {
		p.mu.Unlock()
		return
	}
	select {
	case preparationSlots <- struct{}{}:
	default:
		p.mu.Unlock()
		return
	}
	work, cancel := context.WithTimeout(ctx, 10*time.Minute)
	p.busy = true
	p.cancel = cancel
	p.mu.Unlock()
	go func() {
		defer func() { cancel(); <-preparationSlots }()
		c, err := p.load(work)
		if err == nil {
			err = work.Err()
		}
		if err == nil && (c == nil || c.Name() != p.name) {
			err = errors.New("invalid prepared adapter")
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		p.busy = false
		p.cancel = nil
		if err == nil {
			p.ready = c
			p.err = ""
			return
		}
		p.err = err.Error()
		if p.attempts < 5 {
			p.attempts++
		}
		exponent := p.attempts - 1
		if exponent > 4 {
			exponent = 4
		}
		p.next = time.Now().Add(30 * time.Second * time.Duration(1<<exponent))
	}()
}
