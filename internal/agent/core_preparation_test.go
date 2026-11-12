package agent

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/servicecontrol"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

type preparationPanel struct {
	nopDriver
	revoked atomic.Bool
	reports chan agentproto.Report
}

func (p *preparationPanel) Node(context.Context) (*spec.Node, bool, error) {
	return &spec.Node{Inbounds: []spec.Inbound{{Tag: "vless", Core: "singbox", Protocol: spec.VLESS, Port: 18443}}}, true, nil
}
func (p *preparationPanel) Users(context.Context) ([]spec.User, bool, error) {
	if p.revoked.Load() {
		return []spec.User{}, true, nil
	}
	return []spec.User{{ID: 1, Name: "old", UUID: "11111111-1111-4111-8111-111111111111"}}, true, nil
}
func (p *preparationPanel) Intervals() spec.Intervals {
	return spec.Intervals{Pull: 20 * time.Millisecond, Push: 30 * time.Millisecond}
}
func (p *preparationPanel) Report(_ context.Context, r agentproto.Report) (bool, error) {
	select {
	case p.reports <- r:
	default:
	}
	return false, nil
}

type preparedRecorder struct {
	fakeCore
	users []spec.User
}

func (c *preparedRecorder) Render(n *spec.Node, i []spec.Inbound, u []spec.User) (*core.Bundle, error) {
	c.users = append([]spec.User(nil), u...)
	return c.fakeCore.Render(n, i, u)
}
func TestAgentReportsWhilePreparationBlockedAndUsesCurrentUsers(t *testing.T) {
	p := &preparationPanel{reports: make(chan agentproto.Report, 100)}
	entered := make(chan struct{})
	release := make(chan struct{})
	c := &preparedRecorder{fakeCore: fakeCore{name: "singbox", protos: []spec.Protocol{spec.VLESS}}}
	pending := core.NewPending("singbox", func(ctx context.Context) (core.Core, error) {
		close(entered)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
			return c, nil
		}
	})
	reg := core.NewRegistry()
	reg.Register(pending)
	a := New(&config.Config{DataDir: t.TempDir()}, p, reg, nil, slog.Default())
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	defer func() {
		cancel()
		<-done
		if len(c.users) != 0 {
			t.Fatal("recovery rendered stale users", c.users)
		}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("worker never started")
	}
	select {
	case r := <-p.reports:
		if r.Cores["singbox"].Running || r.Cores["singbox"].PreparationError == "" || r.AppliedRevision != "" {
			t.Fatalf("false readiness: %+v", r.Cores)
		}
	case <-ctx.Done():
		t.Fatal("download blocked reporting")
	}
	p.revoked.Store(true)
	close(release)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case r := <-p.reports:
			if r.Cores["singbox"].PreparationError == "" {
				return
			}
		case <-deadline:
			t.Fatal("preparation recovery not published")
		}
	}
}
func TestPreparedCoreCannotBypassExpiredLease(t *testing.T) {
	a, c, _ := checkpointRig(t)
	c.running = false
	ready := make(chan struct{})
	a.reg.Replace(c.Name(), core.NewPending(c.Name(), func(context.Context) (core.Core, error) { close(ready); return c, nil }))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.prepareCores(ctx)
	<-ready
	deadline := time.Now().Add(time.Second)
	for !a.prepareCores(ctx) {
		if time.Now().After(deadline) {
			t.Fatal("no prepared adapter")
		}
		time.Sleep(time.Millisecond)
	}
	a.driver = &leasePanel{Driver: a.driver, expired: true}
	if err := a.apply(ctx); err == nil {
		t.Fatal("expired lease accepted")
	}
	if c.running {
		t.Fatal("background completion started revoked traffic")
	}
}
func TestPreparationErrorsRemainVisible(t *testing.T) {
	a, _, _ := checkpointRig(t)
	a.reg.Replace("singbox-extended", core.NewPending("singbox-extended", func(context.Context) (core.Core, error) { return nil, errors.New("checksum mismatch") }))
	r := a.buildReport(nil, spec.SystemStatus{})
	if r.Cores["singbox-extended"].PreparationError == "" || r.Cores["singbox-extended"].Running {
		t.Fatal(r.Cores)
	}
}

func TestPreparedCoreRemainsStoppedDuringPause(t *testing.T) {
	a, c, _ := checkpointRig(t)
	c.running = false
	var script string
	fail := false
	a.ServiceControl = &servicecontrol.Manager{Dir: t.TempDir(), Run: serviceControlTestRunner(&script, &fail)}
	a.node.ServiceControl = &spec.ServiceControl{Revision: "paused", Mode: spec.ServiceControlPause}
	ready := make(chan struct{})
	a.reg.Replace(c.Name(), core.NewPending(c.Name(), func(context.Context) (core.Core, error) { close(ready); return c, nil }))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.prepareCores(ctx)
	<-ready
	deadline := time.Now().Add(time.Second)
	for !a.prepareCores(ctx) {
		if time.Now().After(deadline) {
			t.Fatal("preparation missing")
		}
		time.Sleep(time.Millisecond)
	}
	if err := a.apply(ctx); err != nil {
		t.Fatal(err)
	}
	if c.running {
		t.Fatal("prepared adapter bypassed pause")
	}
	a.node.ServiceControl = &spec.ServiceControl{Revision: "resumed", Mode: spec.ServiceControlNormal}
	if err := a.apply(ctx); err != nil {
		t.Fatal(err)
	}
	if !c.running {
		t.Fatal("authorized resume did not recover")
	}
}
