package core

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func waitPending(t *testing.T, p *Pending) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		busy := p.busy
		p.mu.Unlock()
		if !busy {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("worker did not complete")
}
func TestPendingRetriesWithoutStartingOrDowngrading(t *testing.T) {
	var calls atomic.Int32
	wanted := fakeCore{name: "singbox"}
	p := NewPending("singbox", func(context.Context) (Core, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("HTTP 404: unsupported package")
		}
		return wanted, nil
	})
	p.Prepare(context.Background())
	waitPending(t, p)
	if p.Error() == "" || p.Running() || p.Take() != nil {
		t.Fatal("failed package was treated as ready")
	}
	for range 20 {
		p.Prepare(context.Background())
	}
	if calls.Load() != 1 {
		t.Fatal("backoff bypass")
	}
	p.mu.Lock()
	p.next = time.Time{}
	p.mu.Unlock()
	p.Prepare(context.Background())
	waitPending(t, p)
	c := p.Take()
	if c == nil || c.Running() {
		t.Fatal("prepare must only construct")
	}
}
func TestPendingCancellationRejectsLateSuccess(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	p := NewPending("singbox", func(context.Context) (Core, error) { close(entered); <-release; return fakeCore{name: "singbox"}, nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Prepare(ctx)
	<-entered
	cancel()
	close(release)
	waitPending(t, p)
	if p.Take() != nil {
		t.Fatal("cancelled result was accepted")
	}
}
