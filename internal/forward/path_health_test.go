package forward

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func healthSOCKS(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				var request [3]byte
				if _, err := io.ReadFull(c, request[:]); err == nil && request == [3]byte{5, 1, 2} {
					c.Write([]byte{5, 2})
				}
			}()
		}
	}()
	return ln.Addr().String()
}
func healthRule(port int, targets ...string) spec.Forward {
	f := spec.Forward{Tag: "entry-" + strconv.Itoa(port), Listen: "127.0.0.1", Port: port, Protocol: "tcp", Target: targets[0], PathHealth: &spec.PathHealth{RouteID: 1, ScopeID: "scope", Protocol: spec.PathHealthSOCKS5, AutoFailover: true, IntervalSeconds: 15, TimeoutSeconds: 1, FailureThreshold: 2, RecoveryThreshold: 2}}
	for i, target := range targets {
		if i > 0 {
			f.Targets = append(f.Targets, spec.ForwardTarget{Target: target})
		}
		f.PathHealth.Candidates = append(f.PathHealth.Candidates, spec.PathHealthCandidate{ID: "branch-" + strconv.Itoa(i), Target: target, Digest: strings.Repeat(strconv.Itoa(i+1), 64)})
	}
	return f
}
func healthOnlyRule(t *testing.T, m *Manager) *rule {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.rules) != 1 {
		t.Fatal("expected one rule")
	}
	for _, r := range m.rules {
		return r
	}
	return nil
}
func awaitHealth(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("health condition timed out")
}
func healthRelay(t *testing.T, port int, target string) *Manager {
	t.Helper()
	m := NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(m.Stop)
	if err := m.Apply([]spec.Forward{{Tag: "relay", Listen: "127.0.0.1", Port: port, Protocol: "tcp", Target: target}}); err != nil {
		t.Fatal(err)
	}
	return m
}
func healthAddress(port int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) }
func requireHealthHandshake(t *testing.T, port int, want bool) {
	t.Helper()
	c, err := net.DialTimeout("tcp", healthAddress(port), time.Second)
	if err != nil {
		if want {
			t.Fatal(err)
		}
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte{5, 1, 2})
	var answer [2]byte
	_, err = io.ReadFull(c, answer[:])
	got := err == nil && answer == [2]byte{5, 2}
	if got != want {
		t.Fatalf("handshake got %v want %v err=%v", got, want, err)
	}
}

func TestPathHealthActualDeepFailureRecoveryAndNoLastResort(t *testing.T) {
	d := healthSOCKS(t)
	b2Port, b1Port, cPort, aPort := freePort(t), freePort(t), freePort(t), freePort(t)
	b2 := healthRelay(t, b2Port, d)
	b1 := healthRelay(t, b1Port, healthAddress(b2Port))
	_ = b1
	c := healthRelay(t, cPort, d)
	a := NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer a.Stop()
	f := healthRule(aPort, healthAddress(b1Port), healthAddress(cPort))
	if err := a.Apply([]spec.Forward{f}); err != nil {
		t.Fatal(err)
	}
	r := healthOnlyRule(t, a)
	awaitHealth(t, func() bool { return len(a.PathHealthSnapshot()) == 2 })
	r.probePathHealth(context.Background())
	if len(r.candidates()) != 2 {
		t.Fatal("healthy paths not admitted")
	}
	requireHealthHandshake(t, aPort, true)
	firstBefore := r.hops[0].total.Load()
	// First B listener remains open; only its deeper business hop disappears.
	b2.Stop()
	r.probe(context.Background())
	if !r.hops[0].isUp() {
		t.Fatal("fixture did not preserve first-hop TCP")
	}
	r.probePathHealth(context.Background())
	if len(r.candidates()) != 2 {
		t.Fatal("failure threshold not honored")
	}
	r.probePathHealth(context.Background())
	if got := r.candidates(); len(got) != 1 || got[0].target != healthAddress(cPort) {
		t.Fatal("deep-down B remained eligible")
	}
	requireHealthHandshake(t, aPort, true)
	if r.hops[0].total.Load() != firstBefore {
		t.Fatal("selected known failed branch")
	}
	c.Stop()
	r.probePathHealth(context.Background())
	r.probePathHealth(context.Background())
	if len(r.candidates()) != 0 {
		t.Fatal("all-down appended last resort")
	}
	requireHealthHandshake(t, aPort, false)
	// Existing B1 business rule is unchanged, and B2 returns on the same port.
	b2 = healthRelay(t, b2Port, d)
	_ = b2
	r.probePathHealth(context.Background())
	if len(r.candidates()) != 0 {
		t.Fatal("recovery threshold not honored")
	}
	r.probePathHealth(context.Background())
	if len(r.candidates()) != 1 {
		t.Fatal("recovered branch not restored")
	}
	requireHealthHandshake(t, aPort, true)
	before := a.PathHealthSnapshot()
	after := a.PathHealthSnapshot()
	if before[0].Sequence != after[0].Sequence || !before[0].ObservedAt.Equal(after[0].ObservedAt) {
		t.Fatal("snapshot renews probe clock")
	}
	a.Stop()
	if len(a.PathHealthSnapshot()) != 0 {
		t.Fatal("stopped manager retained old evidence")
	}
}

func TestPathHealthAutoOffAndStaleSingleCandidate(t *testing.T) {
	f := healthRule(freePort(t), "198.51.100.20:443")
	r := &rule{spec: f, hops: newHops(f)}
	r.initPathHealth(nil)
	if len(r.candidates()) != 0 {
		t.Fatal("unknown singleton bypasses auto health")
	}
	at := time.Now().Add(-2 * time.Minute)
	r.recordPathHealth(0, "success", "", time.Millisecond, at)
	r.recordPathHealth(0, "success", "", time.Millisecond, at.Add(time.Millisecond))
	if len(r.candidates()) != 0 {
		t.Fatal("stale singleton selected")
	}
	r.spec.PathHealth.AutoFailover = false
	if len(r.candidates()) != 1 {
		t.Fatal("monitoring changed old fallback behavior")
	}
}

func TestPathHealthChangesSelectionWithoutClosingExistingConnections(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var failNew atomic.Bool
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var b [3]byte
				if _, e := io.ReadFull(c, b[:]); e != nil || failNew.Load() {
					return
				}
				c.Write([]byte{5, 2})
				io.Copy(c, c)
			}()
		}
	}()
	m := NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer m.Stop()
	f := healthRule(freePort(t), ln.Addr().String())
	if err = m.Apply([]spec.Forward{f}); err != nil {
		t.Fatal(err)
	}
	r := healthOnlyRule(t, m)
	awaitHealth(t, func() bool { return len(m.PathHealthSnapshot()) == 1 })
	r.probePathHealth(context.Background())
	client, err := net.Dial("tcp", healthAddress(f.Port))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	client.Write([]byte{5, 1, 2})
	var reply [2]byte
	if _, err = io.ReadFull(client, reply[:]); err != nil {
		t.Fatal(err)
	}
	failNew.Store(true)
	r.probePathHealth(context.Background())
	r.probePathHealth(context.Background())
	if len(r.candidates()) != 0 {
		t.Fatal("down candidate retained")
	}
	if _, err = client.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(client, reply[:]); err != nil || string(reply[:]) != "ok" {
		t.Fatal("health transition interrupted established stream", err)
	}
	requireHealthHandshake(t, f.Port, false)
}

func TestPathHealthNodeBudgetAndStopCancelQueuedAndActive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var active, peak atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n := active.Add(1)
			for {
				old := peak.Load()
				if n <= old || peak.CompareAndSwap(old, n) {
					break
				}
			}
			go func() { defer active.Add(-1); defer c.Close(); io.Copy(io.Discard, c) }()
		}
	}()
	m := NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer m.Stop()
	fs := []spec.Forward{}
	for i := 0; i < 12; i++ {
		f := healthRule(freePort(t), ln.Addr().String())
		f.PathHealth.TimeoutSeconds = 10
		fs = append(fs, f)
	}
	if err = m.Apply(fs); err != nil {
		t.Fatal(err)
	}
	awaitHealth(t, func() bool { return active.Load() == 8 })
	if peak.Load() > 8 {
		t.Fatal("unbounded node probe concurrency", peak.Load())
	}
	started := time.Now()
	m.Stop()
	if time.Since(started) > time.Second {
		t.Fatal("stop waited for handshake timeout or queue")
	}
	awaitHealth(t, func() bool { return active.Load() == 0 })
	if len(m.PathHealthSnapshot()) != 0 {
		t.Fatal("canceled sample survived stop")
	}
}
