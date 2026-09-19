package forward

import (
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// tcpNamed answers every connection with its name and hangs up, so a test
// can see which hop a connection went to.
func tcpNamed(t *testing.T, name string) string {
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
			c.Write([]byte(name))
			c.Close()
		}
	}()
	return ln.Addr().String()
}

// via connects through the relay n times and returns who answered.
func via(t *testing.T, port, n int) string {
	t.Helper()
	var b strings.Builder
	for i := 0; i < n; i++ {
		c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(8 * time.Second))
		buf := make([]byte, 1)
		if _, err := c.Read(buf); err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		c.Close()
		b.Write(buf)
	}
	return b.String()
}

func applyOne(t *testing.T, f spec.Forward) *Manager {
	t.Helper()
	m := NewManager(slog.Default())
	t.Cleanup(m.Stop)
	if err := m.Apply([]spec.Forward{f}); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestFailoverSkipsDeadTarget(t *testing.T) {
	port := freePort(t)
	dead := "127.0.0.1:" + strconv.Itoa(freePort(t))
	m := applyOne(t, spec.Forward{Tag: "f", Listen: "127.0.0.1", Port: port, Protocol: "tcp",
		Target: dead, Targets: []spec.ForwardTarget{{Target: tcpNamed(t, "B")}}})
	// The first connection arrives before any probe: the relay must retry
	// on the second hop by itself, and remember the first is down.
	if got := via(t, port, 3); got != "BBB" {
		t.Fatalf("got %q, want BBB", got)
	}
	s := m.Snapshot()[0]
	if !s.Up || len(s.Targets) != 2 || s.Targets[0].Up || s.Targets[0].LastError == "" || !s.Targets[1].Up || s.Targets[1].TotalConn != 3 {
		t.Fatalf("stats: %+v", s)
	}
}

func TestFailoverPrefersFirstUp(t *testing.T) {
	port := freePort(t)
	applyOne(t, spec.Forward{Tag: "f", Listen: "127.0.0.1", Port: port, Protocol: "tcp", Balance: spec.BalanceFailover,
		Target: tcpNamed(t, "A"), Targets: []spec.ForwardTarget{{Target: tcpNamed(t, "B")}}})
	if got := via(t, port, 3); got != "AAA" {
		t.Fatalf("got %q, want AAA", got)
	}
}

func TestRoundRobinFollowsWeights(t *testing.T) {
	port := freePort(t)
	applyOne(t, spec.Forward{Tag: "rr", Listen: "127.0.0.1", Port: port, Protocol: "tcp", Balance: spec.BalanceRoundRobin,
		Target: tcpNamed(t, "A"), Weight: 2, Targets: []spec.ForwardTarget{{Target: tcpNamed(t, "B")}}})
	// Smooth weighted round-robin interleaves 2:1 as A,B,A.
	if got := via(t, port, 6); got != "ABAABA" {
		t.Fatalf("got %q, want ABAABA", got)
	}
}

func TestRoundRobinSkipsDownHop(t *testing.T) {
	port := freePort(t)
	dead := "127.0.0.1:" + strconv.Itoa(freePort(t))
	applyOne(t, spec.Forward{Tag: "rr", Listen: "127.0.0.1", Port: port, Protocol: "tcp", Balance: spec.BalanceRoundRobin,
		Target: dead, Targets: []spec.ForwardTarget{{Target: tcpNamed(t, "B")}}})
	if got := via(t, port, 4); got != "BBBB" {
		t.Fatalf("got %q, want BBBB", got)
	}
}

func TestSingleTargetReportsNoHops(t *testing.T) {
	port := freePort(t)
	m := applyOne(t, spec.Forward{Tag: "one", Listen: "127.0.0.1", Port: port, Protocol: "tcp", Target: tcpNamed(t, "A")})
	if s := m.Snapshot()[0]; s.Targets != nil || s.Status().Targets != nil {
		t.Fatalf("a single-target rule must report as before: %+v", s)
	}
}

func TestApplyRefusesTargetsTheBackendCannotServe(t *testing.T) {
	m := NewManager(slog.Default())
	defer m.Stop()
	extra := []spec.ForwardTarget{{Target: "127.0.0.1:2"}}
	for _, f := range []spec.Forward{
		{Tag: "n", Port: freePort(t), Protocol: "tcp", Target: "127.0.0.1:1", Backend: "nft", Targets: extra},
		{Tag: "r", Port: freePort(t), Protocol: "tcp", Target: "127.0.0.1:1", Backend: "realm", Targets: extra},
		{Tag: "b", Port: freePort(t), Protocol: "tcp", Target: "127.0.0.1:1", Balance: "random", Targets: extra},
	} {
		if err := m.Apply([]spec.Forward{f}); err == nil {
			t.Errorf("%s: accepted %+v", f.Tag, f)
		}
	}
}

func TestRealmConfigTargets(t *testing.T) {
	got := realmConfig([]spec.Forward{{Tag: "lb", Port: 8443, Protocol: "tcp", Target: "a.example:443", Weight: 3,
		Balance: spec.BalanceRoundRobin, Targets: []spec.ForwardTarget{{Target: "b.example:443"}, {Target: "10.0.0.2:443", Weight: 2}}}})
	for _, want := range []string{
		`remote = "a.example:443"`,
		`extra_remotes = ["b.example:443", "10.0.0.2:443"]`,
		`balance = "roundrobin: 3, 1, 2"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in\n%s", want, got)
		}
	}
}
