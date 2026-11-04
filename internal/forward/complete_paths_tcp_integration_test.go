package forward

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// This consumes Captain's real transactional TCP compiler output unchanged.
// Keep it separate from the UDP/both fixture, which has different prerequisites.
func TestCompiledCompletePathTCP(t *testing.T) {
	filename := os.Getenv("CAPTAIN_PATH_ROUTE_FIXTURE")
	if filename == "" {
		t.Skip("set CAPTAIN_PATH_ROUTE_FIXTURE to Captain's generated TCP route fixture")
	}
	var fixture struct {
		EntryPort, LandingPort int
		Nodes                  [][]spec.Forward
		BranchPorts            [][]int
	}
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Nodes) != 3 || len(fixture.BranchPorts) != 2 || len(fixture.BranchPorts[0]) != 2 || len(fixture.BranchPorts[1]) != 1 {
		t.Fatal("fixture must contain complete two-hop and one-hop branches")
	}
	address := func(port int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) }
	byPort := map[int]spec.Forward{}
	owner := map[int]int{}
	for i, rules := range fixture.Nodes {
		for _, rule := range rules {
			if rule.Protocol != "tcp" || rule.Backend != "" || rule.PathHealth != nil || rule.Listen != "127.0.0.1" {
				t.Fatal("fixture must use ordinary loopback native TCP relays with no path health")
			}
			if _, duplicate := byPort[rule.Port]; duplicate || rule.Port == fixture.LandingPort {
				t.Fatal("fixture reused a dedicated listener")
			}
			byPort[rule.Port], owner[rule.Port] = rule, i
		}
	}
	entry, ok := byPort[fixture.EntryPort]
	if !ok || entry.BalanceMode() != spec.BalanceRoundRobin || len(entry.Hops()) != 2 {
		t.Fatal("fixture must use a round-robin entry with two complete branches")
	}
	for branch, ports := range fixture.BranchPorts {
		if entry.Hops()[branch].Target != address(ports[0]) {
			t.Fatal("entry does not select complete branch heads")
		}
		for i, port := range ports {
			next := fixture.LandingPort
			if i+1 < len(ports) {
				next = ports[i+1]
			}
			member, ok := byPort[port]
			if !ok || len(member.Hops()) != 1 || member.Target != address(next) {
				t.Fatal("compiler changed hop order or emitted a cross-branch edge")
			}
		}
	}
	failedOwner := owner[fixture.BranchPorts[0][0]]
	if failedOwner == owner[fixture.EntryPort] || failedOwner == owner[fixture.BranchPorts[1][0]] {
		t.Fatal("fixture must allow stopping B independently of entry A and branch C")
	}

	landing, err := net.Listen("tcp", address(fixture.LandingPort))
	if err != nil {
		t.Fatal(err)
	}
	var echo sync.WaitGroup
	echo.Add(1)
	go func() {
		defer echo.Done()
		for {
			c, err := landing.Accept()
			if err != nil {
				return
			}
			echo.Add(1)
			go func() {
				defer echo.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() { _ = landing.Close(); echo.Wait() })
	managers := make([]*Manager, len(fixture.Nodes))
	for i := len(managers) - 1; i >= 0; i-- {
		managers[i] = NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)))
		t.Cleanup(managers[i].Stop)
		if err = managers[i].Apply(fixture.Nodes[i]); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := func() map[int]int64 {
		out := map[int]int64{}
		for _, manager := range managers {
			for _, stat := range manager.Snapshot() {
				out[stat.Port] = stat.BytesIn
			}
		}
		return out
	}
	send := func(label string, failed bool) int {
		t.Helper()
		before := snapshot()
		c, err := net.DialTimeout("tcp", address(fixture.EntryPort), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = io.WriteString(c, label); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(label))
		if _, err = io.ReadFull(c, got); err != nil || string(got) != label {
			t.Fatalf("end-to-end echo %q: %q %v", label, got, err)
		}
		_ = c.Close() // TCP counters are committed when io.Copy finishes.
		until := time.Now().Add(3 * time.Second)
		for time.Now().Before(until) {
			after := snapshot()
			for selected := range fixture.BranchPorts {
				if failed && selected != 1 {
					continue
				}
				matches := after[fixture.EntryPort]-before[fixture.EntryPort] == int64(len(label))
				for branch, ports := range fixture.BranchPorts {
					for _, port := range ports {
						// A stopped manager removes its snapshot; other hops of
						// failed B must still receive no bytes from C's payload.
						if failed && owner[port] == failedOwner {
							continue
						}
						want := int64(0)
						if branch == selected {
							want = int64(len(label))
						}
						matches = matches && after[port]-before[port] == want
					}
				}
				if matches {
					return selected
				}
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatalf("payload did not traverse exactly one complete branch: before=%v after=%v", before, snapshot())
		return -1
	}
	selected := [2]int{}
	for i := range 12 {
		selected[send("complete-path-message-"+strconv.Itoa(i), false)]++
	}
	if selected != [2]int{6, 6} {
		t.Fatalf("equal-weight branches did not both carry traffic: %v", selected)
	}
	// Only a closed first hop is tested here; a reachable head with a broken
	// tail needs the separate complete-path handshake health feature.
	managers[failedOwner].Stop()
	for i := range 4 {
		if got := send("surviving-complete-path-"+strconv.Itoa(i), true); got != 1 {
			t.Fatalf("closed B head did not fall back to C: branch=%d", got)
		}
	}
}
