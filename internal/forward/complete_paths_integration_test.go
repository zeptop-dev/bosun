package forward

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

type compiledPathTransportFixture struct {
	Protocol               string
	EntryPort, LandingPort int
	Nodes                  [][]spec.Forward
	BranchPorts            [][]int
}

func compiledLanding(t *testing.T, f compiledPathTransportFixture) {
	t.Helper()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(f.LandingPort))
	pc, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		for {
			n, a, e := pc.ReadFrom(buf)
			if e != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], a)
		}
	}()
	var ln net.Listener
	if f.Protocol == "both" {
		ln, err = net.Listen("tcp", address)
		if err != nil {
			_ = pc.Close()
			wg.Wait()
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				c, e := ln.Accept()
				if e != nil {
					return
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(5 * time.Second))
					_, _ = io.Copy(c, c)
				}()
			}
		}()
	}
	t.Cleanup(func() {
		_ = pc.Close()
		if ln != nil {
			_ = ln.Close()
		}
		wg.Wait()
	})
}

// Captain's exporter invokes its real transactional compiler. This reader uses
// those rules unchanged and checks the route taken by each actual payload.
func TestCompiledCompletePathTransports(t *testing.T) {
	dir := os.Getenv("CAPTAIN_PATH_TRANSPORT_FIXTURES")
	if dir == "" {
		t.Skip("set CAPTAIN_PATH_TRANSPORT_FIXTURES to Captain's exported UDP/both fixtures")
	}
	for _, protocol := range []string{"udp", "both"} {
		t.Run(protocol, func(t *testing.T) {
			var f compiledPathTransportFixture
			raw, err := os.ReadFile(filepath.Join(dir, protocol+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(raw, &f); err != nil {
				t.Fatal(err)
			}
			if f.Protocol != protocol || len(f.Nodes) != 3 || len(f.BranchPorts) != 2 || len(f.BranchPorts[0]) != 2 || len(f.BranchPorts[1]) != 1 {
				t.Fatal("fixture must contain complete two-hop and one-hop branches")
			}
			byPort := map[int]spec.Forward{}
			for _, node := range f.Nodes {
				for _, rule := range node {
					if rule.Protocol != protocol || rule.Backend != "" || rule.PathHealth != nil || rule.Listen != "127.0.0.1" {
						t.Fatal("fixture must use ordinary loopback native relays with no health probes")
					}
					if _, dup := byPort[rule.Port]; dup {
						t.Fatal("fixture reused a dedicated listener")
					}
					byPort[rule.Port] = rule
				}
			}
			entry, ok := byPort[f.EntryPort]
			if !ok || entry.BalanceMode() != spec.BalanceRoundRobin || len(entry.Hops()) != 2 {
				t.Fatal("fixture must use a native round-robin entry")
			}
			for branch, ports := range f.BranchPorts {
				if entry.Hops()[branch].Target != net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[0])) {
					t.Fatal("entry does not select complete branch heads")
				}
				for i, port := range ports {
					next := f.LandingPort
					if i+1 < len(ports) {
						next = ports[i+1]
					}
					member, ok := byPort[port]
					if !ok || len(member.Hops()) != 1 || member.Target != net.JoinHostPort("127.0.0.1", strconv.Itoa(next)) {
						t.Fatal("compiler emitted a cross-branch edge or changed hop order")
					}
				}
			}
			compiledLanding(t, f)
			var managers []*Manager
			for _, node := range f.Nodes {
				m := NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)))
				managers = append(managers, m)
				t.Cleanup(m.Stop)
				if err := m.Apply(node); err != nil {
					t.Fatal(err)
				}
			}
			snapshot := func() map[int]int64 {
				out := map[int]int64{}
				for _, m := range managers {
					for _, s := range m.Snapshot() {
						out[s.Port] = s.BytesIn
					}
				}
				return out
			}
			branchDelta := func(before map[int]int64, n int) int {
				t.Helper()
				until := time.Now().Add(time.Second)
				for time.Now().Before(until) {
					after := snapshot()
					for candidate := range f.BranchPorts {
						matches := true
						for branch, ports := range f.BranchPorts {
							for _, port := range ports {
								want := int64(0)
								if branch == candidate {
									want = int64(n)
								}
								if after[port]-before[port] != want {
									matches = false
								}
							}
						}
						if matches {
							return candidate
						}
					}
					time.Sleep(time.Millisecond)
				}
				t.Fatalf("payload did not traverse exactly one complete branch: before=%v after=%v", before, snapshot())
				return -1
			}
			address := net.JoinHostPort("127.0.0.1", strconv.Itoa(f.EntryPort))
			transfer := func(c net.Conn, msg string) {
				t.Helper()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				if _, e := c.Write([]byte(msg)); e != nil {
					t.Fatal(e)
				}
				buf := make([]byte, len(msg))
				if _, e := io.ReadFull(c, buf); e != nil || string(buf) != msg {
					t.Fatalf("actual compiled route failed: %v", e)
				}
			}
			exchange := func(c net.Conn, msg string) int {
				t.Helper()
				before := snapshot()
				transfer(c, msg)
				return branchDelta(before, len(msg))
			}
			selected := [2]int{}
			for source := range 6 {
				c, e := net.Dial("udp", address)
				if e != nil {
					t.Fatal(e)
				}
				defer c.Close()
				chosen := -1
				for packet := range 5 {
					branch := exchange(c, fmt.Sprintf("udp-source-%d-packet-%d", source, packet))
					if chosen >= 0 && branch != chosen {
						t.Fatal("existing UDP source changed branch")
					}
					chosen = branch
				}
				selected[chosen]++
			}
			if selected != [2]int{3, 3} {
				t.Fatalf("new UDP sessions did not follow equal-weight round robin: %v", selected)
			}
			if protocol == "both" {
				for source := range 4 {
					c, e := net.DialTimeout("tcp", address, time.Second)
					if e != nil {
						t.Fatal(e)
					}
					before := snapshot()
					payloadBytes := 0
					for message := range 3 {
						msg := fmt.Sprintf("tcp-source-%d-message-%d", source, message)
						transfer(c, msg)
						payloadBytes += len(msg)
					}
					_ = c.Close()
					// TCP accounts io.Copy bytes when the stream finishes; UDP
					// accounts each datagram. Do not demand mid-stream counters.
					branchDelta(before, payloadBytes)
				}
			}
			t.Logf("actual Captain %s compiler output passed: 2-hop/1-hop paths, six sticky UDP sessions, 1:1 new-session selection, no cross-branch payloads", protocol)
		})
	}
}
