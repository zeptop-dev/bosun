package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func startUDPWithIdle(t *testing.T, target string, idle time.Duration) (*rule, string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := spec.Forward{Tag: "idle", Protocol: "udp", Target: target}
	r := &rule{spec: f, hops: newHops(f), cancel: cancel, log: slog.Default()}
	r.wg.Add(1)
	go r.serveUDPIdle(ctx, pc, idle)
	t.Cleanup(func() {
		cancel()
		_ = pc.Close()
		done := make(chan struct{})
		go func() { r.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("UDP workers did not stop")
		}
		if r.active.Load() != 0 || r.hops[0].active.Load() != 0 {
			t.Error("cancel leaked active UDP accounting")
		}
	})
	return r, pc.LocalAddr().String()
}

func udpClient(t *testing.T, target string) net.Conn {
	t.Helper()
	c, err := net.Dial("udp", target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func udpSink(t *testing.T) net.PacketConn {
	t.Helper()
	p, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func readDatagram(t *testing.T, p net.PacketConn) (string, net.Addr) {
	t.Helper()
	_ = p.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, a, err := p.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf[:n]), a
}

func waitUDPIdle(t *testing.T, r *rule) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if r.active.Load() == 0 && r.hops[0].active.Load() == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("session did not expire: active=%d hop=%d", r.active.Load(), r.hops[0].active.Load())
}

func TestUDPSuccessfulOneWayTrafficKeepsSession(t *testing.T) {
	for _, direction := range []string{"upload", "download"} {
		t.Run(direction, func(t *testing.T) {
			const idle = 300 * time.Millisecond
			server := udpSink(t)
			r, addr := startUDPWithIdle(t, server.LocalAddr().String(), idle)
			client := udpClient(t, addr)
			if _, err := client.Write([]byte("first")); err != nil {
				t.Fatal(err)
			}
			_, peer := readDatagram(t, server)
			until := time.Now().Add(3 * idle)
			for time.Now().Before(until) {
				if direction == "upload" {
					if _, err := client.Write([]byte("one-way")); err != nil {
						t.Fatal(err)
					}
					msg, nextPeer := readDatagram(t, server)
					if msg != "one-way" || nextPeer.String() != peer.String() {
						t.Fatal("active upload changed UDP association")
					}
				} else {
					if _, err := server.WriteTo([]byte("one-way"), peer); err != nil {
						t.Fatal(err)
					}
					_ = client.SetReadDeadline(time.Now().Add(time.Second))
					buf := make([]byte, 32)
					n, err := client.Read(buf)
					if err != nil || string(buf[:n]) != "one-way" {
						t.Fatalf("active download stopped: %q %v", buf[:n], err)
					}
				}
				time.Sleep(idle / 6)
			}
			if r.total.Load() != 1 || r.active.Load() != 1 {
				t.Fatalf("active one-way traffic was recreated: total=%d active=%d", r.total.Load(), r.active.Load())
			}
			waitUDPIdle(t, r)
			if _, err := client.Write([]byte("new")); err != nil {
				t.Fatal(err)
			}
			if msg, _ := readDatagram(t, server); msg != "new" {
				t.Fatal(msg)
			}
			if r.total.Load() != 2 {
				t.Fatal("idle source did not create a new session")
			}
		})
	}
}

type rejectUDPReply struct {
	net.PacketConn
	called chan struct{}
}

func (p rejectUDPReply) WriteTo([]byte, net.Addr) (int, error) {
	close(p.called)
	return 0, io.ErrClosedPipe
}

func TestUDPReturnClosesActualSocketOnIdleAndClientWriteFailure(t *testing.T) {
	for _, mode := range []string{"idle", "client_write_failure"} {
		t.Run(mode, func(t *testing.T) {
			server, receiver := udpSink(t), udpSink(t)
			upstream := udpClient(t, server.LocalAddr().String())
			s := &udpSession{conn: upstream, hop: &hop{}}
			idle := 50 * time.Millisecond
			called := make(chan struct{})
			var p net.PacketConn = receiver
			if mode == "client_write_failure" {
				idle = time.Second
				p = rejectUDPReply{receiver, called}
			}
			s.activity(idle)
			r := &rule{}
			r.wg.Add(1)
			done := make(chan struct{})
			go r.udpReturn(context.Background(), p, receiver.LocalAddr(), s, idle, func() { close(done) })
			if mode == "client_write_failure" {
				if _, err := server.WriteTo([]byte("reply"), upstream.LocalAddr()); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("return reader leaked")
			}
			r.wg.Wait()
			if mode == "client_write_failure" {
				select {
				case <-called:
				default:
					t.Fatal("client write failure was not exercised")
				}
			}
			if _, err := upstream.Write([]byte("must fail")); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("retired socket remained open: %v", err)
			}
		})
	}
}

func TestUDPConcurrentActivityExpiryAndClose(t *testing.T) {
	server := udpSink(t)
	c := udpClient(t, server.LocalAddr().String())
	s := &udpSession{conn: c, hop: &hop{}}
	s.activity(time.Second)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); s.activity(time.Second); s.expire(time.Now(), time.Second); s.close() }()
	}
	wg.Wait()
	if _, err := c.Write([]byte("closed")); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

// Each backend exposes the same port over TCP and UDP and identifies itself in
// replies. Source ports and payloads prove real session affinity, not just the
// scheduler's in-memory choice.
func dualMarkedEcho(t *testing.T, mark string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 256)
		for {
			n, a, e := pc.ReadFrom(buf)
			if e != nil {
				return
			}
			_, _ = pc.WriteTo(append([]byte(mark), buf[:n]...), a)
		}
	}()
	go func() {
		defer wg.Done()
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			_ = c.SetDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 256)
			n, e := c.Read(buf)
			if e == nil {
				_, _ = c.Write(append([]byte(mark), buf[:n]...))
			}
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); _ = pc.Close(); wg.Wait() })
	return ln.Addr().String()
}

func TestUDPClientAffinityRoundRobinAndBothCancel(t *testing.T) {
	one, two := dualMarkedEcho(t, "A:"), dualMarkedEcho(t, "B:")
	m := NewManager(slog.Default())
	t.Cleanup(m.Stop)
	port := freePort(t)
	f := spec.Forward{Tag: "entry", Protocol: "both", Listen: "127.0.0.1", Port: port, Target: one, Targets: []spec.ForwardTarget{{Target: two}}, Balance: spec.BalanceRoundRobin}
	if err := m.Apply([]spec.Forward{f}); err != nil {
		t.Fatal(err)
	}
	r := m.rules[key(f)]
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for i := 0; i < 4; i++ {
		c := udpClient(t, address)
		want := []string{"A:", "B:"}[i%2]
		for j := 0; j < 3; j++ {
			msg := fmt.Sprintf("%d/%d", i, j)
			if _, err := c.Write([]byte(msg)); err != nil {
				t.Fatal(err)
			}
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 256)
			n, err := c.Read(buf)
			if err != nil || string(buf[:n]) != want+msg {
				t.Fatalf("session selection/affinity: %q %v", buf[:n], err)
			}
		}
	}
	c, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("tcp"))
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 32)
	n, err := c.Read(buf)
	_ = c.Close()
	if err != nil || !strings.HasSuffix(string(buf[:n]), ":tcp") {
		t.Fatalf("both TCP failed: %q %v", buf[:n], err)
	}
	if err := m.Apply(nil); err != nil {
		t.Fatal(err)
	}
	if r.active.Load() != 0 {
		t.Fatalf("cancel retained %d active sessions", r.active.Load())
	}
	for _, h := range r.hops {
		if h.active.Load() != 0 {
			t.Fatal("cancel retained hop sessions")
		}
	}
}
