package forward

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"gitlab.com/boyang-hu/bosun/pkg/spec"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func tcpEcho(t *testing.T) string {
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
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

func udpEcho(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], from)
		}
	}()
	return pc.LocalAddr().String()
}

func TestTCPForward(t *testing.T) {
	target := tcpEcho(t)
	port := freePort(t)
	m := NewManager(slog.Default())
	defer m.Stop()
	if err := m.Apply([]spec.Forward{{Tag: "t", Listen: "127.0.0.1", Port: port, Protocol: "tcp", Target: target}}); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	msg := []byte("hello through relay")
	c.Write(msg)
	got := make([]byte, len(msg))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echo: %v %q", err, got)
	}
	c.Close()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		s := m.Snapshot()[0]
		if s.TotalConn == 1 && s.BytesIn == int64(len(msg)) && s.BytesOut == int64(len(msg)) && s.ActiveConn == 0 && s.Up && s.RTT > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("stats: %+v", m.Snapshot()[0])
}

func TestUDPForward(t *testing.T) {
	target := udpEcho(t)
	port := freePort(t)
	m := NewManager(slog.Default())
	defer m.Stop()
	if err := m.Apply([]spec.Forward{{Tag: "u", Listen: "127.0.0.1", Port: port, Protocol: "udp", Target: target}}); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 3; i++ {
		msg := []byte("ping " + strconv.Itoa(i))
		c.Write(msg)
		got := make([]byte, 64)
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := c.Read(got)
		if err != nil || !bytes.Equal(got[:n], msg) {
			t.Fatalf("udp echo %d: %v %q", i, err, got[:n])
		}
	}
	s := m.Snapshot()[0]
	if s.TotalConn != 1 || s.BytesIn == 0 || s.BytesOut == 0 {
		t.Fatalf("stats: %+v", s)
	}
}

func TestApplyDiffAndValidate(t *testing.T) {
	target := tcpEcho(t)
	p1, p2 := freePort(t), freePort(t)
	m := NewManager(slog.Default())
	defer m.Stop()
	a := spec.Forward{Tag: "a", Listen: "127.0.0.1", Port: p1, Protocol: "tcp", Target: target}
	b := spec.Forward{Tag: "b", Listen: "127.0.0.1", Port: p2, Protocol: "both", Target: target}
	if err := m.Apply([]spec.Forward{a, b}); err != nil {
		t.Fatal(err)
	}
	if len(m.Snapshot()) != 2 {
		t.Fatal("expected 2 rules")
	}
	// Remove b, keep a: a's listener must stay open.
	if err := m.Apply([]spec.Forward{a}); err != nil {
		t.Fatal(err)
	}
	if c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(p1), time.Second); err != nil {
		t.Fatal("a should still listen:", err)
	} else {
		c.Close()
	}
	if _, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(p2), 300*time.Millisecond); err == nil {
		t.Fatal("b should be closed")
	}
	// Validation.
	bad := []spec.Forward{{Tag: "x", Port: 1, Protocol: "sctp", Target: "1.2.3.4:5"}}
	if err := m.Apply(bad); err == nil {
		t.Fatal("bad protocol accepted")
	}
	dup := []spec.Forward{a, {Tag: "dup", Listen: "127.0.0.1", Port: p1, Protocol: "tcp", Target: target}}
	if err := m.Apply(dup); err == nil {
		t.Fatal("duplicate port accepted")
	}
}

func TestProbeDown(t *testing.T) {
	port := freePort(t)
	dead := "127.0.0.1:" + strconv.Itoa(freePort(t))
	m := NewManager(slog.Default())
	defer m.Stop()
	if err := m.Apply([]spec.Forward{{Tag: "d", Listen: "127.0.0.1", Port: port, Protocol: "tcp", Target: dead}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if s := m.Snapshot()[0]; !s.Up && s.LastError != "" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("probe should report down: %+v", m.Snapshot()[0])
}
