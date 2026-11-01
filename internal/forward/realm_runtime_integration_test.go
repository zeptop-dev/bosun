package forward

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func realmRuntimeEcho(t *testing.T) string {
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
	var mu sync.Mutex
	active := map[net.Conn]bool{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			active[c] = true
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				_, _ = io.Copy(c, c)
				mu.Lock()
				delete(active, c)
				mu.Unlock()
			}()
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 256)
		for {
			n, a, e := pc.ReadFrom(buf)
			if e != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], a)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		_ = pc.Close()
		mu.Lock()
		for c := range active {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return ln.Addr().String()
}

func realmConnect(t *testing.T, network, address string) net.Conn {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		c, e := net.DialTimeout(network, address, 200*time.Millisecond)
		if e == nil {
			return c
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("realm listener was not ready")
	return nil
}

func realmRoundTrip(c net.Conn, msg string) error {
	_ = c.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, e := c.Write([]byte(msg)); e != nil {
		return e
	}
	b := make([]byte, len(msg))
	if _, e := io.ReadFull(c, b); e != nil {
		return e
	}
	if string(b) != msg {
		return fmt.Errorf("unexpected response")
	}
	return nil
}

func realmUDPRoundTrip(t *testing.T, c net.Conn) {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for i := 0; time.Now().Before(until); i++ {
		if realmRoundTrip(c, fmt.Sprintf("udp-%08d", i)) == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("realm UDP did not transfer through the single target")
}

// The caller first verifies the manifest-pinned release archive and supplies
// its extracted binary and digest. This test never installs or downloads it.
func TestRealmLinuxRuntimeTransportsAndRestart(t *testing.T) {
	if os.Getenv("BOSUN_REALM_TEST") != "1" || runtime.GOOS != "linux" {
		t.Skip("opt-in pinned realm executable fixture")
	}
	binary, expected := os.Getenv("BOSUN_REALM_BINARY"), strings.ToLower(os.Getenv("BOSUN_REALM_SHA256"))
	if !filepath.IsAbs(binary) || len(expected) != 64 {
		t.Fatal("provide absolute BOSUN_REALM_BINARY and verified BOSUN_REALM_SHA256")
	}
	f, e := os.Open(binary)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.New()
	_, e = io.Copy(h, f)
	_ = f.Close()
	if e != nil {
		t.Fatal(e)
	}
	if actual := hex.EncodeToString(h.Sum(nil)); actual != expected {
		t.Fatal("realm binary digest mismatch")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	version, e := exec.CommandContext(ctx, binary, "--version").CombinedOutput()
	cancel()
	if e != nil || !strings.Contains(string(version), "2.9.6") {
		t.Fatalf("expected pinned realm 2.9.6: %v", e)
	}
	t.Log("verified supplied realm 2.9.6 executable sha256", expected)
	target := realmRuntimeEcho(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := &Realm{Binary: func(context.Context) (string, error) { return binary, nil }, Dir: t.TempDir(), Log: log}
	m := NewManager(log)
	m.Realm = backend
	t.Cleanup(m.Stop)
	both := spec.Forward{Tag: "both", Protocol: "both", Listen: "127.0.0.1", Port: freePort(t), Target: target, Backend: "realm"}
	if e := m.Apply([]spec.Forward{both}); e != nil {
		t.Fatal(e)
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(both.Port))
	tcp := realmConnect(t, "tcp", address)
	defer tcp.Close()
	if e := realmRoundTrip(tcp, "before"); e != nil {
		t.Fatal(e)
	}
	udp := realmConnect(t, "udp", address)
	defer udp.Close()
	realmUDPRoundTrip(t, udp)
	pid := backend.proc.PID()
	if e := m.Apply([]spec.Forward{both}); e != nil {
		t.Fatal(e)
	}
	if backend.proc.PID() != pid {
		t.Fatal("unchanged configuration restarted realm")
	}
	if e := realmRoundTrip(tcp, "unchanged"); e != nil {
		t.Fatal(e)
	}
	pure := spec.Forward{Tag: "udp", Protocol: "udp", Listen: "127.0.0.1", Port: freePort(t), Target: target, Backend: "realm"}
	if e := m.Apply([]spec.Forward{both, pure}); e != nil {
		t.Fatal(e)
	}
	if backend.proc.PID() == pid {
		t.Fatal("changed endpoint set did not replace shared realm process")
	}
	_ = tcp.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, e := tcp.Read(b[:]); e == nil {
		t.Fatal("changed shared process retained old TCP stream")
	} else if timeout, ok := e.(net.Error); ok && timeout.Timeout() {
		t.Fatal("old TCP stream stayed open until deadline")
	}
	newTCP := realmConnect(t, "tcp", address)
	defer newTCP.Close()
	if e := realmRoundTrip(newTCP, "after"); e != nil {
		t.Fatal(e)
	}
	realmUDPRoundTrip(t, udp)
	pureAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(pure.Port))
	pureUDP := realmConnect(t, "udp", pureAddress)
	defer pureUDP.Close()
	realmUDPRoundTrip(t, pureUDP)
	if c, e := net.DialTimeout("tcp", pureAddress, 200*time.Millisecond); e == nil {
		c.Close()
		t.Fatal("UDP-only endpoint unexpectedly accepted TCP")
	}
	t.Log("actual realm TCP/UDP both and UDP-only transfers passed; unchanged rules kept TCP; adding an endpoint replaced process and interrupted old TCP; new traffic recovered")
}
