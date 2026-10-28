package snell

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Run with a pinned official snell-server binary in an isolated Linux network
// namespace. This checks actual listeners, not proxy authentication or egress.
// The explicit :: case requires IPv6 and IPv4-mapped socket support; a failure
// means that host/core combination cannot provide both families from this bind.
// This opt-in test has not yet been executed against a Linux Snell server.
func TestSnellListenerFamiliesLive(t *testing.T) {
	binary := os.Getenv("BOSUN_SNELL_TEST_BINARY")
	if binary == "" {
		t.Skip("set BOSUN_SNELL_TEST_BINARY in an isolated network namespace")
	}
	for _, tc := range []struct {
		name, listen string
		v4, v6       bool
	}{
		{"default-ipv4", "", true, false},
		{"explicit-dual-wildcard", "::", true, true},
		{"explicit-ipv4", "0.0.0.0", true, false},
		{"explicit-ipv6", "::1", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe, err := net.Listen("tcp6", "[::1]:0")
			if err != nil {
				t.Fatal(err)
			}
			port := probe.Addr().(*net.TCPAddr).Port
			_ = probe.Close()
			cfg, err := render(spec.Inbound{Tag: "dual-stack-test", Protocol: spec.Snell, Port: port, Listen: tc.listen, SnellPSK: "test-key"})
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			file := filepath.Join(dir, "snell-server.conf")
			if err = os.WriteFile(file, cfg, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "-c", file)
			log, err := os.Create(filepath.Join(dir, "server.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			cmd.Stdout, cmd.Stderr = log, log
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cancel(); _ = cmd.Wait() }()
			connected := func(network, host string) bool {
				conn, err := net.DialTimeout(network, net.JoinHostPort(host, strconv.Itoa(port)), 100*time.Millisecond)
				if err == nil {
					_ = conn.Close()
				}
				return err == nil
			}
			v4, v6 := false, false
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
				v4, v6 = connected("tcp4", "127.0.0.1"), connected("tcp6", "::1")
				if v4 == tc.v4 && v6 == tc.v6 {
					return
				}
				time.Sleep(25 * time.Millisecond)
			}
			output, _ := os.ReadFile(log.Name())
			t.Fatalf("listener families: v4=%v v6=%v; expected %v/%v\n%s", v4, v6, tc.v4, tc.v6, output)
		})
	}
}
