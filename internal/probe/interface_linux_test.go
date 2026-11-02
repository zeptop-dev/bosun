//go:build linux

package probe

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Run only inside an outer private network namespace:
// BOSUN_TEST_PROBE_INTERFACE_NAMESPACE=1 unshare --net ./probe.test -test.run TestBoundProbeNamespace -test.v
func TestBoundProbeNamespace(t *testing.T) {
	if os.Getenv("BOSUN_TEST_PROBE_INTERFACE_NAMESPACE") != "1" {
		t.Skip("requires explicit isolated Linux namespace")
	}
	self, e1 := os.Stat("/proc/self/ns/net")
	init, e2 := os.Stat("/proc/1/ns/net")
	if e1 != nil || e2 != nil || os.SameFile(self, init) {
		t.Fatal("refusing network setup in host namespace")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root in isolated namespace")
	}
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	peer := exec.Command("unshare", "--net", os.Args[0], "-test.run", "^TestBoundProbePeerHelper$", "-test.v")
	peer.Env = append(os.Environ(), "BOSUN_PROBE_PEER_HELPER=1")
	in, err := peer.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := peer.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	peer.Stderr = os.Stderr
	if err = peer.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { in.Close(); peer.Process.Kill(); peer.Wait() }()
	lines := make(chan string, 64)
	go func() {
		defer close(lines)
		scan := bufio.NewScanner(out)
		for scan.Scan() {
			lines <- scan.Text()
		}
	}()
	waitLine := func(prefix string) string {
		t.Helper()
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		for {
			select {
			case line, ok := <-lines:
				if !ok {
					t.Fatal("peer stopped")
				}
				if strings.HasPrefix(line, prefix) {
					return strings.TrimPrefix(line, prefix)
				}
			case <-deadline.C:
				t.Fatal("peer timed out waiting for " + prefix)
			}
		}
	}
	waitLine("PEER_READY")
	run("link", "set", "lo", "up")
	run("link", "add", "wan-good", "type", "veth", "peer", "name", "peer-good")
	run("link", "set", "peer-good", "netns", fmt.Sprint(peer.Process.Pid))
	run("addr", "add", "198.51.100.1/24", "dev", "wan-good")
	run("-6", "addr", "add", "2001:db8:1::1/64", "dev", "wan-good", "nodad")
	run("link", "set", "wan-good", "up")
	run("link", "add", "wan-wrong", "type", "dummy")
	run("addr", "add", "203.0.113.1/24", "dev", "wan-wrong")
	run("link", "set", "wan-wrong", "up")
	run("route", "add", "default", "via", "198.51.100.2", "dev", "wan-good")
	run("-6", "route", "add", "default", "via", "2001:db8:1::2", "dev", "wan-good")
	fmt.Fprintln(in, "start")
	waitLine("SERVERS_READY")
	runner := &Runner{}
	for _, family := range []string{"ipv4", "ipv6"} {
		target, source := "198.51.100.2", "198.51.100.1"
		if family == "ipv6" {
			target, source = "2001:db8:1::2", "2001:db8:1::1"
		}
		for _, kind := range []string{"tcp", "icmp"} {
			dst := target
			if kind == "tcp" {
				dst = net.JoinHostPort(target, "19080")
			}
			task := spec.PingTask{Type: kind, Target: dst, Family: family, SourceInterface: "wan-good", SourceIP: source}
			m := runner.MeasureOnce(context.Background(), task)
			if m.Outcome != "ok" || m.LatencyMs < 0 {
				t.Fatalf("bound %s %s failed: %+v", family, kind, m)
			}
			if kind == "tcp" {
				got := waitLine("SOURCE=")
				host, _, e := net.SplitHostPort(got)
				if e != nil || host != source {
					t.Fatalf("unexpected packet source %q want %q", got, source)
				}
			}
			// A working default path exists. A missing, wrong or down interface must
			// never fall back to it, including when the probe carries no SourceIP.
			for _, device := range []string{"wan-missing", "wan-wrong"} {
				task.SourceInterface = device
				task.SourceIP = ""
				ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
				m = runner.MeasureOnce(ctx, task)
				cancel()
				if m.Outcome == "ok" || m.LatencyMs >= 0 {
					t.Fatalf("%s %s silently fell back via %s: %+v", family, kind, device, m)
				}
			}
			task.SourceInterface = "wan-good"
			task.SourceIP = "192.0.2.10"
			m = runner.MeasureOnce(context.Background(), task)
			if m.Outcome != "interface" && m.Outcome != "invalid" {
				t.Fatalf("wrong source accepted %+v", m)
			}
		}
	}
	run("link", "set", "wan-good", "down")
	for _, kind := range []string{"tcp", "icmp"} {
		target := "198.51.100.2"
		if kind == "tcp" {
			target += ":19080"
		}
		m := runner.MeasureOnce(context.Background(), spec.PingTask{Type: kind, Target: target, SourceInterface: "wan-good"})
		if m.Outcome != "interface" || m.LatencyMs >= 0 {
			t.Fatalf("down interface %+v", m)
		}
	}
}

func TestBoundProbePeerHelper(t *testing.T) {
	if os.Getenv("BOSUN_PROBE_PEER_HELPER") != "1" {
		t.Skip("namespace peer helper")
	}
	fmt.Println("PEER_READY")
	reader := bufio.NewReader(os.Stdin)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"link", "set", "lo", "up"},
		{"addr", "add", "198.51.100.2/24", "dev", "peer-good"},
		{"-6", "addr", "add", "2001:db8:1::2/64", "dev", "peer-good", "nodad"},
		{"link", "set", "peer-good", "up"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("peer setup %v: %v %s", args, err, out)
		}
	}
	var printMu sync.Mutex
	for _, addr := range []string{"198.51.100.2:19080", "[2001:db8:1::2]:19080"} {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			for {
				c, e := listener.Accept()
				if e != nil {
					return
				}
				printMu.Lock()
				fmt.Println("SOURCE=" + c.RemoteAddr().String())
				printMu.Unlock()
				c.Close()
			}
		}()
	}
	fmt.Println("SERVERS_READY")
	reader.ReadString('\n')
}
