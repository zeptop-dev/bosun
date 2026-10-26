package probe

import (
	"context"
	"net"
	"reflect"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func awaitCarrierResults(t *testing.T, r *Runner, n int) []spec.PingResult {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if got := r.Batch(); len(got) == n {
			return got
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("wanted %d results: %+v", n, r.Batch())
	return nil
}

func TestCarrierDualRecordsAndAcknowledgements(t *testing.T) {
	r := &Runner{Dial: func(context.Context, string) (time.Duration, error) { return time.Millisecond, nil }}
	cfg := &spec.Probe{Enabled: true, CarrierProbe: &spec.CarrierProbeConfig{Family: "dual"}}
	r.Configure(context.Background(), cfg)
	defer r.Stop()
	got := awaitCarrierResults(t, r, 6)
	for _, v := range got {
		if len(v.Quality.Recent) != 1 || v.Series == "" || v.Family == "" {
			t.Fatal(v)
		}
	}
	r.Acknowledge(got[:1])
	batch := r.Batch()
	for i, v := range batch {
		want := 1
		if i == 0 {
			want = 0
		}
		if len(v.Quality.Recent) != want {
			t.Fatal("same-name other family acknowledged", batch)
		}
	}
	old := r.Batch()
	cfg.CarrierProbe.TCPIPv4 = []spec.Carrier{{Name: "CT", Addr: "example.com:443"}}
	r.Configure(context.Background(), cfg)
	changed := awaitCarrierResults(t, r, 4)
	r.Acknowledge(old)
	if len(r.Batch()[0].Quality.Recent) != 1 || changed[0].Series == got[0].Series {
		t.Fatal("old configuration contaminated new series")
	}
	// External mutations do not change the runner's effective configuration.
	cfg.CarrierProbe.TCPIPv4[0].Addr = "other.example.com:443"
	if !reflect.DeepEqual(changed, r.Batch()) {
		t.Fatal("configuration alias")
	}
	// A malformed explicit mode must never start legacy fallback tasks.
	r.Configure(context.Background(), &spec.Probe{Enabled: true, CarrierPing: true, CarrierProbe: &spec.CarrierProbeConfig{Protocol: "unknown"}})
	if len(carrierTasks(r.cfg)) != 0 || len(r.Results()) != 0 {
		t.Fatal("invalid config fell back to TCP")
	}
}

func TestTCPFamilyConstrainedLoopback(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6"} {
		t.Run(family, func(t *testing.T) {
			network, addr := "tcp4", "127.0.0.1:0"
			if family == "ipv6" {
				network, addr = "tcp6", "[::1]:0"
			}
			listener, err := net.Listen(network, addr)
			if err != nil {
				t.Skipf("loopback unavailable: %v", err)
			}
			defer listener.Close()
			go func() {
				c, err := listener.Accept()
				if err == nil {
					c.Close()
				}
			}()
			_, port, _ := net.SplitHostPort(listener.Addr().String())
			r := &Runner{LookupIP: func(_ context.Context, n, h string) ([]net.IP, error) {
				want := "ip4"
				if family == "ipv6" {
					want = "ip6"
				}
				if n != want {
					t.Errorf("resolver network %s", n)
				}
				return []net.IP{net.ParseIP("::1"), net.ParseIP("127.0.0.1")}, nil
			}}
			m := r.scheduled(context.Background(), spec.PingTask{Type: "tcp", Family: family, Target: net.JoinHostPort("example.com", port)}, false)
			if m.Outcome != "ok" || m.LatencyMs < 0 {
				t.Fatal(m)
			}
		})
	}
	// Wrong-family DNS answers are not dialed, even if reachable locally.
	r := &Runner{LookupIP: func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}}
	m := r.scheduled(context.Background(), spec.PingTask{Type: "tcp", Family: "ipv6", Target: "example.com:80"}, true)
	if m.Outcome != "dns" || m.LatencyMs != -1 {
		t.Fatal(m)
	}
}

func TestICMPConstrainedFamilyNeverFallsBackToTCP(t *testing.T) {
	for _, failure := range []error{syscall.EPERM, context.DeadlineExceeded, syscall.ENETUNREACH} {
		var tcpCalls, icmpCalls atomic.Int32
		r := &Runner{
			Dial: func(context.Context, string) (time.Duration, error) { tcpCalls.Add(1); return time.Millisecond, nil },
			LookupIP: func(_ context.Context, n, h string) ([]net.IP, error) {
				if n != "ip6" {
					t.Errorf("network %s", n)
				}
				return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, nil
			},
			ICMP: func(_ context.Context, host, src string) (time.Duration, error) {
				icmpCalls.Add(1)
				if host != "::1" {
					t.Errorf("wrong family %s", host)
				}
				return 0, failure
			},
		}
		m := r.scheduled(context.Background(), spec.PingTask{Type: "icmp", Family: "ipv6", Target: "example.com"}, false)
		if m.Outcome != outcome(failure) || m.LatencyMs != -1 || icmpCalls.Load() != 1 || tcpCalls.Load() != 0 {
			t.Fatal(m)
		}
	}
}

func TestICMPBothLoopbackFamilies(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux ICMP socket verification; macOS raw ping permissions differ")
	}
	for _, tc := range []struct{ family, target string }{{"ipv4", "127.0.0.1"}, {"ipv6", "::1"}} {
		t.Run(tc.family, func(t *testing.T) {
			m := (&Runner{}).scheduled(context.Background(), spec.PingTask{Type: "icmp", Family: tc.family, Target: tc.target}, false)
			if m.Outcome == "permission" || m.Outcome == "unreachable" {
				t.Skipf("ICMP loopback unsupported: %s", m.Outcome)
			}
			if m.Outcome != "ok" || m.LatencyMs < 0 {
				t.Fatal(m)
			}
		})
	}
}
