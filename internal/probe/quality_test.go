package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestScheduledTCPDoesNotHideRefusalOrSlowAttempts(t *testing.T) {
	calls := 0
	r := &Runner{Dial: func(context.Context, string) (time.Duration, error) { calls++; return 1500 * time.Millisecond, nil }}
	task := spec.PingTask{Type: "tcp", Target: "example.com:443"}
	m := r.scheduled(context.Background(), task, false)
	if calls != 1 || m.LatencyMs != 1500 || m.Outcome != "ok" {
		t.Fatalf("slow attempt hidden: %+v calls %d", m, calls)
	}
	r.Dial = func(context.Context, string) (time.Duration, error) {
		return 2 * time.Millisecond, &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
	}
	m = r.scheduled(context.Background(), task, false)
	if m.LatencyMs != -1 || m.Outcome != "refused" {
		t.Fatal(m)
	}
	m = r.scheduled(context.Background(), task, true)
	if m.LatencyMs != 2 || m.Outcome != "refused" {
		t.Fatal("carrier compatibility lost", m)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	m = (&Runner{}).scheduled(context.Background(), spec.PingTask{Type: "tcp", Target: addr}, false)
	if m.Outcome != "refused" || m.LatencyMs >= 0 {
		t.Fatal("real closed port marked healthy", m)
	}
}

func TestHTTPQualityStatusTimingsTLSAndDeadline(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/error":
			w.WriteHeader(503)
		case "/redirect":
			http.Redirect(w, r, "/ok", 302)
		case "/slow":
			<-r.Context().Done()
		default:
			time.Sleep(15 * time.Millisecond)
			w.Write([]byte("ok"))
		}
	}))
	defer server.Close()
	r := &Runner{}
	ctx := context.Background()
	m := r.scheduled(ctx, spec.PingTask{Type: "http", Target: server.URL}, false)
	if m.Outcome != "ok" || m.HTTPStatus != 200 || m.Timings.Connect == nil || m.Timings.Response == nil || *m.Timings.Response < 10 || m.Timings.TLS != nil || m.Timings.DNS != nil {
		t.Fatalf("bad phases %+v %+v", m, m.Timings)
	}
	m = r.scheduled(ctx, spec.PingTask{Type: "http", Target: server.URL + "/error"}, false)
	if m.Outcome != "http_status" || m.LatencyMs != -1 || m.HTTPStatus != 503 {
		t.Fatal(m)
	}
	before := hits.Load()
	m = r.scheduled(ctx, spec.PingTask{Type: "http", Target: server.URL + "/redirect"}, false)
	if m.Outcome != "ok" || m.HTTPStatus != 302 || hits.Load() != before+1 {
		t.Fatal("redirect followed", m)
	}
	short, cancel := context.WithTimeout(ctx, 40*time.Millisecond)
	defer cancel()
	m = r.scheduled(short, spec.PingTask{Type: "http", Target: server.URL + "/slow"}, false)
	if m.Outcome != "timeout" || m.LatencyMs != -1 || m.Timings.Response != nil {
		t.Fatalf("timeout %+v", m)
	}
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer tlsServer.Close()
	tlsServer.Config.ErrorLog = nil
	m = r.scheduled(ctx, spec.PingTask{Type: "http", Target: tlsServer.URL}, false)
	if m.Outcome != "tls" || m.LatencyMs != -1 {
		t.Fatal("invalid certificate accepted", m)
	}
	r.HTTPTransport = tlsServer.Client().Transport.(*http.Transport)
	m = r.scheduled(ctx, spec.PingTask{Type: "http", Target: tlsServer.URL}, false)
	if m.Outcome != "ok" || m.Timings.TLS == nil || m.Timings.Connect == nil {
		t.Fatal("TLS phase missing", m)
	}
}

func TestDownloadRejectsHTTPErrorAndEmptyBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error" {
			w.WriteHeader(503)
			io.WriteString(w, "error page")
		} else if r.URL.Path == "/ok" {
			io.WriteString(w, "download sample")
		}
	}))
	defer server.Close()
	for path, want := range map[string]string{"/error": "http_status", "/empty": "empty", "/ok": "ok"} {
		m := (&Runner{}).scheduled(context.Background(), spec.PingTask{Type: "download", Target: server.URL + path}, false)
		if m.Outcome != want {
			t.Fatal(path, m)
		}
		if want != "ok" && m.Mbps != 0 {
			t.Fatal("failed body measured as throughput", m)
		}
	}
}

func TestQualityWindowBreaksJitterAcrossFailures(t *testing.T) {
	samples := []spec.ProbeMeasurement{{LatencyMs: 10}, {LatencyMs: 20}, {LatencyMs: -1}, {LatencyMs: 100}, {LatencyMs: 110}}
	w := windowStats(samples)
	if w.Attempts != 5 || w.Failed != 1 || *w.P50 != 20 || *w.P95 != 110 || *w.Jitter != 10 || *w.Min != 10 || *w.Max != 110 {
		t.Fatal(w)
	}
	w = windowStats([]spec.ProbeMeasurement{{LatencyMs: -1}})
	if w.Failed != 1 || w.P95 != nil || w.Jitter != nil {
		t.Fatal(w)
	}
}

func TestResultsKeepTimeAndBatchUntilAcknowledged(t *testing.T) {
	r := &Runner{Dial: func(context.Context, string) (time.Duration, error) { return time.Millisecond, nil }}
	r.Configure(context.Background(), &spec.Probe{Enabled: true, Tasks: []spec.PingTask{{ID: 1, Name: "test", Type: "tcp", Target: "example.com", IntervalSeconds: 60}}})
	defer r.Stop()
	deadline := time.Now().Add(time.Second)
	for len(r.Results()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	first := r.Batch()
	if len(first) != 1 || len(first[0].Quality.Recent) != 1 || first[0].Quality.WindowStartedAt != first[0].At {
		t.Fatal(first)
	}
	if len(r.Results()[0].Quality.Recent) != 0 || len(r.Batch()[0].Quality.Recent) != 1 {
		t.Fatal("UI consumed pending measurements")
	}
	r.Acknowledge(first)
	if len(r.Batch()[0].Quality.Recent) != 0 || r.Results()[0].At != first[0].At {
		t.Fatal("ack changed sample time or failed to drain batch")
	}
	// An old epoch response cannot acknowledge a new configuration.
	r.Configure(context.Background(), &spec.Probe{Enabled: true, Tasks: []spec.PingTask{{ID: 1, Name: "test", Type: "tcp", Target: "example.com:443", IntervalSeconds: 60}}})
	deadline = time.Now().Add(time.Second)
	for len(r.Results()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	r.Acknowledge(first)
	if len(r.Batch()[0].Quality.Recent) != 1 {
		t.Fatal("old ack consumed new epoch")
	}
}

func TestCanceledOldConfigurationCannotPublish(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	r := &Runner{Dial: func(_ context.Context, addr string) (time.Duration, error) {
		if addr == "old.example.com:80" {
			close(started)
			<-release
			return 99 * time.Millisecond, nil
		}
		return time.Millisecond, nil
	}}
	r.Configure(context.Background(), &spec.Probe{Enabled: true, Carriers: []spec.Carrier{{Name: "edge", Addr: "old.example.com:80"}}, CarrierPing: true})
	<-started
	r.Configure(context.Background(), &spec.Probe{Enabled: true, Carriers: []spec.Carrier{{Name: "edge", Addr: "new.example.com:80"}}, CarrierPing: true})
	defer r.Stop()
	close(release)
	deadline := time.Now().Add(time.Second)
	for len(r.Results()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := r.Results(); len(got) != 1 || got[0].LatencyMs != 1 {
		t.Fatal("old target contaminated new window", got)
	}
}

func TestOutcomeClassificationDoesNotExposeErrors(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{{&net.DNSError{Err: "private resolver", Name: "private.example.com"}, "dns"}, {syscall.EPERM, "permission"}, {syscall.ENETUNREACH, "unreachable"}, {context.DeadlineExceeded, "timeout"}, {errors.New("private URL or token"), "io"}, {&tls.CertificateVerificationError{Err: errors.New("private certificate")}, "tls"}}
	for _, tc := range cases {
		if got := outcome(tc.err); got != tc.want {
			t.Fatalf("%s != %s", got, tc.want)
		}
	}
}

func TestICMPQualityLoopback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux socket-mode verification")
	}
	m := (&Runner{}).scheduled(context.Background(), spec.PingTask{Type: "icmp", Target: "127.0.0.1"}, false)
	if m.Outcome == "permission" {
		t.Skip("runner has neither raw nor datagram ICMP permission")
	}
	if m.Outcome != "ok" || m.LatencyMs < 0 || m.Timings.DNS != nil {
		t.Fatalf("loopback ICMP: %+v", m)
	}
	m = (&Runner{}).scheduled(context.Background(), spec.PingTask{Type: "icmp", Target: "localhost", SourceIP: "127.0.0.1"}, false)
	if m.Outcome != "ok" || m.LatencyMs < 0 || m.Timings.DNS == nil {
		t.Fatalf("source-bound localhost ICMP: %+v", m)
	}
}

func TestLineAndServiceReachabilityRemainDistinct(t *testing.T) {
	for _, tc := range []struct {
		name             string
		id               int64
		explicit         bool
		wantReachability bool
	}{{"explicit", 1, true, true}, {"older captain line", -1, false, true}, {"ordinary service", 1, false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Runner{DialFrom: func(context.Context, string, string) (time.Duration, error) {
				return time.Millisecond, syscall.ECONNREFUSED
			}}
			r.Configure(context.Background(), &spec.Probe{Enabled: true, Tasks: []spec.PingTask{{ID: tc.id, Type: "tcp", Target: "198.51.100.20:443", SourceIP: "10.10.0.2", TCPReachability: tc.explicit}}})
			defer r.Stop()
			deadline := time.Now().Add(time.Second)
			for len(r.Results()) == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			got := r.Results()
			if len(got) != 1 || (got[0].LatencyMs >= 0) != tc.wantReachability || got[0].Quality.Outcome != "refused" || (got[0].Quality.Type == "tcp_reachability") != tc.wantReachability {
				t.Fatalf("reachability policy: %+v", got)
			}
		})
	}
}

func TestWindowStartedAtUsesActualIncludedSamples(t *testing.T) {
	for _, tc := range []struct {
		name    string
		samples []spec.ProbeMeasurement
		want    int64
	}{
		{"empty", nil, 0},
		{"gaps", []spec.ProbeMeasurement{{Sequence: 1, At: 100}, {Sequence: 4, At: 500}, {Sequence: 9, At: 900}}, 100},
		{"backward clock", []spec.ProbeMeasurement{{Sequence: 1, At: 1000}, {Sequence: 2, At: 900}, {Sequence: 3, At: 950}}, 900},
		{"unknown", []spec.ProbeMeasurement{{Sequence: 1, At: 100}, {Sequence: 2, At: 0}}, 0},
		{"failed sample", []spec.ProbeMeasurement{{Sequence: 1, At: 100, LatencyMs: -1}, {Sequence: 2, At: 110, LatencyMs: 1}}, 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := windowStartedAt(tc.samples); got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
	samples := make([]spec.ProbeMeasurement, ringSize+5)
	for i := range samples {
		samples[i] = spec.ProbeMeasurement{Sequence: uint64(i + 1), At: int64(i + 100)}
	}
	samples[0].At = 0 // An old unacknowledged sample is outside the statistical window.
	if got := windowStartedAt(samples); got != 105 {
		t.Fatalf("included pending samples outside window: %d", got)
	}
	if w := windowStats(samples); w.Attempts != ringSize {
		t.Fatal(w)
	}
}
