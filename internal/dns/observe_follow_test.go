package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

func TestFallbackFollowChecksAllSuccessfulSources(t *testing.T) {
	for _, tc := range []struct {
		name, a, b, fallback, want string
		v6                         bool
		traceStatus                int
	}{
		{name: "all unavailable", fallback: "198.51.100.20", want: "no_conflict"},
		{name: "first agrees", a: "198.51.100.20", fallback: "198.51.100.20", want: "no_conflict"},
		{name: "second agrees", b: "198.51.100.20", fallback: "198.51.100.20", want: "no_conflict"},
		{name: "first conflicts", a: "203.0.113.30", fallback: "198.51.100.20", want: "conflict"},
		{name: "second conflicts", b: "203.0.113.30", fallback: "198.51.100.20", want: "conflict"},
		{name: "primary conflict matches first", a: "198.51.100.20", b: "203.0.113.30", fallback: "198.51.100.20", want: "conflict"},
		{name: "primary conflict matches second", a: "203.0.113.30", b: "198.51.100.20", fallback: "198.51.100.20", want: "conflict"},
		{name: "primary conflict matches neither", a: "203.0.113.30", b: "192.0.2.10", fallback: "198.51.100.20", want: "conflict"},
		{name: "invalid source ignored", a: "<html>198.51.100.20</html>", fallback: "198.51.100.20", want: "no_conflict"},
		{name: "fallback invalid", fallback: "10.10.0.2"},
		{name: "fallback HTTP error", fallback: "198.51.100.20", traceStatus: 503},
		{name: "IPv6 available", a: "2001:db8:0::10", fallback: "2001:db8::10", v6: true, want: "no_conflict"},
		{name: "IPv6 conflict", b: "2001:db8::20", fallback: "2001:db8::10", v6: true, want: "conflict"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				if r.URL.Path == "/cdn-cgi/trace" {
					if tc.traceStatus != 0 {
						w.WriteHeader(tc.traceStatus)
					}
					fmt.Fprint(w, traceText(r.Host, tc.fallback))
					return
				}
				value := tc.a
				if r.URL.Path == "/b" {
					value = tc.b
				}
				if value == "" {
					w.WriteHeader(http.StatusServiceUnavailable)
				}
				fmt.Fprint(w, value)
			}))
			defer srv.Close()
			client := publicAddressClient(false) // IPv6 payload validation is tested over the same local TLS fixture.
			defer client.CloseIdleConnections()
			trustTraceServer(client, srv)
			value, fallback := observeFamilyWithFallback(context.Background(), client, []string{srv.URL + "/a", srv.URL + "/b"}, srv.URL, tc.v6)
			if value != "" || fallback == nil || fallback.CheckStatus != tc.want || fallback.RunID != "" {
				t.Fatalf("consensus=%q fallback=%+v, want check %q without run identity", value, fallback, tc.want)
			}
		})
	}
}

func TestFallbackFollowCannotUseIncompleteProbe(t *testing.T) {
	for _, phase := range []string{"regular", "fallback"} {
		t.Run(phase, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if (r.URL.Path == "/cdn-cgi/trace") == (phase == "fallback") {
					w.Header().Set("Content-Type", "text/plain")
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					return
				}
				w.WriteHeader(503)
			}))
			defer srv.Close()
			client := publicAddressClient(false)
			defer client.CloseIdleConnections()
			trustTraceServer(client, srv)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			value, fallback := observeFamilyWithFallback(ctx, client, []string{srv.URL + "/a", srv.URL + "/b"}, srv.URL, false)
			if value != "" || fallback != nil && (fallback.CheckStatus != "" || fallback.RunID != "") {
				t.Fatalf("cancelled sample carries follow evidence: %q %+v", value, fallback)
			}
		})
	}
}

// Optional cross-repository fixture export. The real TLS responders below
// produce the raw samples; Captain driver tests attach sampler continuity.
func TestFallbackFollowContractRawExport(t *testing.T) {
	var conflict atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.Path == "/cdn-cgi/trace" {
			fmt.Fprint(w, traceText(r.Host, "198.51.100.20"))
		} else if r.URL.Path == "/a" && conflict.Load() {
			fmt.Fprint(w, "203.0.113.30")
		} else {
			w.WriteHeader(503)
		}
	}))
	defer srv.Close()
	client := publicAddressClient(false)
	defer client.CloseIdleConnections()
	trustTraceServer(client, srv)
	var samples []agentproto.PublicAddresses
	for i := range 5 {
		conflict.Store(i == 2)
		// Only one regular responder is available during the conflicting sample.
		value, fallback := observeFamilyWithFallback(context.Background(), client, []string{srv.URL + "/a", srv.URL + "/b"}, srv.URL, false)
		want := agentproto.PublicAddressFallbackCheckNoConflict
		if conflict.Load() {
			want = agentproto.PublicAddressFallbackCheckConflict
		}
		if value != "" || fallback == nil || fallback.CheckStatus != want {
			t.Fatalf("unexpected real sample %d: %q %+v", i, value, fallback)
		}
		// Time alone is controlled for later cross-repository confirmation tests.
		fallback.SampledAt = 1_800_000_000 + int64(i)*120
		samples = append(samples, agentproto.PublicAddresses{SampledAt: fallback.SampledAt, FallbackIPv4: fallback})
	}
	if path := os.Getenv("BOSUN_ADDRESS_CONTRACT_RAW"); path != "" {
		body, err := json.MarshalIndent(samples, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
