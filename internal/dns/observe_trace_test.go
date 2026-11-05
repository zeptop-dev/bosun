package dns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

func traceText(host, address string) string {
	return "fl=test\nh=" + host + "\nip=" + address + "\nts=1793912345.123\nvisit_scheme=https\ncolo=LAX\ntls=TLSv1.3\nwarp=off\n"
}

// Only tests install a private test CA. The production client has no TLS override.
func trustTraceServer(client *http.Client, srv *httptest.Server) {
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: roots}
}

func TestTraceOrigin(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"https://example.com:2096/agent/path?pair=secret#token", "https://example.com:2096"},
		{"https://[2001:db8::10]:2096", "https://[2001:db8::10]:2096"},
		{"https://example.com", "https://example.com"},
		{"http://example.com:2096", ""},
		{"https://user:password@example.com:2096", ""},
		{"https:example.com", ""},
		{"https:///missing", ""},
		{"https://example.com:0", ""},
		{"https://example.com:", ""},
		{"https://example.com:65536", ""},
		{"https://example.com:port", ""},
		{strings.Repeat("x", 2049), ""},
	} {
		got := traceOrigin(tc.input)
		if tc.want == "" {
			if got != nil {
				t.Errorf("invalid origin accepted: %q", tc.input)
			}
		} else if got == nil || got.String() != tc.want {
			t.Errorf("origin = %v, want %s", got, tc.want)
		}
	}
}

func TestTraceUsesAnonymousHTTPSOriginAndIgnoresProxy(t *testing.T) {
	var proxied, requests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxied.Add(1); w.WriteHeader(502) }))
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("ALL_PROXY", proxy.URL)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "GET" || r.URL.RequestURI() != "/cdn-cgi/trace" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Proxy-Authorization") != "" {
			t.Errorf("unexpected request: %s %s, headers %v", r.Method, r.URL.RequestURI(), r.Header)
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "must-not-return"})
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, traceText(r.Host, "198.51.100.20"))
	}))
	defer srv.Close()
	client := publicAddressClient(false)
	defer client.CloseIdleConnections()
	if client.Transport.(*http.Transport).Proxy != nil || client.Jar != nil {
		t.Fatal("public address client has proxy or cookies")
	}
	trustTraceServer(client, srv)
	for range 2 {
		got := observeTrace(context.Background(), client, srv.URL+"/prefix?pair=secret#token", false)
		if got == nil || got.Address != "198.51.100.20" || got.Error != "" || got.Source != agentproto.PublicAddressFallbackSource || got.Origin != srv.URL || got.SampledAt < time.Now().Unix()-1 {
			t.Fatalf("observation = %+v", got)
		}
	}
	if proxied.Load() != 0 || requests.Load() != 2 {
		t.Fatal("request escaped configured origin")
	}
}

func TestTraceTLSVerificationCannotBeBypassed(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer srv.Close()
	client := publicAddressClient(false)
	defer client.CloseIdleConnections()
	got := observeTrace(context.Background(), client, srv.URL, false)
	if got == nil || got.Address != "" || got.Error != "tls" || requests.Load() != 0 {
		t.Fatalf("untrusted TLS was not rejected: %+v requests=%d", got, requests.Load())
	}
}

func TestTraceDoesNotFollowRedirects(t *testing.T) {
	var next atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { next.Add(1) }))
	defer target.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/cdn-cgi/trace", http.StatusFound)
	}))
	defer srv.Close()
	client := publicAddressClient(false)
	defer client.CloseIdleConnections()
	trustTraceServer(client, srv)
	got := observeTrace(context.Background(), client, srv.URL, false)
	if got == nil || got.Address != "" || got.Error != "http_status" || next.Load() != 0 {
		t.Fatalf("redirect result: %+v, second origin calls %d", got, next.Load())
	}
}

func TestTraceRejectsInvalidResponse(t *testing.T) {
	for _, tc := range []struct {
		name, contentType, address, suffix string
		status                             int
		v6                                 bool
	}{
		{name: "direct Captain 404", status: 404},
		{name: "HTML", status: 200, contentType: "text/html", address: "198.51.100.20"},
		{name: "oversized", status: 200, contentType: "text/plain", address: "198.51.100.20", suffix: "extra=" + strings.Repeat("a", traceBodyLimit)},
		{name: "duplicate", status: 200, contentType: "text/plain", address: "198.51.100.20", suffix: "ip=203.0.113.30\n"},
		{name: "private", status: 200, contentType: "text/plain", address: "10.10.0.2"},
		{name: "wrong family", status: 200, contentType: "text/plain", address: "198.51.100.20", v6: true},
		{name: "IPv4 mapped", status: 200, contentType: "text/plain", address: "::ffff:198.51.100.20", v6: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				fmt.Fprint(w, traceText(r.Host, tc.address)+tc.suffix)
			}))
			defer srv.Close()
			client := publicAddressClient(false)
			defer client.CloseIdleConnections()
			trustTraceServer(client, srv)
			got := observeTrace(context.Background(), client, srv.URL, tc.v6)
			want := "invalid_response"
			if tc.status != 200 {
				want = "http_status"
			}
			if got == nil || got.Address != "" || got.Error != want {
				t.Fatalf("invalid response accepted: %+v", got)
			}
		})
	}
	origin, _ := url.Parse("https://example.com:2096")
	for _, body := range []string{
		"ip=198.51.100.20", strings.ReplaceAll(traceText("example.com", "198.51.100.20"), "1793912345.123", "NaN"),
		traceText("other.example.com", "198.51.100.20"), strings.ReplaceAll(traceText("example.com", "198.51.100.20"), "TLSv1.3", "off"),
	} {
		if parseTrace([]byte(body), origin, false) != "" {
			t.Fatal("invalid trace parsed")
		}
	}
}

func TestTraceForcesAddressFamily(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, traceText(r.Host, "198.51.100.20"))
	}))
	defer srv.Close()
	v6Client := publicAddressClient(true)
	defer v6Client.CloseIdleConnections()
	trustTraceServer(v6Client, srv)
	got := observeTrace(context.Background(), v6Client, srv.URL, true)
	if got == nil || got.Address != "" || got.Error != "network" {
		t.Fatalf("tcp6 reached v4 address: %+v", got)
	}

	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback unavailable")
	}
	v6Server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, traceText(r.Host, "2001:db8::10"))
	}))
	v6Server.Listener.Close()
	v6Server.Listener = ln
	v6Server.StartTLS()
	defer v6Server.Close()
	trustTraceServer(v6Client, v6Server)
	got = observeTrace(context.Background(), v6Client, v6Server.URL, true)
	if got == nil || got.Address != "2001:db8::10" || got.Error != "" {
		t.Fatalf("tcp6 observation: %+v", got)
	}
	v4Client := publicAddressClient(false)
	defer v4Client.CloseIdleConnections()
	trustTraceServer(v4Client, v6Server)
	got = observeTrace(context.Background(), v4Client, v6Server.URL, false)
	if got == nil || got.Address != "" || got.Error != "network" {
		t.Fatalf("tcp4 reached v6 address: %+v", got)
	}
}

func TestConsensusWinsAndFallbackNeverPromotes(t *testing.T) {
	var traceCalls atomic.Int32
	var agreeing atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.Path == "/cdn-cgi/trace" {
			traceCalls.Add(1)
			fmt.Fprint(w, traceText(r.Host, "198.51.100.20"))
		} else if r.URL.Path == "/a" || agreeing.Load() {
			fmt.Fprint(w, "203.0.113.30")
		} else {
			w.WriteHeader(503)
		}
	}))
	defer srv.Close()
	client := publicAddressClient(false)
	defer client.CloseIdleConnections()
	trustTraceServer(client, srv)
	urls := []string{srv.URL + "/a", srv.URL + "/b"}
	for range 3 {
		value, fallback := observeFamilyWithFallback(context.Background(), client, urls, srv.URL, false)
		if value != "" || fallback == nil || fallback.Address != "198.51.100.20" {
			t.Fatalf("single source promoted: %s %+v", value, fallback)
		}
	}
	agreeing.Store(true)
	value, fallback := observeFamilyWithFallback(context.Background(), client, urls, srv.URL, false)
	if value != "203.0.113.30" || fallback != nil || traceCalls.Load() != 3 {
		t.Fatalf("fallback replaced consensus: %s %+v", value, fallback)
	}
}

func TestTraceSlowBodyHonorsDeadline(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()
	client := publicAddressClient(false)
	defer client.CloseIdleConnections()
	trustTraceServer(client, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	got := observeTrace(ctx, client, srv.URL, false)
	if got == nil || got.Address != "" || got.Error != "timeout" {
		t.Fatalf("unbounded body: %+v", got)
	}
}

func TestConsensusRequestsRunTogetherBeforeFallback(t *testing.T) {
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		select {
		case <-release:
			fmt.Fprint(w, "198.51.100.20")
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	client := publicAddressClient(false)
	defer client.CloseIdleConnections()
	trustTraceServer(client, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan string, 1)
	go func() { done <- observeFamily(ctx, client, []string{srv.URL + "/a", srv.URL + "/b"}, false) }()
	for range 2 {
		select {
		case <-arrived:
		case <-ctx.Done():
			t.Fatal("sources did not run concurrently")
		}
	}
	close(release)
	if got := <-done; got != "198.51.100.20" {
		t.Fatalf("parallel consensus: %s", got)
	}
}
