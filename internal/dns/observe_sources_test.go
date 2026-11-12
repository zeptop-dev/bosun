package dns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRedundantAddressConsensus(t *testing.T) {
	for _, tc := range []struct {
		values []string
		want   string
	}{
		{[]string{"", "192.0.2.10", "192.0.2.10", "192.0.2.10"}, "192.0.2.10"},
		{[]string{"", "", "192.0.2.10", "192.0.2.10"}, "192.0.2.10"},
		{[]string{"192.0.2.10", "", "", ""}, ""},
		{[]string{"192.0.2.10", "192.0.2.10", "192.0.2.10", "198.51.100.20"}, ""},
		{[]string{"192.0.2.10", "198.51.100.20", "", ""}, ""},
		{[]string{"", "", "", ""}, ""},
	} {
		if got := addressConsensus(tc.values); got != tc.want {
			t.Fatalf("%v: %s", tc.values, got)
		}
	}
}
func TestIPIPResponseStrictField(t *testing.T) {
	for _, tc := range []struct {
		body string
		want string
	}{
		{"当前 IP：192.0.2.10  来自于：中国 上海 上海  电信\n", "192.0.2.10"},
		{"当前 IP：10.10.0.2  来自于：中国", ""},
		{"当前 IP：2001:db8::10  来自于：中国", ""},
		{"<html>当前 IP：192.0.2.10  来自于：中国</html>", ""},
		{"error 192.0.2.10", ""}, {"当前 IP：192.0.2.10", ""},
		{"当前 IP：192.0.2.10  来自于：", ""},
		{"当前 IP：192.0.2.10\n  来自于：中国", ""},
		{"当前 IP：192.0.2.10  来自于：" + strings.Repeat("x", 513), ""},
	} {
		if got := parseAddressResponse(ipipSource, []byte(tc.body), false); got != tc.want {
			t.Fatalf("%q: %s", tc.body, got)
		}
	}
	if parseAddressResponse("https://example.com", []byte("当前 IP：192.0.2.10  来自于：中国"), false) != "" {
		t.Fatal("source-specific parser leaked")
	}
	if parseAddressResponse(mainlandTextSource, []byte("192.0.2.10\n"), false) != "192.0.2.10" {
		t.Fatal("plain endpoint")
	}
	if parseAddressResponse(ipipSource, []byte("当前 IP：192.0.2.10  来自于：中国"), true) != "" {
		t.Fatal("IPv6 policy changed")
	}
}
func TestSourcesDoNotCountDuplicatesOrHTTPFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/failure" {
			w.WriteHeader(503)
		}
		w.Write([]byte("192.0.2.10"))
	}))
	defer srv.Close()
	cases := []struct {
		paths []string
		want  string
	}{
		{[]string{"/a", "/a"}, ""},
		{[]string{"/failure", "/a", "/b"}, "192.0.2.10"},
		{[]string{"/failure", "/a", "/a"}, ""},
	}
	for _, tc := range cases {
		urls := []string{}
		for _, p := range tc.paths {
			urls = append(urls, srv.URL+p)
		}
		if got := observeFamily(context.Background(), srv.Client(), urls, false); got != tc.want {
			t.Fatalf("%v: %s", tc.paths, got)
		}
	}
}
func TestSourceGateNeverReusesAResult(t *testing.T) {
	var g sourceGate
	now := time.Now()
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g.allow(now) {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 || g.allow(now.Add(30*time.Second)) || g.allow(now.Add(-time.Minute)) {
		t.Fatal("gate failed")
	}
	if !g.allow(now.Add(65 * time.Second)) {
		t.Fatal("gate did not reopen")
	}
}

func TestRedundantSourcesCannotHideConflictFromFallback(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cdn-cgi/trace":
			w.Write([]byte(traceText(r.Host, "192.0.2.10")))
		case "/conflict":
			w.Write([]byte("198.51.100.20"))
		case "/failed":
			w.WriteHeader(503)
		default:
			w.Write([]byte("192.0.2.10"))
		}
	}))
	defer srv.Close()
	client := publicAddressClient(false)
	defer client.CloseIdleConnections()
	trustTraceServer(client, srv)
	value, fallback := observeFamilyWithFallback(context.Background(), client, []string{srv.URL + "/a", srv.URL + "/b", srv.URL + "/conflict", srv.URL + "/failed"}, srv.URL, false)
	if value != "" || fallback == nil || fallback.CheckStatus != "conflict" {
		t.Fatalf("conflict disappeared: %q %+v", value, fallback)
	}
	value, fallback = observeFamilyWithFallback(context.Background(), client, []string{srv.URL + "/a", srv.URL + "/b", srv.URL + "/failed"}, srv.URL, false)
	if value != "192.0.2.10" || fallback != nil {
		t.Fatalf("two successful sources failed: %q %+v", value, fallback)
	}
}
