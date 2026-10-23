package xray

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Check the final dial address, not merely the earlier routing match: a public
// test destination is explicitly redirected to a local fixture. No privileged
// firewall or host-network modifications are needed for this regression.
func TestFreedomFinalRulesLiveXray(t *testing.T) {
	binary := os.Getenv("BOSUN_XRAY_WG_TEST_BINARY")
	if binary == "" {
		t.Skip("set BOSUN_XRAY_WG_TEST_BINARY to Xray >= 26.6.27")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	free := func() int {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.Addr().(*net.TCPAddr).Port
	}
	server, err := New(Options{Binary: binary, WorkDir: t.TempDir(), APIListen: net.JoinHostPort("127.0.0.1", strconv.Itoa(free()))}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if !server.Capabilities().WireGuardDevices {
		t.Fatal("test needs a core with modern finalRules support")
	}
	t.Cleanup(func() { _ = server.Stop(context.Background()) })
	var hits atomic.Int64
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "fixture")
	}))
	defer destination.Close()
	port := free()
	node := &spec.Node{
		Inbounds:        []spec.Inbound{{Tag: "http", Protocol: spec.HTTP, Listen: "127.0.0.1", Port: port, NoSniff: true}},
		DefaultOutbound: "fixture", Outbounds: []spec.Outbound{{Tag: "fixture", Protocol: "freedom", Settings: map[string]any{"redirect": strings.TrimPrefix(destination.URL, "http://")}}},
	}
	apply := func() {
		t.Helper()
		bundle, err := server.Render(node, node.Inbounds, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := server.Apply(ctx, bundle); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := server.Stats(ctx, false); err == nil {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("test core API did not become ready")
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	proxyURL, _ := url.Parse("http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	request := func() bool {
		response, err := client.Get("http://192.0.0.9/") // globally reachable anycast in spec.PrivateRanges
		if err != nil {
			return false
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return string(body) == "fixture"
	}
	apply()
	if request() || hits.Load() != 0 {
		t.Fatal("public routing target bypassed the final private-address denial")
	}
	node.PrivateDestAllow = []string{"127.0.0.1/32"}
	apply()
	if !request() || hits.Load() != 1 {
		t.Fatal("explicit private destination exception was ignored")
	}
	node.PrivateDestAllow = nil
	apply()
	if request() || hits.Load() != 1 {
		t.Fatal("revoked private destination exception remained effective")
	}
	node.AllowPrivateDest = true
	apply()
	if !request() || hits.Load() != 2 {
		t.Fatal("explicit global private destination exemption was ignored")
	}
}
