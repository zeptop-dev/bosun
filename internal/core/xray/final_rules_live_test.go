package xray

import (
	"context"
	"encoding/json"
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

	"github.com/zeptop-dev/bosun/internal/core/grpcraw"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protowire"
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
	// Advanced overrides use the same case-insensitive struct fields as the
	// upstream JSON loader. An explicit restrictive policy must survive them.
	patch, _ := json.Marshal(m{"outbounds": []m{{"Protocol": "Freedom", "Tag": "fixture", "Settings": m{
		"redirect": strings.TrimPrefix(destination.URL, "http://"), "FinalRules": []m{{"action": "block", "blockDelay": 0}},
	}}}})
	node.Overrides = map[string]json.RawMessage{"xray": patch}
	apply()
	if request() || hits.Load() != 2 {
		t.Fatal("case-insensitive override fields lost the explicit blocking policy")
	}
}

func TestFreedomFinalRulesPrivateDNSLiveXray(t *testing.T) {
	binary := os.Getenv("BOSUN_XRAY_WG_TEST_BINARY")
	if binary == "" {
		t.Skip("set BOSUN_XRAY_WG_TEST_BINARY to Xray >= 26.6.27")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dns, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var queries atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 4096)
		for {
			n, peer, err := dns.ReadFrom(buffer)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buffer[:n]) != nil {
				continue
			}
			queries.Add(1)
			reply := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionAvailable: true}, Questions: query.Questions}
			for _, q := range query.Questions {
				if q.Type == dnsmessage.TypeA {
					reply.Answers = append(reply.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 0, 9}}})
				}
			}
			if data, err := reply.Pack(); err == nil {
				_, _ = dns.WriteTo(data, peer)
			}
		}
	}()
	t.Cleanup(func() { _ = dns.Close(); <-done })
	free := func() int {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.Addr().(*net.TCPAddr).Port
	}
	api := net.JoinHostPort("127.0.0.1", strconv.Itoa(free()))
	server, err := New(Options{Binary: binary, WorkDir: t.TempDir(), APIListen: api}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Stop(context.Background()) })
	node := &spec.Node{DNS: []string{"127.0.0.1"}, Inbounds: []spec.Inbound{{Tag: "user", Protocol: spec.VLESS, Listen: "127.0.0.1", Port: free(), PrivateAccess: &spec.PrivateAccess{Mode: "internal"}}}, Routes: []spec.RouteRule{{Match: []string{"ip:192.0.0.9/32"}, Action: "direct"}}}
	bundle, err := server.Render(node, node.Inbounds, nil)
	if err != nil {
		t.Fatal(err)
	}
	var cfg m
	if err := json.Unmarshal(bundle.Files[bundle.Main], &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["api"].(map[string]any)["services"] = []string{"RoutingService", "StatsService"}
	cfg["dns"].(map[string]any)["servers"] = []m{{"address": "127.0.0.1", "port": dns.LocalAddr().(*net.UDPAddr).Port}}
	bundle.Files[bundle.Main], _ = json.Marshal(cfg)
	if err := server.Start(ctx, bundle); err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient(api, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDefaultCallOptions(grpc.WaitForReady(true)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for target, want := range map[string]string{"fixture.example.com": "direct", "127.0.0.1": "block"} {
		response, err := grpcraw.Invoke(ctx, conn, "/xray.app.router.command.RoutingService/TestRoute", wireGuardTestRouteRequest("user", "user|user", target))
		if err != nil {
			t.Fatal(err)
		}
		var outbound string
		for len(response) > 0 {
			field, kind, n := protowire.ConsumeTag(response)
			if n < 0 {
				t.Fatal("invalid routing response")
			}
			response = response[n:]
			if field == 12 && kind == protowire.BytesType {
				outbound, _ = protowire.ConsumeString(response)
				break
			}
			n = protowire.ConsumeFieldValue(field, kind, response)
			if n < 0 {
				t.Fatal("invalid routing response")
			}
			response = response[n:]
		}
		if outbound != want {
			t.Fatalf("target %s routed to %s, want %s", target, outbound, want)
		}
	}
	if queries.Load() == 0 {
		t.Fatal("core-private DNS request did not reach its configured resolver")
	}
}
