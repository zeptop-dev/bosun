package xray

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// This uses an actual Mihomo REALITY handshake, not Xray as both endpoints:
// Xray's own new client clears the default version floor and hides the bug.
// Every listener and destination is loopback; no operator credentials or
// public disguise service are needed.
func TestRealityMihomoClientVersionLive(t *testing.T) {
	xrayBinary, mihomoBinary := os.Getenv("BOSUN_XRAY_TEST_BINARY"), os.Getenv("BOSUN_MIHOMO_TEST_BINARY")
	if xrayBinary == "" || mihomoBinary == "" {
		t.Skip("set BOSUN_XRAY_TEST_BINARY (26.7.11+) and BOSUN_MIHOMO_TEST_BINARY")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	free := func() int {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.Addr().(*net.TCPAddr).Port
	}
	disguise := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	disguise.Config.ErrorLog = log.New(io.Discard, "", 0)
	disguise.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
	disguise.StartTLS()
	defer disguise.Close()
	var hits atomic.Int64
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "reality-compatible")
	}))
	defer destination.Close()

	ib := spec.Inbound{Tag: "reality", Protocol: spec.VLESS, Listen: "127.0.0.1", Port: free(), Flow: "xtls-rprx-vision", NoSniff: true,
		TLS: &spec.TLS{Mode: spec.TLSReality, ServerName: "example.com", Reality: &spec.Reality{
			HandshakeServer: "127.0.0.1", HandshakePort: disguise.Listener.Addr().(*net.TCPAddr).Port,
		}}}
	spec.FillInboundSecrets(&ib)
	user := spec.User{ID: 1, Name: "fixture", UUID: "00000000-0000-4000-8000-000000000001"}
	server, err := New(Options{Binary: xrayBinary, WorkDir: t.TempDir(), APIListen: net.JoinHostPort("127.0.0.1", strconv.Itoa(free()))}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Stop(context.Background())
	if !server.strictOutboundSecurity {
		t.Fatal("test requires Xray 26.7.11 or later to exercise its default version floor")
	}

	mixed := free()
	clientConfig := m{
		"mixed-port": mixed, "bind-address": "127.0.0.1", "mode": "rule", "log-level": "silent", "ipv6": false,
		"proxies": []m{{"name": "fixture", "type": "vless", "server": "127.0.0.1", "port": ib.Port,
			"uuid": user.UUID, "network": "tcp", "tls": true, "flow": "xtls-rprx-vision", "servername": "example.com", "client-fingerprint": "chrome",
			"reality-opts": m{"public-key": ib.TLS.Reality.PublicKey, "short-id": ib.TLS.Reality.ShortIDs[0]}}},
		"rules": []string{"MATCH,fixture"},
	}
	clientDir := t.TempDir()
	configFile := filepath.Join(clientDir, "config.json")
	data, _ := json.Marshal(clientConfig)
	if err := os.WriteFile(configFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	client := exec.CommandContext(ctx, mihomoBinary, "-d", clientDir, "-f", configFile)
	client.Stdout, client.Stderr = io.Discard, io.Discard
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Process.Kill(); _ = client.Wait() }()
	readyBy := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(mixed)), 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(readyBy) {
			t.Fatal("Mihomo listener did not start")
		}
		time.Sleep(25 * time.Millisecond)
	}
	proxyURL, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(mixed))
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	request := func() bool {
		response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get(destination.URL)
		if err != nil {
			return false
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		return err == nil && string(body) == "reality-compatible"
	}
	for _, test := range []struct {
		name  string
		floor *string
		works bool
	}{
		{name: "upstream omitted default rejects Mihomo"},
		{name: "rendered compatibility default admits Mihomo", floor: stringPtr("0.0.0"), works: true},
		{name: "explicit modern policy still rejects Mihomo", floor: stringPtr("26.3.27")},
	} {
		t.Run(test.name, func(t *testing.T) {
			bundle, err := server.Render(&spec.Node{AllowPrivateDest: true}, []spec.Inbound{ib}, []spec.User{user})
			if err != nil {
				t.Fatal(err)
			}
			cfg := decode(t, bundle.Files[bundle.Main])
			reality := configObjects(cfg["inbounds"])[0]["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
			if test.floor == nil {
				delete(reality, "minClientVer")
			} else if *test.floor != "0.0.0" {
				reality["minClientVer"] = *test.floor
			} // the success case uses the renderer output without changing it
			bundle.Files[bundle.Main], _ = json.Marshal(cfg)
			if err := server.Start(ctx, bundle); err != nil {
				t.Fatal(err)
			}
			defer server.Stop(context.Background())
			deadline := time.Now().Add(5 * time.Second)
			for {
				conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(ib.Port)), 100*time.Millisecond)
				if err == nil {
					_ = conn.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("Xray listener did not start")
				}
				time.Sleep(25 * time.Millisecond)
			}
			before := hits.Load()
			if test.works {
				for !request() {
					if time.Now().After(deadline) {
						t.Fatal("Mihomo could not authenticate with the compatibility default")
					}
					time.Sleep(50 * time.Millisecond)
				}
			} else {
				for range 2 {
					if request() {
						t.Fatal("Mihomo bypassed the restrictive client-version floor")
					}
				}
				if hits.Load() != before {
					t.Fatal("rejected client reached the destination")
				}
			}
		})
	}
}

func stringPtr(value string) *string { return &value }
