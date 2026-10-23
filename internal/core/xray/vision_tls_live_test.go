package xray

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
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

type visionSwitchEvidence struct {
	tls13, direct atomic.Bool
}

func (e *visionSwitchEvidence) Write(line []byte) (int, error) {
	if bytes.Contains(line, []byte("XtlsFilterTls found tls 1.3!")) {
		e.tls13.Store(true)
	}
	if bytes.Contains(line, []byte("Xtls Unpadding new block")) && bytes.Contains(line, []byte("command 2")) {
		e.direct.Store(true)
	}
	return len(line), nil
}

// REALITY uses a separate TLS library. This fixture deliberately uses the
// server's ordinary crypto/tls connection, then sends TLS 1.3 through Vision
// until its direct-copy command exercises the reflected input/rawInput fields.
func TestVisionTLSMihomoHTTPSLive(t *testing.T) {
	xrayBinary, mihomoBinary := os.Getenv("BOSUN_XRAY_TEST_BINARY"), os.Getenv("BOSUN_MIHOMO_TEST_BINARY")
	if xrayBinary == "" || mihomoBinary == "" {
		t.Skip("set BOSUN_XRAY_TEST_BINARY and BOSUN_MIHOMO_TEST_BINARY")
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
	payload := bytes.Repeat([]byte("vision-tls-https-fixture\n"), 32768)
	var accepted atomic.Int64
	destination := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, int64(len(payload)+1)))
		if err != nil || !bytes.Equal(body, payload) {
			http.Error(w, "unexpected payload", http.StatusBadRequest)
			return
		}
		accepted.Add(1)
		_, _ = w.Write(payload)
	}))
	destination.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	destination.StartTLS()
	defer destination.Close()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	certificate := destination.TLS.Certificates[0]
	var certPEM []byte
	for _, cert := range certificate.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	ib := spec.Inbound{Tag: "vision", Protocol: spec.VLESS, Listen: "127.0.0.1", Port: free(), Flow: "xtls-rprx-vision", NoSniff: true,
		TLS: &spec.TLS{Mode: spec.TLSStandard, CertPath: certPath, KeyPath: keyPath}}
	user := spec.User{ID: 1, Name: "fixture", UUID: "00000000-0000-4000-8000-000000000001"}
	var evidence visionSwitchEvidence
	server, err := New(Options{Binary: xrayBinary, WorkDir: filepath.Join(dir, "server"), LogLevel: "debug", APIListen: net.JoinHostPort("127.0.0.1", strconv.Itoa(free()))}, slog.New(slog.NewTextHandler(&evidence, &slog.HandlerOptions{Level: slog.LevelDebug})))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Stop(context.Background())
	bundle, err := server.Render(&spec.Node{AllowPrivateDest: true}, []spec.Inbound{ib}, []spec.User{user})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(ctx, bundle); err != nil {
		t.Fatal(err)
	}
	mixed, clientDir := free(), t.TempDir()
	config := m{"mixed-port": mixed, "bind-address": "127.0.0.1", "mode": "rule", "log-level": "silent", "ipv6": false,
		"proxies": []m{{"name": "fixture", "type": "vless", "server": "127.0.0.1", "port": ib.Port,
			"uuid": user.UUID, "network": "tcp", "tls": true, "flow": "xtls-rprx-vision", "servername": "example.com", "client-fingerprint": "chrome",
			"skip-cert-verify": true}}, // only the local, generated fixture certificate
		"rules": []string{"MATCH,fixture"}}
	data, _ := json.Marshal(config)
	configFile := filepath.Join(clientDir, "config.json")
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
	for _, port := range []int{ib.Port, mixed} {
		for {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				break
			}
			if time.Now().After(readyBy) {
				t.Fatal("fixture listener did not start")
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	proxyURL, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(mixed))
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}} // local fixture only
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	// New connections exercise the switch repeatedly, including a second
	// connection after an incompatible core might have crashed/restarted.
	for range 2 {
		response, err := httpClient.Post(destination.URL, "application/octet-stream", bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("ordinary TLS + Vision HTTPS request failed: %v", err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK || !bytes.Equal(body, payload) {
			t.Fatal("ordinary TLS + Vision corrupted the HTTPS payload")
		}
	}
	if accepted.Load() != 2 || !server.Running() {
		t.Fatal("ordinary TLS + Vision did not retain a working server")
	}
	if !evidence.tls13.Load() || !evidence.direct.Load() {
		t.Fatal("HTTPS traffic did not exercise the Vision TLS 1.3 direct-copy switch")
	}
}
