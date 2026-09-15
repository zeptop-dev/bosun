package decoy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func selfSigned(t *testing.T, name string) *tls.Config {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

func freePort(t *testing.T) int {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

func TestBuiltinPageAndProxy(t *testing.T) {
	s := New(nil, slog.Default())
	s.TLSConfig = selfSigned(t, "www.example.com")
	port := freePort(t)
	s.Configure(context.Background(), &spec.Decoy{Domain: "www.example.com", Port: port})
	defer s.Stop()
	client := &http.Client{Transport: &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "www.example.com"}}} //nolint:gosec
	resp, err := client.Get("https://127.0.0.1:" + strconv.Itoa(port) + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "www.example.com") || strings.Contains(strings.ToLower(string(body)), "bosun") {
		t.Fatalf("page: %d %s", resp.StatusCode, body)
	}
	if resp.TLS.Version != tls.VersionTLS13 || resp.TLS.NegotiatedProtocol != "h2" {
		t.Fatalf("tls %x alpn %q", resp.TLS.Version, resp.TLS.NegotiatedProtocol)
	}
	if st := s.Status(); st == nil || !st.Running || st.Port != port {
		t.Fatalf("status %+v", st)
	}

	// Switch to a reverse proxy: same listener port, new handler.
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("upstream " + r.Host)) }))
	defer up.Close()
	s.Configure(context.Background(), &spec.Decoy{Domain: "www.example.com", Port: port, Upstream: up.URL})
	resp, err = client.Get("https://127.0.0.1:" + strconv.Itoa(port) + "/x")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.HasPrefix(string(body), "upstream ") {
		t.Fatalf("proxy: %s", body)
	}
	s.Configure(context.Background(), nil)
	if s.Status() != nil {
		t.Fatal("still configured after nil")
	}
}
