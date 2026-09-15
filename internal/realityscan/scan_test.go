package realityscan

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/http"
	"testing"
)

func TestCDNByIP(t *testing.T) {
	if CDNByIP(net.ParseIP("104.16.124.96")) != "cloudflare" {
		t.Fatal("cloudflare range not recognised")
	}
	if CDNByIP(net.ParseIP("198.51.100.20")) != "" {
		t.Fatal("documentation range flagged")
	}
}

func TestCDNByHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "cloudflare")
	if cdnByHeaders(h) != "cloudflare" {
		t.Fatal("server header")
	}
	h = http.Header{}
	h.Set("Via", "1.1 varnish")
	h.Set("X-Served-By", "cache-nrt-1234")
	if cdnByHeaders(h) != "fastly" {
		t.Fatal("fastly headers")
	}
	if cdnByHeaders(http.Header{}) != "" {
		t.Fatal("empty headers")
	}
}

func TestCDNByIssuer(t *testing.T) {
	c := &x509.Certificate{Issuer: pkix.Name{Organization: []string{"Cloudflare, Inc."}, CommonName: "Cloudflare Inc ECC CA-3"}}
	if cdnByIssuer(c) != "cloudflare" {
		t.Fatal("issuer")
	}
}

// A refused connection must come back as a clear reason, not a hang.
func TestProbeConnectFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	r := Probe(context.Background(), addr, Options{SkipHTTP: true})
	if r.Feasible || r.Reason == "" || r.LatencyMs != -1 {
		t.Fatalf("unexpected %+v", r)
	}
}

func TestScanOrdersFeasibleFirst(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	out := Scan(context.Background(), []string{addr, ""}, Options{SkipHTTP: true})
	if len(out) != 2 || out[0].Feasible || out[1].Feasible {
		t.Fatalf("unexpected %+v", out)
	}
}

func TestSameHost(t *testing.T) {
	if !sameHost("/en/", "www.example.com") || !sameHost("https://www.example.com/x", "www.example.com") {
		t.Fatal("same-host redirects must not count")
	}
	if sameHost("https://example.com/", "www.example.com") {
		t.Fatal("apex redirect is another host")
	}
}
