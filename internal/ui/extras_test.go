package ui

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/local"
)

func selfSignedPEM(t *testing.T, names ...string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	kb, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
}

func TestParityAPI(t *testing.T) {
	store, pw, err := local.Open(filepath.Join(t.TempDir(), "local.json"), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	// admin set: the installer's way to seed the login before first start.
	if err := store.SetAdmin("boss", "correct-horse"); err != nil || !store.Login("boss", "correct-horse") || store.Login("admin", pw) {
		t.Fatalf("admin set: %v", err)
	}
	s := New(Deps{Store: store, Version: "test", Log: slog.Default()})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, srv: srv, http: &http.Client{Jar: jar}}
	if code, _ := c.do("POST", "/api/login", map[string]string{"Username": "boss", "Password": "correct-horse"}); code != 200 {
		t.Fatal("login")
	}

	// Ingress with PascalCase keys (the form) and snake_case (round-trip).
	code, b := c.do("POST", "/api/ingresses", map[string]any{"Name": "IPLC", "BindIP": "10.10.0.2", "LineIP": "198.51.100.20", "EntryHost": "203.0.113.30", "EntryDomain": "iplc.example.com", "PortFrom": 17701, "PortTo": 17799})
	var g local.Ingress
	_ = json.Unmarshal(b, &g)
	if code != 200 || g.ID == "" || g.EntryDomain != "iplc.example.com" {
		t.Fatalf("create ingress: %d %s", code, b)
	}
	if code, _ := c.do("PUT", "/api/ingresses/"+g.ID, map[string]any{"name": "IPLC", "bind_ip": "10.10.0.2", "line_ip": "198.51.100.20", "entry_host": "203.0.113.30", "entry_domain": "iplc.example.com", "port_from": 17701, "port_to": 17799, "port_offset": 1000}); code != 200 {
		t.Fatal("update ingress with snake_case keys")
	}
	if code, b := c.do("POST", "/api/inbounds", map[string]any{"tag": "m", "protocol": "mieru", "port": 17800, "enabled": true, "ingress_id": g.ID, "mieru_transport": "TCP"}); code != 400 || !strings.Contains(string(b), "range") {
		t.Fatalf("port outside range: %d %s", code, b)
	}
	if code, b := c.do("POST", "/api/inbounds", map[string]any{"tag": "m", "protocol": "mieru", "port": 17710, "enabled": true, "ingress_id": g.ID, "mieru_transport": "TCP"}); code != 200 {
		t.Fatalf("create line inbound: %d %s", code, b)
	}
	if _, b := c.do("GET", "/api/inbounds", nil); !strings.Contains(string(b), `"ingress_id":"`+g.ID+`"`) {
		t.Fatalf("ingress_id round-trip: %s", b)
	}
	code, b = c.do("POST", "/api/users", map[string]any{"name": "alice", "enabled": true})
	var u local.User
	_ = json.Unmarshal(b, &u)
	if code != 200 {
		t.Fatalf("user: %s", b)
	}
	// Share links advertise the entry domain on the mapped port.
	_, b = c.do("GET", "/api/users/1/links", nil)
	if !strings.Contains(string(b), "@iplc.example.com?port=18710") {
		t.Fatalf("links via ingress: %s", b)
	}
	anon := &client{t: t, srv: srv, http: &http.Client{}}
	_, b = anon.do("GET", "/sub/"+u.SubToken, nil)
	dec, _ := base64.StdEncoding.DecodeString(string(b))
	if !strings.Contains(string(dec), "iplc.example.com?port=18710") {
		t.Fatalf("sub via ingress: %s", dec)
	}

	// Routing: parse a share link, save with validation.
	code, b = c.do("POST", "/api/routing/parse", map[string]string{"text": "vless://11111111-1111-1111-1111-111111111111@exit.test:443?security=reality&pbk=PUB&sid=ab&sni=www.apple.com&type=tcp#exit\ngarbage://"})
	var parsed struct {
		Nodes []struct {
			Name     string          `json:"name"`
			Protocol string          `json:"protocol"`
			Remote   json.RawMessage `json:"remote"`
		} `json:"nodes"`
		Skipped int `json:"skipped"`
	}
	_ = json.Unmarshal(b, &parsed)
	if code != 200 || len(parsed.Nodes) != 1 || parsed.Skipped != 1 || parsed.Nodes[0].Protocol != "vless" {
		t.Fatalf("parse: %d %s", code, b)
	}
	if code, _ := c.do("PUT", "/api/routing", map[string]any{"outbounds": []map[string]any{{"tag": "exit", "remote": parsed.Nodes[0].Remote}}, "routes": []map[string]any{{"match": []string{"inbound:m"}, "action": "outbound", "value": "nope"}}}); code != 400 {
		t.Fatal("rule to unknown outbound accepted")
	}
	if code, b := c.do("PUT", "/api/routing", map[string]any{"outbounds": []map[string]any{{"tag": "exit", "remote": parsed.Nodes[0].Remote}}, "routes": []map[string]any{{"match": []string{"inbound:m"}, "action": "outbound", "value": "exit"}}, "default_outbound": ""}); code != 200 {
		t.Fatalf("routing: %d %s", code, b)
	}
	if _, b := c.do("GET", "/api/routing", nil); !strings.Contains(string(b), `"host":"exit.test"`) {
		t.Fatalf("routing get: %s", b)
	}

	// Certificates: the view never carries PEM.
	cert, key := selfSignedPEM(t, "jp1.example.com")
	if code, _ := c.do("POST", "/api/certificates", map[string]string{"cert_pem": cert, "key_pem": "nope"}); code != 400 {
		t.Fatal("bad pair accepted")
	}
	code, b = c.do("POST", "/api/certificates", map[string]string{"cert_pem": cert, "key_pem": key})
	if code != 200 || !strings.Contains(string(b), `"domain":"jp1.example.com"`) || strings.Contains(string(b), "BEGIN") {
		t.Fatalf("upload: %d %s", code, b)
	}
	if _, b := c.do("GET", "/api/certificates", nil); !strings.Contains(string(b), `"issuer":"jp1.example.com"`) || strings.Contains(string(b), "PRIVATE") {
		t.Fatalf("list: %s", b)
	}
	if code, _ := c.do("DELETE", "/api/certificates/jp1.example.com", nil); code != 200 {
		t.Fatal("delete cert")
	}

	// Probe settings and the read shape.
	if code, _ := c.do("PUT", "/api/probe", map[string]any{"enabled": true, "carrier_ping": true, "carriers": []map[string]string{{"name": "HK", "addr": "hkix"}}}); code != 400 {
		t.Fatal("bad carrier accepted")
	}
	if code, b := c.do("PUT", "/api/probe", map[string]any{"enabled": true, "carrier_ping": true, "tasks": []map[string]any{{"name": "cf", "type": "tcp", "target": "1.1.1.1:443", "interval_seconds": 30}}}); code != 200 {
		t.Fatalf("probe: %d %s", code, b)
	}
	_, b = c.do("GET", "/api/probe", nil)
	if !strings.Contains(string(b), `"results":[]`) || !strings.Contains(string(b), `"defaults":[{"name":"CT"`) || !strings.Contains(string(b), `"name":"cf"`) {
		t.Fatalf("probe get: %s", b)
	}
	if _, b := c.do("GET", "/api/status", nil); !strings.Contains(string(b), `"pings":[]`) {
		t.Fatalf("status pings: %s", b)
	}
	// Deleting the ingress detaches the inbound; links fall back to the host.
	if code, _ := c.do("DELETE", "/api/ingresses/"+g.ID, nil); code != 200 {
		t.Fatal("delete ingress")
	}
	if _, b := c.do("GET", "/api/users/1/links", nil); strings.Contains(string(b), "iplc.example.com") {
		t.Fatalf("links after delete: %s", b)
	}
}
