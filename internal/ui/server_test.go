package ui

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/zeptop-dev/bosun/internal/authutil"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/local"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

type client struct {
	t    *testing.T
	srv  *httptest.Server
	http *http.Client
}

func (c *client) do(method, path string, body any) (int, []byte) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func TestAPI(t *testing.T) {
	store, pw, err := local.Open(filepath.Join(t.TempDir(), "local.json"), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	adopted := ""
	s := New(Deps{Store: store, Version: "test", Log: slog.Default(),
		Adopt: func(ctx context.Context, url, code string) error {
			if code != "GOOD-CODE" {
				return io.ErrUnexpectedEOF
			}
			adopted = url
			return store.Adopt(url)
		},
		Detach: func(ctx context.Context, keep bool) error { return store.Detach(nil) },
	})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, srv: srv, http: &http.Client{Jar: jar}}

	if code, _ := c.do("GET", "/api/status", nil); code != 401 {
		t.Fatalf("unauthenticated status: %d", code)
	}
	if code, _ := c.do("POST", "/api/login", map[string]string{"Username": "admin", "Password": "wrong"}); code != 401 {
		t.Fatalf("bad login: %d", code)
	}
	if code, b := c.do("POST", "/api/login", map[string]string{"Username": "admin", "Password": pw}); code != 200 {
		t.Fatalf("login: %d %s", code, b)
	}

	code, b := c.do("POST", "/api/keys/reality", nil)
	var keys map[string]string
	_ = json.Unmarshal(b, &keys)
	if code != 200 || len(keys["private_key"]) != 43 || len(keys["public_key"]) != 43 {
		t.Fatalf("reality keys: %d %s", code, b)
	}

	ib := map[string]any{"tag": "reality", "protocol": "vless", "port": 443, "flow": "xtls-rprx-vision", "enabled": true,
		"tls": map[string]any{"mode": 2, "server_name": "www.apple.com", "reality": map[string]any{"private_key": keys["private_key"], "public_key": keys["public_key"], "short_ids": []string{"0123abcd"}, "handshake_server": "www.apple.com", "handshake_port": 443}}}
	if code, b := c.do("POST", "/api/inbounds", ib); code != 200 {
		t.Fatalf("create inbound: %d %s", code, b)
	}
	if code, b := c.do("POST", "/api/inbounds", map[string]any{"tag": "dup", "protocol": "vless", "port": 443, "enabled": true}); code != 400 || !strings.Contains(string(b), "port 443") {
		t.Fatalf("port clash: %d %s", code, b)
	}
	code, b = c.do("POST", "/api/users", map[string]any{"name": "alice", "enabled": true})
	var u local.User
	_ = json.Unmarshal(b, &u)
	if code != 200 || u.ID == 0 || u.UUID == "" || u.SubToken == "" {
		t.Fatalf("create user: %d %s", code, b)
	}

	code, b = c.do("GET", "/api/users/1/links", nil)
	var links struct {
		Links  []Link `json:"links"`
		SubURL string `json:"sub_url"`
	}
	_ = json.Unmarshal(b, &links)
	if code != 200 || len(links.Links) != 1 || !strings.HasPrefix(links.Links[0].URI, "vless://"+u.UUID+"@127.0.0.1:443?") || !strings.Contains(links.Links[0].URI, "security=reality") {
		t.Fatalf("links: %d %s", code, b)
	}
	if !strings.Contains(links.SubURL, "/sub/"+u.SubToken) {
		t.Fatalf("sub url: %s", links.SubURL)
	}

	// The subscription needs no login; the format follows the client:
	// a base64 URI list by default, Clash YAML for mihomo-family agents.
	anon := &client{t: t, srv: srv, http: &http.Client{}}
	code, b = anon.do("GET", "/sub/"+u.SubToken, nil)
	dec, _ := base64.StdEncoding.DecodeString(string(b))
	if code != 200 || !strings.HasPrefix(string(dec), "vless://") {
		t.Fatalf("subscription: %d %s", code, b)
	}
	code, b = anon.do("GET", "/sub/"+u.SubToken+"?client=clash", nil)
	if code != 200 || !strings.Contains(string(b), "proxies:") || !strings.Contains(string(b), "type: vless") {
		t.Fatalf("clash subscription: %d %s", code, b)
	}
	if code, _ := anon.do("GET", "/sub/nope", nil); code != 404 {
		t.Fatal("unknown token should 404")
	}

	// Takeover: a bad code fails without changing anything; a good one
	// makes the node read-only.
	if code, _ := c.do("POST", "/api/mode/adopt", map[string]string{"url": "http://captain.test", "pair_code": "BAD"}); code != 502 {
		t.Fatalf("bad pair code: %d", code)
	}
	if code, b := c.do("POST", "/api/mode/adopt", map[string]string{"url": "http://captain.test/", "pair_code": "GOOD-CODE"}); code != 200 || adopted != "http://captain.test" {
		t.Fatalf("adopt: %d %s %q", code, b, adopted)
	}
	if code, _ := c.do("POST", "/api/users", map[string]any{"name": "bob", "enabled": true}); code != 409 {
		t.Fatalf("managed mode must reject edits: %d", code)
	}
	code, b = c.do("GET", "/api/status", nil)
	var st map[string]any
	_ = json.Unmarshal(b, &st)
	if code != 200 || st["mode"] != "managed" || st["has_snapshot"] != true {
		t.Fatalf("status: %d %s", code, b)
	}
	if code, _ := c.do("POST", "/api/mode/detach", map[string]bool{"keep": false}); code != 200 {
		t.Fatal("detach")
	}
	if code, b := c.do("GET", "/api/inbounds", nil); code != 200 || !strings.Contains(string(b), `"tag":"reality"`) {
		t.Fatalf("snapshot restored: %d %s", code, b)
	}
	_ = agentproto.State{}
}

// A panel restart (upgrade, rollback, restart button) must not sign the
// operator out: sessions live next to the state file.
func TestSessionsSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "local.json")
	store, pw, err := local.Open(path, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	first := httptest.NewServer(New(Deps{Store: store, Version: "a", Log: slog.Default()}).Handler())
	c := &client{t: t, srv: first, http: &http.Client{Jar: jar}}
	if code, b := c.do("POST", "/api/login", map[string]string{"Username": "admin", "Password": pw}); code != 200 {
		t.Fatalf("login: %d %s", code, b)
	}
	first.Close()

	// New process: fresh Server on the same state path, same cookie jar
	// (the jar keys on host:port, so reuse the listener address).
	second := httptest.NewUnstartedServer(New(Deps{Store: store, Version: "b", Log: slog.Default()}).Handler())
	second.Listener.Close()
	second.Listener = mustListen(t, first.Listener.Addr().String())
	second.Start()
	defer second.Close()
	c.srv = second
	if code, b := c.do("GET", "/api/me", nil); code != 200 {
		t.Fatalf("session lost across restart: %d %s", code, b)
	}
	if code, _ := c.do("POST", "/api/logout", nil); code != 200 {
		t.Fatal("logout")
	}
	if code, _ := c.do("GET", "/api/me", nil); code != 401 {
		t.Fatalf("session survived logout: %d", code)
	}
}

func mustListen(t *testing.T, addr string) net.Listener {
	t.Helper()
	for i := 0; i < 20; i++ {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			return ln
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("cannot rebind %s", addr)
	return nil
}

// The REALITY scan endpoint probes from the node; a closed local port must
// come back as one unusable row rather than an error.
func TestRealityScanEndpoint(t *testing.T) {
	store, pw, err := local.Open(filepath.Join(t.TempDir(), "local.json"), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Deps{Store: store, Version: "test", Log: slog.Default()}).Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, srv: srv, http: &http.Client{Jar: jar}}
	if code, _ := c.do("POST", "/api/login", map[string]string{"Username": "admin", "Password": pw}); code != 200 {
		t.Fatal("login")
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	code, body := c.do("POST", "/api/reality/scan", map[string]any{"hosts": []string{addr}})
	if code != 200 {
		t.Fatalf("scan: %d %s", code, body)
	}
	var out []map[string]any
	if err := json.Unmarshal(body, &out); err != nil || len(out) != 1 || out[0]["feasible"] != false {
		t.Fatalf("unexpected %s", body)
	}
}

// Second factor and API tokens on the standalone panel.
func TestTOTPAndAPITokens(t *testing.T) {
	store, pw, err := local.Open(filepath.Join(t.TempDir(), "local.json"), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Deps{Store: store, Version: "test", Log: slog.Default()}).Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, srv: srv, http: &http.Client{Jar: jar}}
	if code, _ := c.do("POST", "/api/login", map[string]string{"Username": "admin", "Password": pw}); code != 200 {
		t.Fatal("login")
	}
	code, body := c.do("POST", "/api/2fa/setup", nil)
	var setup struct{ Secret, URI string }
	if code != 200 || json.Unmarshal(body, &setup) != nil || setup.Secret == "" {
		t.Fatalf("setup: %d %s", code, body)
	}
	if code, _ := c.do("POST", "/api/2fa/enable", map[string]string{"Code": "000000"}); code != 400 {
		t.Fatalf("wrong code accepted: %d", code)
	}
	if code, _ := c.do("POST", "/api/2fa/enable", map[string]string{"Code": authutil.TOTPCode(setup.Secret, time.Now())}); code != 200 {
		t.Fatalf("enable: %d", code)
	}
	// A new session now needs the code.
	jar2, _ := cookiejar.New(nil)
	c2 := &client{t: t, srv: srv, http: &http.Client{Jar: jar2}}
	if code, _ := c2.do("POST", "/api/login", map[string]string{"Username": "admin", "Password": pw}); code != 428 {
		t.Fatalf("login without code: %d", code)
	}
	if code, _ := c2.do("POST", "/api/login", map[string]string{"Username": "admin", "Password": pw, "Code": authutil.TOTPCode(setup.Secret, time.Now())}); code != 200 {
		t.Fatalf("login with code: %d", code)
	}
	// API token: created once, usable as a bearer, revoked.
	code, body = c.do("POST", "/api/tokens", map[string]string{"Name": "script"})
	var tok struct {
		ID    int64
		Token string
	}
	if code != 200 || json.Unmarshal(body, &tok) != nil || !strings.HasPrefix(tok.Token, "bsn_") {
		t.Fatalf("create token: %d %s", code, body)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("bearer: %v %v", err, resp)
	}
	resp.Body.Close()
	if code, _ := c.do("DELETE", "/api/tokens/"+strconv.FormatInt(tok.ID, 10), nil); code != 200 {
		t.Fatal("revoke")
	}
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 401 {
		t.Fatalf("revoked token still works: %d", resp.StatusCode)
	}
	resp.Body.Close()
}
