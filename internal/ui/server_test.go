package ui

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

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

	// The subscription needs no login.
	anon := &client{t: t, srv: srv, http: &http.Client{}}
	code, b = anon.do("GET", "/sub/"+u.SubToken, nil)
	dec, _ := base64.StdEncoding.DecodeString(string(b))
	if code != 200 || !strings.HasPrefix(string(dec), "vless://") {
		t.Fatalf("subscription: %d %s", code, b)
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
