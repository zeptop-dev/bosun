package hysteria

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

var users = []spec.User{
	{ID: 1, Name: "u1", UUID: "uuid-1", Password: "pw-1"},
	{ID: 2, Name: "u2", UUID: "uuid-2", Password: "pw-2"},
}

func inbound() spec.Inbound {
	return spec.Inbound{Tag: "hy", Protocol: spec.Hysteria2, Port: 8443, UpMbps: 100, DownMbps: 500,
		Obfs: "salamander", ObfsPassword: "obfs",
		TLS: &spec.TLS{Mode: spec.TLSStandard, ServerName: "a", CertPath: "/c", KeyPath: "/k"}}
}

func TestRender(t *testing.T) {
	opt := renderOptions{AuthURL: "http://127.0.0.1:1/auth", StatsListen: "127.0.0.1:2", StatsSecret: "s"}
	out, st, err := render([]spec.Inbound{inbound()}, users, opt)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["listen"] != ":8443" {
		t.Fatalf("listen: %v", cfg["listen"])
	}
	if cfg["auth"].(map[string]any)["http"].(map[string]any)["url"] != opt.AuthURL {
		t.Fatalf("auth: %v", cfg["auth"])
	}
	if cfg["obfs"].(map[string]any)["salamander"].(map[string]any)["password"] != "obfs" {
		t.Fatalf("obfs: %v", cfg["obfs"])
	}
	if cfg["bandwidth"].(map[string]any)["down"] != "500 mbps" {
		t.Fatalf("bandwidth: %v", cfg["bandwidth"])
	}
	if _, has := cfg["users"]; has {
		t.Fatal("users must not be in the server config")
	}
	if st.users["pw-1"].Name != "u1" {
		t.Fatalf("state users: %+v", st.users)
	}
	_, st2, _ := render([]spec.Inbound{inbound()}, users[:1], opt)
	if st.key != st2.key {
		t.Fatal("key must not depend on users")
	}
	ib := inbound()
	ib.Port = 9443
	_, st3, _ := render([]spec.Inbound{ib}, users, opt)
	if st.key == st3.key {
		t.Fatal("key must change with the listener")
	}

	if _, _, err := render([]spec.Inbound{inbound(), inbound()}, users, opt); err == nil {
		t.Fatal("two inbounds must be rejected")
	}
	ib = inbound()
	ib.TLS = nil
	if _, _, err := render([]spec.Inbound{ib}, users, opt); err == nil {
		t.Fatal("missing TLS must be rejected")
	}
}

func TestAuthServer(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	a, err := newAuthServer(addr, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer a.close(context.Background())
	a.setUsers(map[string]spec.User{"pw-1": users[0]})

	post := func(auth string) map[string]any {
		body, _ := json.Marshal(map[string]any{"addr": "1.2.3.4:5", "auth": auth, "tx": 0})
		resp, err := http.Post("http://"+addr+"/auth", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out
	}
	if r := post("pw-1"); r["ok"] != true || r["id"] != "u1" {
		t.Fatalf("valid auth: %v", r)
	}
	if r := post("wrong"); r["ok"] != false {
		t.Fatalf("invalid auth: %v", r)
	}
	if on := a.online(); len(on["u1"]) != 1 || on["u1"][0] != "1.2.3.4" {
		t.Fatalf("online after auth: %v", on)
	}
	a.setUsers(map[string]spec.User{})
	if r := post("pw-1"); r["ok"] != false {
		t.Fatalf("removed user must be rejected: %v", r)
	}
}

func TestStatsClient(t *testing.T) {
	var kicked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "sec" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/traffic":
			if r.URL.Query().Get("clear") != "1" {
				t.Errorf("expected clear=1")
			}
			_, _ = w.Write([]byte(`{"u1":{"tx":10,"rx":20}}`))
		case "/kick":
			_ = json.NewDecoder(r.Body).Decode(&kicked)
			_, _ = w.Write([]byte("OK"))
		case "/online":
			_, _ = w.Write([]byte(`{"u1":1}`))
		}
	}))
	defer srv.Close()
	c := &statsClient{base: srv.URL, secret: "sec", http: srv.Client()}
	tr, err := c.traffic(context.Background(), true)
	if err != nil || tr["u1"] != (spec.Traffic{Up: 10, Down: 20}) {
		t.Fatalf("traffic: %v %v", tr, err)
	}
	if err := c.kick(context.Background(), []string{"u2"}); err != nil || len(kicked) != 1 || kicked[0] != "u2" {
		t.Fatalf("kick: %v %v", kicked, err)
	}
	if on, err := c.online(context.Background()); err != nil || on["u1"] != 1 {
		t.Fatalf("online: %v %v", on, err)
	}
	bad := &statsClient{base: srv.URL, secret: "nope", http: srv.Client()}
	if _, err := bad.traffic(context.Background(), false); err == nil {
		t.Fatal("wrong secret must fail")
	}
}
