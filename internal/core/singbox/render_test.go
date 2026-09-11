package singbox

import (
	"encoding/json"
	"testing"

	"gitlab.com/boyang-hu/bosun/pkg/spec"
)

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, b)
	}
	return out
}

var users = []spec.User{
	{ID: 1, Name: "u1", UUID: "11111111-1111-1111-1111-111111111111", Password: "11111111-1111-1111-1111-111111111111"},
	{ID: 2, Name: "u2", UUID: "22222222-2222-2222-2222-222222222222", Password: "22222222-2222-2222-2222-222222222222"},
}

func TestRenderVLESSReality(t *testing.T) {
	ib := spec.Inbound{
		Tag: "in", Protocol: spec.VLESS, Port: 443, Flow: "xtls-rprx-vision",
		TLS: &spec.TLS{Mode: spec.TLSReality, ServerName: "www.apple.com", Reality: &spec.Reality{
			PrivateKey: "pk", ShortIDs: []string{"abcd"}, HandshakeServer: "www.apple.com", HandshakePort: 443,
		}},
	}
	node := &spec.Node{Inbounds: []spec.Inbound{ib}}
	b, err := render(node, node.Inbounds, users, renderOptions{LogLevel: "info", StatsListen: "127.0.0.1:9101"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := decode(t, b)
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	if in["type"] != "vless" || in["listen"] != "::" || in["listen_port"] != float64(443) {
		t.Fatalf("bad inbound: %v", in)
	}
	u := in["users"].([]any)[0].(map[string]any)
	if u["flow"] != "xtls-rprx-vision" || u["uuid"] != users[0].UUID {
		t.Fatalf("bad user: %v", u)
	}
	tls := in["tls"].(map[string]any)
	r := tls["reality"].(map[string]any)
	if r["private_key"] != "pk" || tls["server_name"] != "www.apple.com" {
		t.Fatalf("bad reality: %v", tls)
	}
	if _, has := tls["certificate_path"]; has {
		t.Fatal("reality inbound must not carry certificate_path")
	}
	stats := cfg["experimental"].(map[string]any)["v2ray_api"].(map[string]any)["stats"].(map[string]any)
	if len(stats["users"].([]any)) != 2 {
		t.Fatalf("stats users: %v", stats)
	}
	outs := cfg["outbounds"].([]any)
	if len(outs) != 1 || outs[0].(map[string]any)["tag"] != "direct" {
		t.Fatalf("outbounds: %v", outs)
	}
}

func TestRenderHysteria2RequiresTLS(t *testing.T) {
	node := &spec.Node{Inbounds: []spec.Inbound{{Tag: "hy", Protocol: spec.Hysteria2, Port: 8443}}}
	if _, err := render(node, node.Inbounds, users, renderOptions{}); err == nil {
		t.Fatal("expected error without TLS")
	}
	node.Inbounds[0].TLS = &spec.TLS{Mode: spec.TLSStandard, ServerName: "x", CertPath: "/c", KeyPath: "/k"}
	node.Inbounds[0].Obfs, node.Inbounds[0].ObfsPassword = "salamander", "s3cret"
	b, err := render(node, node.Inbounds, users, renderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	in := decode(t, b)["inbounds"].([]any)[0].(map[string]any)
	if in["obfs"].(map[string]any)["password"] != "s3cret" {
		t.Fatalf("obfs: %v", in)
	}
	if in["tls"].(map[string]any)["certificate_path"] != "/c" {
		t.Fatalf("tls: %v", in["tls"])
	}
}

func TestRenderShadowsocks2022(t *testing.T) {
	node := &spec.Node{Inbounds: []spec.Inbound{{
		Tag: "ss", Protocol: spec.Shadowsocks, Port: 8388, Cipher: "2022-blake3-aes-128-gcm", ServerKey: "c2VydmVya2V5c2VydmVya2V5",
	}}}
	b, err := render(node, node.Inbounds, users, renderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	in := decode(t, b)["inbounds"].([]any)[0].(map[string]any)
	if in["password"] != "c2VydmVya2V5c2VydmVya2V5" {
		t.Fatalf("server key: %v", in)
	}
	u := in["users"].([]any)[0].(map[string]any)
	if u["password"] != ss2022UserKey(users[0].UUID, 16) {
		t.Fatalf("user key: %v", u)
	}
	if ss2022UserKey("11111111-1111-1111-1111-111111111111", 16) != "MTExMTExMTEtMTExMS0xMQ==" {
		t.Fatalf("derivation changed: %s", ss2022UserKey("11111111-1111-1111-1111-111111111111", 16))
	}
}

func TestRenderOutboundChainAndRoutes(t *testing.T) {
	node := &spec.Node{
		Inbounds: []spec.Inbound{{Tag: "in", Protocol: spec.Trojan, Port: 443, TLS: &spec.TLS{Mode: spec.TLSStandard, ServerName: "a", CertPath: "/c", KeyPath: "/k"}}},
		Outbounds: []spec.Outbound{
			{Tag: "warp", Protocol: "wireguard", Settings: map[string]any{"private_key": "x"}},
			{Tag: "landing", Protocol: "socks", Settings: map[string]any{"server": "1.2.3.4", "server_port": 1080}, ProxyTag: "warp"},
		},
		Routes: []spec.RouteRule{
			{Match: []string{"protocol:bittorrent"}, Action: "block"},
			{Match: []string{"domain:netflix.com"}, Action: "outbound", Value: "landing"},
		},
	}
	b, err := render(node, node.Inbounds, users, renderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := decode(t, b)
	outs := cfg["outbounds"].([]any)
	if len(outs) != 3 || outs[2].(map[string]any)["detour"] != "warp" {
		t.Fatalf("outbounds: %v", outs)
	}
	rules := cfg["route"].(map[string]any)["rules"].([]any)
	if rules[0].(map[string]any)["action"] != "reject" {
		t.Fatalf("rule0: %v", rules[0])
	}
	if rules[1].(map[string]any)["outbound"] != "landing" {
		t.Fatalf("rule1: %v", rules[1])
	}
}

func TestRenderScopedUsers(t *testing.T) {
	node := &spec.Node{Inbounds: []spec.Inbound{
		{Tag: "all", Protocol: spec.VMess, Port: 1},
		{Tag: "vip", Protocol: spec.VMess, Port: 2, ScopedUsers: true, Users: users[:1]},
		{Tag: "nobody", Protocol: spec.VMess, Port: 3, ScopedUsers: true},
	}}
	b, err := render(node, node.Inbounds, users, renderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := decode(t, b)
	ins := cfg["inbounds"].([]any)
	if n := len(ins[0].(map[string]any)["users"].([]any)); n != 2 {
		t.Fatalf("all: %d users", n)
	}
	if n := len(ins[1].(map[string]any)["users"].([]any)); n != 1 {
		t.Fatalf("vip: %d users", n)
	}
	if n := len(ins[2].(map[string]any)["users"].([]any)); n != 0 {
		t.Fatalf("nobody: %d users", n)
	}
	stats := cfg["experimental"].(map[string]any)["v2ray_api"].(map[string]any)["stats"].(map[string]any)
	if len(stats["users"].([]any)) != 2 {
		t.Fatalf("stats users must be the union: %v", stats["users"])
	}
}
