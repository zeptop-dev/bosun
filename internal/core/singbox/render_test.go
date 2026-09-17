package singbox

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
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
		AllowPrivateDest: true, // this fixture indexes the rule list
		Inbounds:         []spec.Inbound{{Tag: "in", Protocol: spec.Trojan, Port: 443, TLS: &spec.TLS{Mode: spec.TLSStandard, ServerName: "a", CertPath: "/c", KeyPath: "/k"}}},
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
	// rules[0] is the sniff action for every inbound.
	if rules[0].(map[string]any)["action"] != "sniff" {
		t.Fatalf("sniff rule: %v", rules[0])
	}
	if rules[1].(map[string]any)["action"] != "reject" {
		t.Fatalf("rule1: %v", rules[1])
	}
	if rules[2].(map[string]any)["outbound"] != "landing" {
		t.Fatalf("rule2: %v", rules[2])
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
	// One counter per user and inbound: u1 and u2 on "all", u1 on "vip".
	if got := fmt.Sprint(stats["users"]); got != "[u1|all u2|all u1|vip]" {
		t.Fatalf("stats users must be per inbound: %v", stats["users"])
	}
}

func TestRuleSetsSniffDNS(t *testing.T) {
	node := &spec.Node{DNS: []string{"tls://1.1.1.1"}, Outbounds: []spec.Outbound{{Tag: "lb", Balancer: &spec.Balancer{Members: []string{"direct"}}}},
		Routes: []spec.RouteRule{{Match: []string{"geosite:openai"}, Action: "outbound", Value: "lb"}}}
	ibs := []spec.Inbound{{Tag: "a", Protocol: spec.VLESS, Port: 1000}, {Tag: "b", Protocol: spec.VLESS, Port: 1001, NoSniff: true}}
	b, err := render(node, ibs, []spec.User{{ID: 1, Name: "u", UUID: "7f3a4b2c-1d5e-4f6a-9b8c-0d1e2f3a4b5c"}}, renderOptions{StatsListen: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"geosite-openai"`, `meta-rules-dat/meta/geo/geosite/openai.srs`, `"action": "sniff"`, `"type": "urltest"`, `"type": "tls"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in\n%s", want, s)
		}
	}
	if strings.Contains(s, `"inbound": [
          "a",
          "b"
        ],
        "action": "sniff"`) {
		t.Fatal("no_sniff inbound included in sniff rule")
	}
}

func TestRenderTUICDefaultsALPN(t *testing.T) {
	ib := spec.Inbound{Tag: "t", Protocol: spec.TUIC, Port: 9001, TLS: &spec.TLS{Mode: spec.TLSStandard, ServerName: "x.example", CertPath: "/c", KeyPath: "/k"}}
	node := &spec.Node{Inbounds: []spec.Inbound{ib}}
	cfg, err := render(node, node.Inbounds, []spec.User{{Name: "u", UUID: "id", Password: "p"}}, renderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Inbounds []struct {
			TLS struct {
				ALPN []string `json:"alpn"`
			} `json:"tls"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(cfg, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Inbounds) != 1 || len(doc.Inbounds[0].TLS.ALPN) != 1 || doc.Inbounds[0].TLS.ALPN[0] != "h3" {
		t.Fatalf("tuic inbound should default to alpn h3: %s", cfg)
	}
}

// Snell renders as sing-box's v5 server: shared psk alone, or with a key
// per user in multi-user mode; obfs http maps to obfs_mode.
func TestRenderSnell(t *testing.T) {
	users := []spec.User{{Name: "u1", UUID: "uuid-1", Password: "key-1"}}
	single := spec.Inbound{Tag: "sn", Protocol: spec.Snell, Port: 6160, SnellPSK: "server-psk", SnellVersion: 4, SnellObfs: "http"}
	in, err := renderInbound(single, users)
	if err != nil {
		t.Fatal(err)
	}
	if in["type"] != "snell" || in["version"] != 5 || in["psk"] != "server-psk" || in["obfs_mode"] != "http" || in["users"] != nil {
		t.Fatalf("single-user snell: %v", in)
	}
	multi := single
	multi.SnellMultiUser, multi.SnellObfs = true, ""
	in, err = renderInbound(multi, users)
	if err != nil {
		t.Fatal(err)
	}
	us, _ := in["users"].([]any)
	if len(us) != 1 || us[0].(m)["userkey"] != "key-1" || us[0].(m)["name"] != "u1|sn" || in["obfs_mode"] != nil {
		t.Fatalf("multi-user snell: %v", in)
	}
}

// EgressByIngress: an inbound bound to an address gets a direct exit bound
// to it and a rule sending its traffic there; any-address inbounds and
// nodes with a default landing outbound are left alone.
func TestRenderEgressByIngress(t *testing.T) {
	node := &spec.Node{EgressByIngress: true}
	inbounds := []spec.Inbound{
		{Tag: "a", Protocol: spec.Shadowsocks, Port: 8388, Cipher: "aes-128-gcm", Listen: "198.51.100.20"},
		{Tag: "b", Protocol: spec.Shadowsocks, Port: 8389, Cipher: "aes-128-gcm", Listen: "198.51.100.21"},
		{Tag: "c", Protocol: spec.Shadowsocks, Port: 8390, Cipher: "aes-128-gcm"},
	}
	users := []spec.User{{ID: 1, Name: "u", Password: "p"}}
	out, err := render(node, inbounds, users, renderOptions{StatsListen: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = json.Unmarshal(out, &cfg)
	var bound []string
	for _, o := range cfg["outbounds"].([]any) {
		if om := o.(map[string]any); om["inet4_bind_address"] != nil {
			bound = append(bound, om["tag"].(string)+"="+om["inet4_bind_address"].(string))
		}
	}
	if len(bound) != 2 || bound[0] != "direct@198.51.100.20=198.51.100.20" {
		t.Fatalf("bound exits: %v", bound)
	}
	rules := cfg["route"].(map[string]any)["rules"].([]any)
	last := rules[len(rules)-1].(map[string]any)
	if last["outbound"] != "direct@198.51.100.21" || last["inbound"].([]any)[0] != "b" {
		t.Fatalf("bind rule: %v", last)
	}
	node.DefaultOutbound = "landing"
	node.Outbounds = []spec.Outbound{{Tag: "landing", Protocol: "socks", Settings: map[string]any{"server": "203.0.113.30", "server_port": 1080}}}
	out, err = render(node, inbounds, users, renderOptions{StatsListen: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "inet4_bind_address") {
		t.Fatal("a landing outbound must switch binding off")
	}
}
