package xray

import (
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

var users = []spec.User{
	{ID: 1, Name: "u1", UUID: "11111111-1111-1111-1111-111111111111", Password: "p1"},
	{ID: 2, Name: "u2", UUID: "22222222-2222-2222-2222-222222222222", Password: "p2"},
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, b)
	}
	return out
}

func TestRenderVLESSRealityAndKey(t *testing.T) {
	ib := spec.Inbound{
		Tag: "in", Protocol: spec.VLESS, Port: 443, Flow: "xtls-rprx-vision",
		TLS: &spec.TLS{Mode: spec.TLSReality, ServerName: "www.apple.com", Reality: &spec.Reality{
			PrivateKey: "pk", ShortIDs: []string{"abcd"}, HandshakeServer: "www.apple.com", HandshakePort: 443,
		}},
	}
	node := &spec.Node{Inbounds: []spec.Inbound{ib}}
	b, st, err := render(node, node.Inbounds, users, renderOptions{LogLevel: "warning", APIListen: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := decode(t, b)
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	if in["protocol"] != "vless" || in["port"] != float64(443) {
		t.Fatalf("inbound: %v", in)
	}
	c := in["settings"].(map[string]any)["clients"].([]any)[0].(map[string]any)
	if c["email"] != "u1|in" || c["flow"] != "xtls-rprx-vision" {
		t.Fatalf("client: %v", c)
	}
	ss := in["streamSettings"].(map[string]any)
	if ss["security"] != "reality" || ss["network"] != "raw" {
		t.Fatalf("stream: %v", ss)
	}
	r := ss["realitySettings"].(map[string]any)
	if r["target"] != "www.apple.com:443" || r["privateKey"] != "pk" {
		t.Fatalf("reality: %v", r)
	}
	if cfg["api"].(map[string]any)["listen"] != "127.0.0.1:1" {
		t.Fatalf("api: %v", cfg["api"])
	}

	// Same inbounds, different users: key unchanged. Different port: key changes.
	_, st2, _ := render(node, node.Inbounds, users[:1], renderOptions{})
	if st.inboundsKey != st2.inboundsKey {
		t.Fatal("key must ignore users")
	}
	node.Inbounds[0].Port = 8443
	_, st3, _ := render(node, node.Inbounds, users, renderOptions{})
	if st.inboundsKey == st3.inboundsKey {
		t.Fatal("key must change with inbound settings")
	}
}

func TestRenderTransportsAndTLS(t *testing.T) {
	tls := &spec.TLS{Mode: spec.TLSStandard, ServerName: "a", CertPath: "/c", KeyPath: "/k"}
	cases := []struct {
		tr   *spec.Transport
		key  string
		want string
	}{
		{&spec.Transport{Type: "ws", Path: "/ws", Host: "h"}, "wsSettings", "ws"},
		{&spec.Transport{Type: "grpc", ServiceName: "svc"}, "grpcSettings", "grpc"},
		{&spec.Transport{Type: "httpupgrade", Path: "/up"}, "httpupgradeSettings", "httpupgrade"},
		{&spec.Transport{Type: "xhttp", Path: "/x", Mode: "auto"}, "xhttpSettings", "xhttp"},
	}
	for _, tc := range cases {
		node := &spec.Node{Inbounds: []spec.Inbound{{Tag: "t", Protocol: spec.Trojan, Port: 1, TLS: tls, Transport: tc.tr}}}
		b, _, err := render(node, node.Inbounds, users, renderOptions{})
		if err != nil {
			t.Fatalf("%s: %v", tc.want, err)
		}
		ss := decode(t, b)["inbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
		if ss["network"] != tc.want || ss[tc.key] == nil || ss["security"] != "tls" {
			t.Fatalf("%s: %v", tc.want, ss)
		}
	}
	node := &spec.Node{Inbounds: []spec.Inbound{{Tag: "t", Protocol: spec.VLESS, Port: 1, Transport: &spec.Transport{Type: "http"}}}}
	if _, _, err := render(node, node.Inbounds, users, renderOptions{}); err == nil {
		t.Fatal("http transport must be rejected by xray renderer")
	}
	node = &spec.Node{Inbounds: []spec.Inbound{{Tag: "t", Protocol: spec.Shadowsocks, Cipher: "2022-blake3-aes-128-gcm", Port: 1}}}
	if _, _, err := render(node, node.Inbounds, users, renderOptions{}); err == nil {
		t.Fatal("ss2022 must be rejected by xray renderer")
	}
}

func TestRenderOutboundsAndRoutes(t *testing.T) {
	node := &spec.Node{
		Inbounds: []spec.Inbound{{Tag: "in", Protocol: spec.VMess, Port: 1}},
		Outbounds: []spec.Outbound{{Tag: "landing", Protocol: "socks", ProxyTag: "warp",
			Settings: map[string]any{"servers": []any{map[string]any{"address": "1.2.3.4", "port": 1080}}, "streamSettings": map[string]any{"network": "tcp"}}}},
		Routes: []spec.RouteRule{{Match: []string{"protocol:bittorrent"}, Action: "block"}, {Match: []string{"domain:netflix.com", "ip:1.1.1.1/32"}, Action: "outbound", Value: "landing"}},
	}
	b, _, err := render(node, node.Inbounds, users, renderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := decode(t, b)
	outs := cfg["outbounds"].([]any)
	o := outs[2].(map[string]any)
	if o["proxySettings"].(map[string]any)["tag"] != "warp" || o["streamSettings"] == nil || o["settings"].(map[string]any)["servers"] == nil {
		t.Fatalf("outbound: %v", o)
	}
	rules := cfg["routing"].(map[string]any)["rules"].([]any)
	if rules[0].(map[string]any)["outboundTag"] != "api" {
		t.Fatalf("api rule missing: %v", rules[0])
	}
	if rules[1].(map[string]any)["outboundTag"] != "block" {
		t.Fatalf("rule1: %v", rules[1])
	}
	r2 := rules[2].(map[string]any)
	if r2["outboundTag"] != "landing" || r2["domain"].([]any)[0] != "domain:netflix.com" || r2["ip"].([]any)[0] != "1.1.1.1/32" {
		t.Fatalf("rule2: %v", r2)
	}
}

// TestAddUserEncoding decodes the hand-built AlterInboundRequest back and
// checks the nesting: tag, TypedMessage(AddUserOperation{User{email, account}}).
func TestAddUserEncoding(t *testing.T) {
	acc, err := account(spec.VLESS, users[0], "xtls-rprx-vision")
	if err != nil {
		t.Fatal(err)
	}
	user := strField(2, users[0].Name)
	user = append(user, bytesField(3, acc)...)
	op := typed(typeAddUser, bytesField(1, user))
	req := strField(1, "in")
	req = append(req, bytesField(2, op)...)

	fields := parse(t, req)
	if string(fields[1]) != "in" {
		t.Fatalf("tag: %q", fields[1])
	}
	tm := parse(t, fields[2])
	if string(tm[1]) != typeAddUser {
		t.Fatalf("op type: %q", tm[1])
	}
	addOp := parse(t, tm[2])
	u := parse(t, addOp[1])
	if string(u[2]) != "u1" {
		t.Fatalf("email: %q", u[2])
	}
	accTM := parse(t, u[3])
	if string(accTM[1]) != "xray.proxy.vless.Account" {
		t.Fatalf("account type: %q", accTM[1])
	}
	accFields := parse(t, accTM[2])
	if string(accFields[1]) != users[0].UUID || string(accFields[2]) != "xtls-rprx-vision" {
		t.Fatalf("account: %q %q", accFields[1], accFields[2])
	}
}

// parse returns bytes-typed fields of a message by number (last wins).
func parse(t *testing.T, b []byte) map[protowire.Number][]byte {
	t.Helper()
	out := map[protowire.Number][]byte{}
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			t.Fatal(protowire.ParseError(n))
		}
		b = b[n:]
		if typ != protowire.BytesType {
			t.Fatalf("unexpected wire type %v for field %d", typ, num)
		}
		v, n := protowire.ConsumeBytes(b)
		if n < 0 {
			t.Fatal(protowire.ParseError(n))
		}
		out[num] = v
		b = b[n:]
	}
	return out
}

func TestDiffUsers(t *testing.T) {
	prev := map[string]spec.User{"a": {Name: "a", UUID: "1"}, "b": {Name: "b", UUID: "2"}}
	next := map[string]spec.User{"a": {Name: "a", UUID: "1"}, "b": {Name: "b", UUID: "changed"}, "c": {Name: "c", UUID: "3"}}
	adds, removes := diffUsers(prev, next)
	if len(adds) != 2 || len(removes) != 1 || removes[0] != "b" {
		t.Fatalf("adds=%v removes=%v", adds, removes)
	}
	adds, removes = diffUsers(next, map[string]spec.User{})
	if len(adds) != 0 || len(removes) != 3 {
		t.Fatalf("clear: adds=%v removes=%v", adds, removes)
	}
}

func TestRenderScopedUsers(t *testing.T) {
	node := &spec.Node{Inbounds: []spec.Inbound{
		{Tag: "all", Protocol: spec.VMess, Port: 1},
		{Tag: "vip", Protocol: spec.VMess, Port: 2, ScopedUsers: true, Users: users[:1]},
	}}
	_, st, err := render(node, node.Inbounds, users, renderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.users["all"]) != 2 || len(st.users["vip"]) != 1 {
		t.Fatalf("scoped users: %+v", st.users)
	}
}

func TestDecodeIPMap(t *testing.T) {
	entry := func(ip string, n uint64) []byte {
		var e []byte
		e = protowire.AppendTag(e, 1, protowire.BytesType)
		e = protowire.AppendString(e, ip)
		e = protowire.AppendTag(e, 2, protowire.VarintType)
		e = protowire.AppendVarint(e, n)
		return e
	}
	var resp []byte
	resp = protowire.AppendTag(resp, 1, protowire.BytesType)
	resp = protowire.AppendString(resp, "user>>>u1>>>online")
	for _, e := range [][]byte{entry("1.2.3.4", 1), entry("5.6.7.8", 2)} {
		resp = protowire.AppendTag(resp, 2, protowire.BytesType)
		resp = protowire.AppendBytes(resp, e)
	}
	ips, err := decodeIPMap(resp)
	if err != nil || len(ips) != 2 || ips[0] != "1.2.3.4" || ips[1] != "5.6.7.8" {
		t.Fatalf("ips=%v err=%v", ips, err)
	}
}

func TestRealityFallbackLimit(t *testing.T) {
	ib := spec.Inbound{Tag: "r", Protocol: spec.VLESS, Port: 443, TLS: &spec.TLS{Mode: spec.TLSReality, ServerName: "www.apple.com", Reality: &spec.Reality{PrivateKey: "k", HandshakeServer: "www.apple.com", HandshakePort: 443}}}
	out, err := renderInbound(ib, nil)
	if err != nil {
		t.Fatal(err)
	}
	rs := out["streamSettings"].(m)["realitySettings"].(m)
	if rs["limitFallbackUpload"] == nil || rs["limitFallbackDownload"] == nil {
		t.Fatalf("fallback limit missing: %v", rs)
	}
	ib.TLS.Reality.FallbackLimit = &spec.FallbackLimit{Off: true}
	out, _ = renderInbound(ib, nil)
	if out["streamSettings"].(m)["realitySettings"].(m)["limitFallbackUpload"] != nil {
		t.Fatal("limit rendered although off")
	}
}

func TestFallbacks(t *testing.T) {
	ib := spec.Inbound{Tag: "f", Protocol: spec.VLESS, Port: 443, TLS: &spec.TLS{Mode: spec.TLSStandard, ServerName: "www.example.com", CertPath: "/c", KeyPath: "/k"},
		Fallbacks: []spec.Fallback{{Dest: "80"}, {Path: "/ws", Dest: "127.0.0.1:8080", Xver: 1}}}
	out, err := renderInbound(ib, nil)
	if err != nil {
		t.Fatal(err)
	}
	fbs := out["settings"].(m)["fallbacks"].([]m)
	if len(fbs) != 2 || fbs[0]["dest"] != 80 || fbs[1]["dest"] != "127.0.0.1:8080" || fbs[1]["path"] != "/ws" || fbs[1]["xver"] != 1 {
		t.Fatalf("fallbacks: %v", fbs)
	}
	ib.TLS.Mode = spec.TLSReality
	if _, err := renderInbound(ib, nil); err == nil {
		t.Fatal("fallbacks accepted with REALITY")
	}
}

func TestWARPOutbound(t *testing.T) {
	node := &spec.Node{Outbounds: []spec.Outbound{{Tag: "warp", WARP: &spec.WARP{PrivateKey: "PRIV", PeerPublicKey: "PEER", Addresses: []string{"172.16.0.2/32"}, Reserved: []int{1, 2, 3}}}},
		Routes: []spec.RouteRule{{Match: []string{"domain:openai.com"}, Action: "outbound", Value: "warp"}}}
	ib := spec.Inbound{Tag: "v", Protocol: spec.VLESS, Port: 8080}
	b, _, err := render(node, []spec.Inbound{ib}, []spec.User{{ID: 1, Name: "u", UUID: "7f3a4b2c-1d5e-4f6a-9b8c-0d1e2f3a4b5c"}}, renderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"protocol": "wireguard"`, `"secretKey": "PRIV"`, `"publicKey": "PEER"`, `"engage.cloudflareclient.com:2408"`, `"reserved"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in\n%s", want, s)
		}
	}
}

func TestBalancerGeoDNS(t *testing.T) {
	node := &spec.Node{DNS: []string{"1.1.1.1", "https://dns.google/dns-query"},
		Outbounds: []spec.Outbound{
			{Tag: "a", Remote: &spec.Remote{Host: "203.0.113.30", Port: 443, UUID: "7f3a4b2c-1d5e-4f6a-9b8c-0d1e2f3a4b5c", Settings: spec.Inbound{Protocol: spec.VLESS}}},
			{Tag: "b", Remote: &spec.Remote{Host: "198.51.100.20", Port: 443, UUID: "7f3a4b2c-1d5e-4f6a-9b8c-0d1e2f3a4b5c", Settings: spec.Inbound{Protocol: spec.VLESS}}},
			{Tag: "lb", Balancer: &spec.Balancer{Members: []string{"a", "b"}}},
		},
		Routes: []spec.RouteRule{{Match: []string{"geosite:netflix", "geoip:us"}, Action: "outbound", Value: "lb"}}, DefaultOutbound: "lb"}
	ib := spec.Inbound{Tag: "v", Protocol: spec.VLESS, Port: 8080, NoSniff: true}
	b, _, err := render(node, []spec.Inbound{ib}, []spec.User{{ID: 1, Name: "u", UUID: "7f3a4b2c-1d5e-4f6a-9b8c-0d1e2f3a4b5c"}}, renderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"balancerTag": "lb"`, `"geosite:netflix"`, `"geoip:us"`, `"leastPing"`, `"observatory"`, `"https://dns.google/dns-query"`, `"enabled": false`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in\n%s", want, s)
		}
	}
	if strings.Contains(s, `"tag": "lb",
      "protocol"`) {
		t.Fatal("balancer rendered as an outbound")
	}
}

func TestSpeedLimitOutbounds(t *testing.T) {
	node := &spec.Node{UserSpeedLimitMbps: 20}
	users := []spec.User{{ID: 1, Name: "a", UUID: "7f3a4b2c-1d5e-4f6a-9b8c-0d1e2f3a4b5c"}, {ID: 2, Name: "b", UUID: "8f3a4b2c-1d5e-4f6a-9b8c-0d1e2f3a4b5c", SpeedLimitMbps: 5}}
	ib := spec.Inbound{Tag: "v", Protocol: spec.VLESS, Port: 8080}
	b, st, err := render(node, []spec.Inbound{ib}, users, renderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"tag": "limit-1"`, `"tag": "limit-2"`, `"mark": 65537`, `"user": [
          "b|v"
        ]`, `"outboundTag": "limit-2"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in\n%s", want, s)
		}
	}
	// Dropping a limited user changes the key (restart), unlike a plain user change.
	_, st2, _ := render(node, []spec.Inbound{ib}, users[:1], renderOptions{})
	if st.inboundsKey == st2.inboundsKey {
		t.Fatal("limited user set change must change the key")
	}
	plain := &spec.Node{}
	plainUsers := []spec.User{users[0], {ID: 3, Name: "c", UUID: "9f3a4b2c-1d5e-4f6a-9b8c-0d1e2f3a4b5c"}}
	_, p1, _ := render(plain, []spec.Inbound{ib}, plainUsers, renderOptions{})
	_, p2, _ := render(plain, []spec.Inbound{ib}, plainUsers[:1], renderOptions{})
	if p1.inboundsKey != p2.inboundsKey {
		t.Fatal("plain user change must keep the key")
	}
}
