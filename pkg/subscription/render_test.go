package subscription

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/wg"

	"gopkg.in/yaml.v3"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func sample() []Line {
	reality := &spec.TLS{Mode: spec.TLSReality, ServerName: "www.apple.com", Reality: &spec.Reality{PublicKey: "PUB", ShortIDs: []string{"0123"}}}
	tls := &spec.TLS{Mode: spec.TLSStandard, ServerName: "node1.test"}
	uuid := "11111111-1111-1111-1111-111111111111"
	mk := func(name string, ib spec.Inbound) Line {
		return Line{Name: name, Host: "entry.test", Port: 443, Inbound: ib, UUID: uuid, Password: uuid}
	}
	return []Line{
		mk("reality", spec.Inbound{Protocol: spec.VLESS, Flow: "xtls-rprx-vision", TLS: reality}),
		mk("vmess-ws", spec.Inbound{Protocol: spec.VMess, TLS: tls, Transport: &spec.Transport{Type: "ws", Path: "/ws", Host: "cdn.test"}}),
		mk("trojan-grpc", spec.Inbound{Protocol: spec.Trojan, TLS: tls, Transport: &spec.Transport{Type: "grpc", ServiceName: "svc"}}),
		mk("ss2022", spec.Inbound{Protocol: spec.Shadowsocks, Cipher: "2022-blake3-aes-128-gcm", ServerKey: "c2VydmVya2V5c2VydmVya2V5"}),
		mk("hy2", spec.Inbound{Protocol: spec.Hysteria2, TLS: tls, Obfs: "salamander", ObfsPassword: "obfs", UpMbps: 100, DownMbps: 500}),
		mk("tuic", spec.Inbound{Protocol: spec.TUIC, TLS: tls, CongestionControl: "bbr"}),
		mk("anytls", spec.Inbound{Protocol: spec.AnyTLS, TLS: tls}),
		mk("mieru", spec.Inbound{Protocol: spec.Mieru, MieruTransport: "TCP"}),
		mk("xhttp", spec.Inbound{Protocol: spec.VLESS, TLS: tls, Transport: &spec.Transport{Type: "xhttp", Path: "/x", Mode: "auto"}}),
		mk("mieru-both", spec.Inbound{Protocol: spec.Mieru, MieruTransport: "BOTH", MieruMTU: 1400, MieruMultiplexing: "MULTIPLEXING_HIGH", MieruHandshake: "HANDSHAKE_NO_WAIT"}),
		mk("snell", spec.Inbound{Protocol: spec.Snell, SnellPSK: "psk-shared", SnellVersion: 5, SnellObfs: "http", SnellObfsHost: "www.bing.com"}),
	}
}

func TestClash(t *testing.T) {
	out, err := Clash{}.Render(sample(), Account{})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("yaml: %v\n%s", err, out)
	}
	proxies := doc["proxies"].([]any)
	if len(proxies) != 11 {
		t.Fatalf("expected 11 proxies, got %d", len(proxies))
	}
	if mb := proxies[9].(map[string]any); mb["transport"] != "TCP" || mb["multiplexing"] != "MULTIPLEXING_HIGH" || mb["handshake-mode"] != "HANDSHAKE_NO_WAIT" {
		t.Fatalf("mieru knobs: %v", mb)
	}
	if sn := proxies[10].(map[string]any); sn["type"] != "snell" || sn["psk"] != "psk-shared" || sn["version"] != 5 || sn["obfs-opts"].(map[string]any)["mode"] != "http" {
		t.Fatalf("snell: %v", sn)
	}
	p0 := proxies[0].(map[string]any)
	if p0["type"] != "vless" || p0["flow"] != "xtls-rprx-vision" || p0["reality-opts"].(map[string]any)["public-key"] != "PUB" || p0["servername"] != "www.apple.com" {
		t.Fatalf("reality proxy: %v", p0)
	}
	ss := proxies[3].(map[string]any)
	if !strings.HasPrefix(ss["password"].(string), "c2VydmVya2V5c2VydmVya2V5:") {
		t.Fatalf("ss2022 password: %v", ss["password"])
	}
	if m := proxies[7].(map[string]any); m["type"] != "mieru" || m["username"] != m["password"] || m["transport"] != "TCP" {
		t.Fatalf("mieru: %v", m)
	}
	if x := proxies[8].(map[string]any); x["network"] != "xhttp" {
		t.Fatalf("xhttp: %v", x)
	}
	groups := doc["proxy-groups"].([]any)
	if len(groups[0].(map[string]any)["proxies"].([]any)) != 12 {
		t.Fatalf("select group should list AUTO + 11")
	}
}

func TestSingBox(t *testing.T) {
	out, err := SingBox{}.Render(sample(), Account{})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("json: %v", err)
	}
	outs := doc["outbounds"].([]any)
	// 2 groups + 8 servers (mieru and xhttp skipped, snell included) + direct
	if len(outs) != 11 {
		t.Fatalf("outbounds: %d", len(outs))
	}
	r := outs[2].(map[string]any)
	if r["type"] != "vless" || r["tls"].(map[string]any)["reality"].(map[string]any)["public_key"] != "PUB" || r["flow"] != "xtls-rprx-vision" {
		t.Fatalf("reality: %v", r)
	}
	hy := outs[6].(map[string]any)
	if hy["type"] != "hysteria2" || hy["obfs"].(map[string]any)["password"] != "obfs" || hy["down_mbps"] != float64(500) {
		t.Fatalf("hy2: %v", hy)
	}
}

func TestURIList(t *testing.T) {
	out, err := URIList{}.Render(sample(), Account{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(string(out))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	if len(lines) != 10 {
		t.Fatalf("expected 10 links (snell has none), got %d:\n%s", len(lines), raw)
	}
	if both := lines[9]; !strings.HasPrefix(both, "mierus://") || !strings.Contains(both, "port=443&port=444") || !strings.Contains(both, "protocol=TCP&protocol=UDP") || !strings.Contains(both, "mtu=1400") || !strings.Contains(both, "multiplexing=MULTIPLEXING_HIGH") || !strings.Contains(both, "handshake-mode=HANDSHAKE_NO_WAIT") {
		t.Fatalf("mieru BOTH link: %s", both)
	}
	if !strings.HasPrefix(lines[0], "vless://11111111-1111-1111-1111-111111111111@entry.test:443?") || !strings.Contains(lines[0], "security=reality") || !strings.Contains(lines[0], "pbk=PUB") || !strings.Contains(lines[0], "flow=xtls-rprx-vision") {
		t.Fatalf("vless: %s", lines[0])
	}
	if !strings.HasPrefix(lines[1], "vmess://") {
		t.Fatalf("vmess: %s", lines[1])
	}
	if !strings.HasPrefix(lines[3], "ss://") || !strings.HasPrefix(lines[4], "hysteria2://") || !strings.HasPrefix(lines[5], "tuic://") || !strings.HasPrefix(lines[7], "mierus://") {
		t.Fatalf("links: %v", lines)
	}
}

func TestSurgeAndPick(t *testing.T) {
	out, _ := Surge{}.Render(sample(), Account{})
	s := string(out)
	for _, want := range []string{"vmess-ws = vmess, entry.test, 443", "hy2 = hysteria2, entry.test, 443, password=", "tuic = tuic, entry.test, 443, uuid=", "snell = snell, entry.test, 443, psk=psk-shared, version=5, obfs=http, obfs-host=www.bing.com"} {
		if !strings.Contains(s, want) {
			t.Fatalf("surge missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "reality") || strings.Contains(s, "ss2022") || strings.Contains(s, "mieru") {
		t.Fatalf("surge must skip unsupported lines:\n%s", s)
	}
	if Pick("", "ClashMetaForAndroid/2.9").Name() != "clash" || Pick("", "SFA/1.10 (sing-box 1.10)").Name() != "singbox" ||
		Pick("", "Surge/5").Name() != "surge" || Pick("", "v2rayN/6").Name() != "uri" || Pick("shadowrocket", "Mozilla").Name() != "uri" || Pick("mihomo", "").Name() != "clash" {
		t.Fatal("pick")
	}
}

func TestLoon(t *testing.T) {
	out, _ := Loon{}.Render(sample(), Account{})
	s := string(out)
	for _, want := range []string{
		`reality = VLESS,entry.test,443,"11111111-1111-1111-1111-111111111111",transport=tcp,flow=xtls-rprx-vision,over-tls=true,sni=www.apple.com,skip-cert-verify=false,public-key=PUB,short-id=0123,udp=true`,
		`vmess-ws = vmess,entry.test,443,aes-128-gcm,"11111111-1111-1111-1111-111111111111",transport=ws,path=/ws,host=cdn.test,alterId=0,over-tls=true,sni=node1.test,skip-cert-verify=false,udp=true`,
		`hy2 = Hysteria2,entry.test,443,"11111111-1111-1111-1111-111111111111",sni=node1.test,skip-cert-verify=false,fast-open=true,salamander-password="obfs",udp=true`,
		`anytls = AnyTLS,entry.test,443,"11111111-1111-1111-1111-111111111111",sni=node1.test,skip-cert-verify=false,udp=true`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("loon missing %q:\n%s", want, s)
		}
	}
	// grpc trojan, SS2022, tuic, mieru and xhttp have no Loon form.
	for _, skip := range []string{"trojan-grpc", "ss2022", "tuic", "mieru", "xhttp"} {
		if strings.Contains(s, skip+" =") {
			t.Fatalf("loon must skip %s:\n%s", skip, s)
		}
	}
}

func TestQuantumultX(t *testing.T) {
	out, _ := QuantumultX{}.Render(sample(), Account{})
	raw, err := base64.StdEncoding.DecodeString(string(out))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		"vless=entry.test:443, method=none, password=11111111-1111-1111-1111-111111111111, obfs=over-tls, reality-base64-pubkey=PUB, reality-hex-shortid=0123, obfs-host=www.apple.com, vless-flow=xtls-rprx-vision, fast-open=true, udp-relay=true, tag=reality",
		"vmess=entry.test:443, method=aes-128-gcm, password=11111111-1111-1111-1111-111111111111, obfs=wss, obfs-uri=/ws, tls-verification=true, obfs-host=cdn.test, fast-open=true, udp-relay=true, tag=vmess-ws",
		"shadowsocks=entry.test:443, method=2022-blake3-aes-128-gcm, password=c2VydmVya2V5c2VydmVya2V5:",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("qx missing %q:\n%s", want, s)
		}
	}
	// grpc trojan, hysteria2, tuic, anytls, mieru and xhttp have no QX form.
	if strings.Count(s, "\n") != 3 || strings.Contains(s, "trojan-grpc") || strings.Contains(s, "hy2") {
		t.Fatalf("qx lines:\n%s", s)
	}
}

func TestSurfboard(t *testing.T) {
	out, _ := Surfboard{}.Render(sample(), Account{})
	s := string(out)
	for _, want := range []string{
		"[General]",
		"vmess-ws = vmess, entry.test, 443, username=11111111-1111-1111-1111-111111111111, udp-relay=true, ws=true, ws-path=/ws, ws-headers=Host:cdn.test, tls=true, sni=node1.test, skip-cert-verify=false, vmess-aead=true",
		"PROXY = select, AUTO, vmess-ws\n",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("surfboard missing %q:\n%s", want, s)
		}
	}
	// Surfboard has no vless, hysteria2, tuic, anytls, SS2022 or grpc.
	for _, skip := range []string{"hy2 =", "reality =", "trojan-grpc =", "anytls =", "ss2022 =", "tuic ="} {
		if strings.Contains(s, skip) {
			t.Fatalf("surfboard must skip %s:\n%s", skip, s)
		}
	}
}

func TestStashAndTemplates(t *testing.T) {
	out, err := Stash{}.Render(sample(), Account{})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc["proxies"].([]any)) != 11 || doc["mixed-port"] != nil {
		t.Fatalf("stash doc: %v", doc)
	}
	// Stash dialect: sni not servername, hysteria2 auth + up-speed/down-speed, tuic version/alpn, no smux.
	stashOut := string(out)
	for _, want := range []string{"sni: www.apple.com", "auth: 11111111-1111-1111-1111-111111111111", "up-speed: 100", "down-speed: 500", "version: 5", "transport: tcp\n"} {
		if !strings.Contains(stashOut, want) {
			t.Fatalf("stash missing %q:\n%s", want, stashOut)
		}
	}
	for _, bad := range []string{"servername:", "smux:", "congestion-controller:", "udp-relay-mode:"} {
		if strings.Contains(stashOut, bad) {
			t.Fatalf("stash must not emit %s:\n%s", bad, stashOut)
		}
	}
	// Custom YAML template: an extra group with the placeholder expands in place; DIRECT survives.
	tpl := "mode: rule\nproxy-groups:\n  - name: MAIN\n    type: select\n    proxies: [\"{{proxy_names}}\", DIRECT]\n  - name: FAST\n    type: url-test\n    proxies: [\"{{proxy_names}}\"]\nrules:\n  - MATCH,MAIN\n"
	out, err = Clash{}.RenderWith(sample(), Account{}, tpl)
	if err != nil {
		t.Fatal(err)
	}
	doc = nil
	_ = yaml.Unmarshal(out, &doc)
	groups := doc["proxy-groups"].([]any)
	main := groups[0].(map[string]any)["proxies"].([]any)
	if len(main) != 12 || main[0] != "reality" || main[11] != "DIRECT" || len(groups[1].(map[string]any)["proxies"].([]any)) != 11 {
		t.Fatalf("template groups: %v", groups)
	}
	if len(doc["proxies"].([]any)) != 11 || doc["mode"] != "rule" {
		t.Fatalf("template doc: %v", doc)
	}
	// Custom INI template for Surge.
	out, _ = Surge{}.RenderWith(sample(), Account{}, "[Proxy]\n{{proxies}}\n[Proxy Group]\nALL = select, {{proxy_names}}\n")
	s := string(out)
	if !strings.HasPrefix(s, "[Proxy]\nvmess-ws = vmess") || !strings.Contains(s, "ALL = select, vmess-ws, hy2, tuic") || strings.Contains(s, "[General]") {
		t.Fatalf("surge template:\n%s", s)
	}
	// Defaults exist for every templated format and nothing else.
	if names := TemplateNames(); strings.Join(names, ",") != "clash,egern,loon,qx,stash,surfboard,surge" {
		t.Fatalf("template names: %v", names)
	}
	if DefaultTemplate("singbox") != "" || DefaultTemplate("loon") != "{{proxies}}\n" {
		t.Fatal("default templates")
	}
}

func TestPickNewClients(t *testing.T) {
	cases := map[string]string{
		"Stash/2.5.0 Clash/1.9.0": "stash", "Loon/3.2.1 (iPhone)": "loon", "Quantumult%20X/1.4.1": "qx",
		"Surfboard/2.24 (Android)": "surfboard", "Surge/5.8": "surge", "ClashMetaForAndroid/2.9": "clash",
	}
	for ua, want := range cases {
		if got := Pick("", ua).Name(); got != want {
			t.Fatalf("ua %q: got %s want %s", ua, got, want)
		}
	}
	if Pick("stash", "").Name() != "stash" || Pick("quantumult-x", "").Name() != "qx" || Pick("surfboard", "Mozilla").Name() != "surfboard" {
		t.Fatal("aliases")
	}
}

func TestWireGuardRendering(t *testing.T) {
	priv, pub, _ := wg.Keypair()
	l := Line{Name: "wg", Host: "198.51.100.20", Port: 51820, UUID: "u1", UserID: 7, Inbound: spec.Inbound{Tag: "wg", Protocol: spec.WireGuard, Port: 51820, WGPrivateKey: priv, WGPublicKey: pub}}
	conf := WGConf(l)
	if !strings.Contains(conf, "[Interface]") || !strings.Contains(conf, "PublicKey = "+pub) || !strings.Contains(conf, "Endpoint = 198.51.100.20:51820") || strings.Contains(conf, priv) {
		t.Fatalf("conf:\n%s", conf)
	}
	out, _ := WireGuardConf{}.Render([]Line{l}, Account{})
	if !strings.HasPrefix(string(out), "# wg\n[Interface]") {
		t.Fatalf("renderer: %s", out)
	}
	if p := clashProxy(l); p == nil || p["type"] != "wireguard" || p["public-key"] != pub {
		t.Fatalf("clash: %v", p)
	}
	if o := singboxOutbound(l); o == nil || o["type"] != "wireguard" {
		t.Fatalf("singbox: %v", o)
	}
	if Pick("wg", "").Name() != "wireguard" {
		t.Fatal("alias")
	}
}

func TestEgern(t *testing.T) {
	out, err := Egern{}.Render(sample(), Account{})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"proxies:", "- vless:", "user_id:", "- hysteria2:", "auth:", "- select:", "name: PROXY", "- default:", "policy: PROXY", "reality:", "public_key:"} {
		if !strings.Contains(s, want) {
			t.Fatalf("egern missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "{{proxy_names}}") || strings.Contains(s, "mieru") {
		t.Fatalf("egern output:\n%s", s)
	}
	if Pick("", "Egern/2.20 iOS").Name() != "egern" || Pick("egern", "").Name() != "egern" {
		t.Fatal("egern detection")
	}
	// A bare template (no policy groups) still yields a proxies list.
	bare, err := Egern{}.RenderWith(sample(), Account{}, "proxies: []\n")
	if err != nil || !strings.Contains(string(bare), "- vless:") || strings.Contains(string(bare), "policy_groups") {
		t.Fatalf("bare: %v %s", err, bare)
	}
}

func TestProxyNameFilters(t *testing.T) {
	lines := sample()
	for i := range lines {
		lines[i].Tags = nil
	}
	lines[0].Name, lines[0].Tags = "🇭🇰 HK-1", []string{"hk", "premium"}
	lines[1].Name, lines[1].Tags = "🇯🇵 JP-1", []string{"jp"}
	tpl := "proxy-groups:\n  - name: HK\n    type: select\n    proxies: [\"{{proxy_names:tag=HK}}\"]\n  - name: JP\n    type: select\n    proxies: [\"{{proxy_names:match=jp|日本}}\", DIRECT]\n  - name: NONE\n    type: select\n    proxies: [\"{{proxy_names:tag=nope}}\", DIRECT]\n"
	out, err := Clash{}.RenderWith(lines, Account{}, tpl)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "- name: HK\n    proxies:\n    - 🇭🇰 HK-1\n") && !strings.Contains(s, "HK-1") {
		t.Fatalf("tag filter: %s", s)
	}
	if strings.Contains(s, "{{proxy_names") {
		t.Fatalf("placeholder left: %s", s)
	}
	hk := s[strings.Index(s, "name: HK"):strings.Index(s, "name: JP")]
	if strings.Contains(hk, "JP-1") || !strings.Contains(hk, "HK-1") {
		t.Fatalf("HK group: %s", hk)
	}
	jp := s[strings.Index(s, "name: JP"):strings.Index(s, "name: NONE")]
	if strings.Contains(jp, "HK-1") || !strings.Contains(jp, "JP-1") {
		t.Fatalf("JP group: %s", jp)
	}
	ini, _ := Surge{}.RenderWith(lines, Account{}, "[Proxy]\n{{proxies}}\n[Proxy Group]\nJP = select, {{proxy_names:tag=jp}}\nALL = select, {{proxy_names}}\n")
	if !strings.Contains(string(ini), "JP = select, 🇯🇵 JP-1\n") {
		t.Fatalf("surge tag filter: %s", ini)
	}
}

// Snell reaches sing-box clients (version 4 on the wire) with the shared
// psk, plus the user key on a multi-user inbound; Surge and mihomo have no
// user key, so multi-user lines are left out of their documents.
func TestSnellRendering(t *testing.T) {
	shared := Line{Name: "sn", Host: "203.0.113.30", Port: 6160, Password: "user-key", Inbound: spec.Inbound{Protocol: spec.Snell, SnellPSK: "server-psk", SnellObfs: "http", SnellObfsHost: "www.bing.com"}}
	multi := shared
	multi.Inbound.SnellMultiUser = true
	out, err := SingBox{}.Render([]Line{shared, multi}, Account{})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(out, &doc)
	var sn []map[string]any
	for _, o := range doc["outbounds"].([]any) {
		if x := o.(map[string]any); x["type"] == "snell" {
			sn = append(sn, x)
		}
	}
	if len(sn) != 2 || sn[0]["version"] != float64(4) || sn[0]["psk"] != "server-psk" || sn[0]["obfs_mode"] != "http" || sn[0]["user_key"] != nil || sn[1]["user_key"] != "user-key" {
		t.Fatalf("sing-box snell: %v", sn)
	}
	clash, _ := Clash{}.RenderWith([]Line{shared, multi}, Account{}, "")
	if strings.Count(string(clash), "type: snell") != 1 || strings.Contains(string(clash), "user-key") {
		t.Fatalf("clash must carry only the shared-psk line:\n%s", clash)
	}
	surge, _ := Surge{}.Render([]Line{shared, multi}, Account{})
	if strings.Count(string(surge), "= snell,") != 1 || strings.Contains(string(surge), "user-key") {
		t.Fatalf("surge must carry only the shared-psk line:\n%s", surge)
	}
}
