package singbox

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestRenderRemoteOutbounds(t *testing.T) {
	node := &spec.Node{
		DefaultOutbound: "landing",
		Outbounds: []spec.Outbound{
			{Tag: "landing", Remote: &spec.Remote{Host: "exit.test", Port: 443, UUID: "u1", Settings: spec.Inbound{Protocol: spec.VLESS, Flow: "xtls-rprx-vision",
				TLS: &spec.TLS{Mode: spec.TLSReality, ServerName: "www.apple.com", Reality: &spec.Reality{PublicKey: "PUB", ShortIDs: []string{"ab"}}}}}},
			{Tag: "ss-exit", ProxyTag: "landing", Remote: &spec.Remote{Host: "ss.test", Port: 8388, Password: "pw", Settings: spec.Inbound{Protocol: spec.Shadowsocks, Cipher: "aes-128-gcm"}}},
			{Tag: "hy", Remote: &spec.Remote{Host: "hy.test", Port: 443, Password: "pw", Insecure: true, Settings: spec.Inbound{Protocol: spec.Hysteria2, TLS: &spec.TLS{Mode: spec.TLSStandard, ServerName: "hy.test"}, Obfs: "salamander", ObfsPassword: "o"}}},
		},
		Routes: []spec.RouteRule{{Match: []string{"inbound:in-a", "domain:example.com"}, Action: "outbound", Value: "ss-exit"}},
	}
	ib := spec.Inbound{Tag: "in-a", Protocol: spec.Shadowsocks, Port: 1, Cipher: "aes-128-gcm"}
	b, err := render(node, []spec.Inbound{ib}, []spec.User{{Name: "a", Password: "p"}}, renderOptions{LogLevel: "warn", StatsListen: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = json.Unmarshal(b, &cfg)
	outs := cfg["outbounds"].([]any)
	if len(outs) != 4 {
		t.Fatalf("outbounds %d", len(outs))
	}
	s := string(b)
	for _, want := range []string{`"type": "vless"`, `"flow": "xtls-rprx-vision"`, `"public_key": "PUB"`, `"short_id": "ab"`, `"fingerprint": "chrome"`,
		`"detour": "landing"`, `"method": "aes-128-gcm"`, `"type": "hysteria2"`, `"insecure": true`, `"salamander"`, `"final": "landing"`, `"inbound": [`, `"in-a"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in\n%s", want, s)
		}
	}
	if strings.Contains(strings.Split(s, `"type": "hysteria2"`)[1], "utls") {
		t.Fatal("QUIC outbound must not carry utls")
	}
	// An unsupported protocol is an error, not silence.
	node.Outbounds = append(node.Outbounds, spec.Outbound{Tag: "bad", Remote: &spec.Remote{Host: "x", Port: 1, Settings: spec.Inbound{Protocol: spec.Mieru}}})
	if _, err := render(node, []spec.Inbound{ib}, nil, renderOptions{}); err == nil {
		t.Fatal("mieru remote should be refused")
	}
}
