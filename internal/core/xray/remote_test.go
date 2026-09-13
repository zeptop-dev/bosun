package xray

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestRenderRemoteOutboundsXray(t *testing.T) {
	node := &spec.Node{
		DefaultOutbound: "landing",
		Outbounds: []spec.Outbound{
			{Tag: "ws", Remote: &spec.Remote{Host: "ws.test", Port: 443, Password: "pw", Settings: spec.Inbound{Protocol: spec.Trojan, TLS: &spec.TLS{Mode: spec.TLSStandard, ServerName: "ws.test"}, Transport: &spec.Transport{Type: "ws", Path: "/t", Host: "cdn.test"}}}},
			{Tag: "landing", Remote: &spec.Remote{Host: "exit.test", Port: 443, UUID: "u1", Settings: spec.Inbound{Protocol: spec.VLESS, Flow: "xtls-rprx-vision",
				TLS: &spec.TLS{Mode: spec.TLSReality, ServerName: "www.apple.com", Reality: &spec.Reality{PublicKey: "PUB", ShortIDs: []string{"ab"}}}}}},
		},
		Routes: []spec.RouteRule{{Match: []string{"inbound:in-a"}, Action: "outbound", Value: "ws"}},
	}
	ib := spec.Inbound{Tag: "in-a", Protocol: spec.VLESS, Port: 1}
	b, _, err := render(node, []spec.Inbound{ib}, []spec.User{{Name: "a", UUID: "11111111-1111-1111-1111-111111111111"}}, renderOptions{LogLevel: "warning", APIListen: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = json.Unmarshal(b, &cfg)
	outs := cfg["outbounds"].([]any)
	if len(outs) != 4 || outs[0].(map[string]any)["tag"] != "landing" || outs[1].(map[string]any)["tag"] != "direct" {
		t.Fatalf("outbound order: %v", outs)
	}
	s := string(b)
	for _, want := range []string{`"vnext"`, `"flow": "xtls-rprx-vision"`, `"security": "reality"`, `"publicKey": "PUB"`, `"shortId": "ab"`, `"wsSettings"`, `"Host": "cdn.test"`, `"inboundTag": [`, `"in-a"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in\n%s", want, s)
		}
	}
	node.Outbounds = append(node.Outbounds, spec.Outbound{Tag: "hy", Remote: &spec.Remote{Host: "h", Port: 1, Settings: spec.Inbound{Protocol: spec.Hysteria2}}})
	if _, _, err := render(node, []spec.Inbound{ib}, nil, renderOptions{}); err == nil {
		t.Fatal("hysteria2 remote must be refused on Xray")
	}
}
