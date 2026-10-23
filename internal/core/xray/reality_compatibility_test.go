package xray

import (
	"encoding/json"
	"testing"

	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestRealityPreservesCrossClientAdmission(t *testing.T) {
	for _, proxyProtocol := range []bool{false, true} {
		ib := spec.Inbound{Tag: "reality", Protocol: spec.VLESS, Port: 443, AcceptProxyProtocol: proxyProtocol,
			TLS: &spec.TLS{Mode: spec.TLSReality, ServerName: "example.com", Reality: &spec.Reality{
				PrivateKey: "fixture-key", HandshakeServer: "example.com", HandshakePort: 443, ShortIDs: []string{"abcd"},
			}}}
		node := &spec.Node{Inbounds: []spec.Inbound{ib}}
		data, _, err := render(node, node.Inbounds, users, renderOptions{})
		if err != nil {
			t.Fatal(err)
		}
		cfg := decode(t, data)
		in := configObjects(cfg["inbounds"])[0]
		stream := in["streamSettings"].(map[string]any)
		reality := stream["realitySettings"].(map[string]any)
		// An empty or omitted value inherits Xray's new 26.3.27 floor,
		// which rejects Mihomo's 1.8.2 authentication payload. Zero retains
		// the old no-version-floor behavior for every compatible client.
		if reality["minClientVer"] != "0.0.0" {
			t.Fatal("REALITY admission depends on the selected core's default version floor")
		}
		if reality["limitFallbackUpload"] == nil || reality["limitFallbackDownload"] == nil {
			t.Fatal("compatibility must not disable unauthenticated fallback limits")
		}
		if proxyProtocol && stream["sockopt"].(map[string]any)["acceptProxyProtocol"] != true {
			t.Fatal("compatibility must preserve the required PROXY header")
		}

		// Defaults are placed before the existing merge mechanism. An
		// explicitly supplied REALITY policy must never be rewritten to zero.
		patch := json.RawMessage(`{"streamSettings":{"realitySettings":{"minClientVer":"26.3.27","maxClientVer":"26.7.28"}}}`)
		if err := core.ApplyOverride("xray", in, patch); err != nil {
			t.Fatal(err)
		}
		reality = in["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
		if reality["minClientVer"] != "26.3.27" || reality["maxClientVer"] != "26.7.28" {
			t.Fatal("an explicit REALITY client-version policy was changed")
		}
	}
}

func TestRealityCompatibilityDoesNotAddClientRestrictions(t *testing.T) {
	for _, security := range []*spec.TLS{nil, {Mode: spec.TLSStandard, CertPath: "fixture.crt", KeyPath: "fixture.key"}} {
		stream, err := renderStream(spec.Inbound{Protocol: spec.VLESS, TLS: security})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := stream["realitySettings"]; ok {
			t.Fatal("REALITY compatibility settings leaked into another transport")
		}
	}
	remote, err := renderRemote(spec.Outbound{Tag: "upstream", Remote: &spec.Remote{
		Host: "example.com", Port: 443, UUID: users[0].UUID,
		Settings: spec.Inbound{Protocol: spec.VLESS, TLS: &spec.TLS{Mode: spec.TLSReality, ServerName: "example.com",
			Reality: &spec.Reality{PublicKey: "fixture-public-key", ShortIDs: []string{"abcd"}}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	settings := remote["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
	if _, ok := settings["minClientVer"]; ok {
		t.Fatal("a server admission policy was added to an outbound client")
	}
}
