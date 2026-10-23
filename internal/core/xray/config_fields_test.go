package xray

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestXrayStructuralAliasesPreserveExplicitPolicies(t *testing.T) {
	patch := json.RawMessage(`{"outbounds":[{"Protocol":"FrEeDoM","Tag":"direct","Settings":{"redirect":"127.0.0.1:8080","domainStrategy":"UseIPv4","FinalRules":[{"action":"block"}]},"StreamSettings":{"Security":"none","tcpSettings":{"header":{"request":{"headers":{"Host":["example.com"],"host":["second.example.com"],"Settings":["opaque"]}}}}}}]}`)
	node := &spec.Node{Inbounds: []spec.Inbound{{Tag: "test", Protocol: spec.VLESS, Port: 12345}}, Overrides: map[string]json.RawMessage{"xray": patch}}
	before, _ := json.Marshal(node)
	data, _, err := render(node, node.Inbounds, nil, renderOptions{ModernConfig: true, StrictOutboundSecurity: true})
	if err != nil {
		t.Fatal(err)
	}
	var cfg m
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	out := configObjects(cfg["outbounds"])[0]
	settings := out["settings"].(map[string]any)
	if out["protocol"] != "freedom" || out["tag"] != "direct" || settings["redirect"] != "127.0.0.1:8080" || settings["domainStrategy"] != "UseIPv4" || !reflect.DeepEqual(configObjects(settings["finalRules"]), []m{{"action": "block"}}) {
		t.Fatal("alias normalization lost or widened an operator-authored policy")
	}
	if _, shadow := out["Settings"]; shadow {
		t.Fatal("two differently cased settings bodies were emitted")
	}
	stream := out["streamSettings"].(map[string]any)
	headers := stream["tcpSettings"].(map[string]any)["header"].(map[string]any)["request"].(map[string]any)["headers"].(map[string]any)
	if len(headers) != 3 || headers["Host"] == nil || headers["host"] == nil || headers["Settings"] == nil {
		t.Fatal("free-form HTTP header keys were normalized as config fields")
	}
	after, _ := json.Marshal(node)
	if string(before) != string(after) {
		t.Fatal("render mutated the stored node/override configuration")
	}
}

func TestXrayStructuralAliasesCannotBypassModernChecks(t *testing.T) {
	for _, outbound := range []m{
		{"Protocol": "FREEDOM", "Settings": m{"IPSBlocked": []string{"10.0.0.0/8"}}},
		{"Protocol": "VLESS", "Settings": m{"Address": "edge.example.com", "Encryption": "none"}, "StreamSettings": m{"Security": "NONE"}},
		{"Protocol": "vless", "Settings": m{"Vnext": []m{{"Address": "edge.example.com", "Users": []m{{"Encryption": "none"}}}}}},
		{"Protocol": "Trojan", "Settings": m{"Servers": []m{{"Address": "edge.example.com"}}}},
		{"Protocol": "VMess", "Settings": m{"Vnext": []m{{"Users": []m{{"Security": "zero"}}}}}},
	} {
		input := m{"outbounds": []m{outbound}}
		before, _ := json.Marshal(input)
		cfg, err := normalizeXrayConfigFields(input)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateXrayConfigCompatibility(cfg, renderOptions{ModernConfig: true, StrictOutboundSecurity: true}); err == nil {
			t.Fatal("a case-insensitive schema field bypassed compatibility checks")
		}
		if err := applyFreedomFinalRules(cfg, &spec.Node{}, nil); err != nil {
			t.Fatal(err)
		}
		after, _ := json.Marshal(input)
		if string(before) != string(after) {
			t.Fatal("normalization or finalRules mutated a shared source map/slice")
		}
	}
}

func TestXrayStructuralAliasesRejectAmbiguity(t *testing.T) {
	for _, input := range []m{
		{"outbounds": nil, "Outbounds": nil},
		{"outbounds": []m{{"protocol": "freedom", "Protocol": "vless"}}},
		{"outbounds": []m{{"protocol": "freedom", "tag": "one", "Tag": "two"}}},
		{"outbounds": []m{{"protocol": "freedom", "Settings": m{}, "settings": m{}}}},
		{"outbounds": []m{{"protocol": "vless", "streamSettings": m{}, "StreamSettings": m{}}}},
		{"outbounds": []m{{"protocol": "vless", "settings": m{"address": "one.example.com", "Address": "two.example.com"}}}},
		{"outbounds": []m{{"protocol": "vless", "settings": m{"Vnext": []m{{"users": []m{{"encryption": "none", "Encryption": "other"}}}}}}}},
		{"outbounds": []m{{"protocol": "freedom", "settings": m{"finalRules": nil, "FinalRules": []m{{"action": "block"}}}}}},
	} {
		if _, err := normalizeXrayConfigFields(input); err == nil {
			t.Fatal("ambiguous case-insensitive struct fields were accepted")
		}
	}
}
