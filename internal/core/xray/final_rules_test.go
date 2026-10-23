package xray

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func renderedFinalRules(t *testing.T, node *spec.Node, users []spec.User) map[string][]m {
	t.Helper()
	data, _, err := render(node, node.Inbounds, users, renderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var cfg m
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	out := map[string][]m{}
	for _, item := range configObjects(cfg["outbounds"]) {
		if item["protocol"] == "freedom" {
			settings, _ := item["settings"].(map[string]any)
			out[item["tag"].(string)] = configObjects(settings["finalRules"])
		}
	}
	return out
}

func TestFreedomFinalRulesPreserveGlobalPermissions(t *testing.T) {
	base := spec.Node{Inbounds: []spec.Inbound{{Tag: "test", Protocol: spec.VLESS, Port: 12345}}}
	for _, test := range []struct {
		name string
		node spec.Node
		want []m
	}{
		{"default", base, []m{{"action": "block", "ip": spec.PrivateRanges, "blockDelay": 0}, {"action": "allow"}}},
		{"explicit global exemption", spec.Node{Inbounds: base.Inbounds, AllowPrivateDest: true}, []m{{"action": "allow"}}},
		{"one exception", spec.Node{Inbounds: base.Inbounds, PrivateDestAllow: []string{"10.10.0.2/32"}}, []m{{"action": "allow", "ip": []string{"10.10.0.2/32"}}, {"action": "block", "ip": spec.PrivateRanges, "blockDelay": 0}, {"action": "allow"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, _ := json.Marshal(renderedFinalRules(t, &test.node, nil)["direct"])
			want, _ := json.Marshal(test.want)
			if string(got) != string(want) {
				t.Fatal("final destination policy changed the node's explicit permissions")
			}
		})
	}
	base.Outbounds = []spec.Outbound{{Tag: "custom", Protocol: "freedom", Settings: map[string]any{"finalRules": []m{{"action": "block"}}}}}
	got := renderedFinalRules(t, &base, nil)["custom"]
	if !reflect.DeepEqual(got, []m{{"action": "block"}}) {
		t.Fatal("operator-authored restrictive finalRules were replaced")
	}
}

func TestFreedomFinalRulesPrivateScopesRemainSeparate(t *testing.T) {
	node := &spec.Node{Inbounds: []spec.Inbound{
		{Tag: "allowed", Protocol: spec.VLESS, Port: 12345, PrivateAccess: &spec.PrivateAccess{Mode: "custom", Rules: []spec.PrivateAccessRule{{CIDR: "10.10.0.2/32", Protocol: "tcp", PortStart: 8080, PortEnd: 8080}}}},
		{Tag: "ordinary", Protocol: spec.VLESS, Port: 12346},
	}}
	users := []spec.User{{ID: 1, Name: "user", UUID: "user-uuid", SpeedLimitMbps: 2}}
	policies := renderedFinalRules(t, node, users)
	var privateClones int
	for tag, rules := range policies {
		encoded, _ := json.Marshal(rules)
		if !strings.HasPrefix(tag, "private-") {
			if strings.Contains(string(encoded), "10.10.0.2/32") {
				t.Fatal("ordinary direct/shaping outbound inherited another inbound's permission")
			}
			continue
		}
		privateClones++
		if len(rules) != 4 || rules[0]["action"] != "block" || rules[2]["action"] != "block" || rules[3]["action"] != "allow" {
			t.Fatal("private clone lost metadata protection or general private deny")
		}
		allow := rules[1]
		if allow["action"] != "allow" || allow["network"] != "tcp" || allow["port"] != "8080-8080" || !reflect.DeepEqual(allow["ip"], []any{"10.10.0.2/32"}) {
			t.Fatal("grant was widened beyond its address, protocol or port")
		}
	}
	if privateClones != 4 {
		t.Fatalf("expected direct/shaping clones for both private identities, got %d", privateClones)
	}
	node.Inbounds = nil
	node.ReverseClients = []spec.ReverseClient{{ID: "one", Host: "198.51.100.20", Port: 23456, UUID: "00000000-0000-4000-8000-000000000001", PrivateAccess: &spec.PrivateAccess{Mode: "custom", Rules: []spec.PrivateAccessRule{{CIDR: "10.10.0.2/32", Protocol: "udp", PortStart: 53}}}}}
	policies = renderedFinalRules(t, node, nil)
	if len(policies["direct"]) != 2 {
		t.Fatal("reverse public exit is missing explicit private deny/public allow")
	}
	for tag, rules := range policies {
		if strings.HasPrefix(tag, "private-") && (rules[1]["network"] != "udp" || rules[1]["port"] != "53-53") {
			t.Fatal("reverse private grant widened beyond its own scope")
		}
	}
}

func TestModernXrayRejectsIncompatibleSecurityModes(t *testing.T) {
	strict := renderOptions{ModernConfig: true, StrictOutboundSecurity: true}
	for _, outbound := range []m{
		{"protocol": "vless", "settings": m{"address": "edge.example.com", "encryption": "none"}},
		{"protocol": "vless", "settings": m{"vnext": []m{{"address": "edge.example.com", "users": []m{{"encryption": "none"}}}}}},
		{"protocol": "trojan", "settings": m{"servers": []m{{"address": "edge.example.com"}}}},
		{"protocol": "trojan", "settings": m{"address": "edge.example.com"}},
		{"protocol": "vmess", "settings": m{"vnext": []m{{"users": []m{{"security": "NONE"}}}}}},
		{"protocol": "shadowsocks", "settings": m{"servers": []m{{"method": "plain"}}}},
		{"protocol": "freedom", "settings": m{"ipsBlocked": []string{"10.0.0.0/8"}}},
	} {
		cfg := m{"outbounds": []m{outbound}}
		if err := validateXrayConfigCompatibility(cfg, strict); err == nil {
			t.Fatal("new core accepted a removed mode or public cleartext transport")
		}
		if err := validateXrayConfigCompatibility(cfg, renderOptions{}); err != nil {
			t.Fatal("compatibility gate changed the old core's configuration", err)
		}
	}
	for _, outbound := range []m{
		{"protocol": "vless", "settings": m{"address": "edge.example.com", "encryption": "none"}, "streamSettings": m{"security": "tls"}},
		{"protocol": "trojan", "settings": m{"address": "edge.example.com"}, "streamSettings": m{"security": "reality"}},
		{"protocol": "vless", "settings": m{"vnext": []m{{"address": "10.10.0.2", "users": []m{{"encryption": "none"}}}}}},
		{"protocol": "vmess", "settings": m{"security": "auto"}},
	} {
		if err := validateXrayConfigCompatibility(m{"outbounds": []m{outbound}}, strict); err != nil {
			t.Fatal("compatible outbound rejected", err)
		}
	}
	for host, want := range map[string]bool{"edge.example.com": false, "10.10.0.2": true, "198.51.100.20": true, "::1": true, "fd00::1": true, "192.0.0.9": true, "edge.internal.": true, "local-host": true, "edge.internal.example.com": false} {
		if xrayCleartextPrivateHost(host) != want {
			t.Fatalf("upstream transport classification changed for %s", host)
		}
	}
	// This path is used before activateCore drains/stops the current core.
	node := &spec.Node{ReverseClients: []spec.ReverseClient{{ID: "one", Host: "edge.example.com", Port: 443, UUID: "00000000-0000-4000-8000-000000000001"}}}
	if _, _, err := render(node, nil, nil, strict); err == nil {
		t.Fatal("managed public cleartext reverse survived core-switch preflight")
	}
}
