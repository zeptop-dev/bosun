package subdesign

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
	"github.com/zeptop-dev/bosun/pkg/subscription"
	"gopkg.in/yaml.v3"
)

func TestNodeDualStackDesignLifecycle(t *testing.T) {
	d, _ := Preset("basic")
	original := clone(d)
	before, err := d.Render("clash")
	if err != nil {
		t.Fatal(err)
	}
	d.Enhancements.NodeDualStack = true
	serialized, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var saved Design
	if err = json.Unmarshal(serialized, &saved); err != nil || !saved.Enhancements.NodeDualStack {
		t.Fatalf("saved design lost option: %s, %v", serialized, err)
	}
	all, support, err := saved.RenderSupported()
	if err != nil || len(all) != 1 || all["clash"] == "" {
		t.Fatalf("unsupported formats silently rendered: %v, %v", all, err)
	}
	for _, item := range support {
		if item.Format == "clash" {
			if !item.Supported {
				t.Fatalf("Mihomo rejected: %+v", item)
			}
			continue
		}
		if item.Supported || !strings.Contains(strings.Join(item.ReasonCodes, ","), "node_dual_stack_mihomo") {
			t.Fatalf("format lacks explicit gate: %+v", item)
		}
		if _, err := saved.Render(item.Format); err == nil {
			t.Fatalf("%s accepted unsupported enhancement", item.Format)
		}
	}
	if !strings.Contains(all["clash"], "ipv6: true\ntcp-concurrent: true\n") {
		t.Fatalf("missing dialer options: %s", all["clash"])
	}
	if !reflect.DeepEqual(original.Groups, saved.Groups) || !reflect.DeepEqual(original.Rules, saved.Rules) {
		t.Fatal("rendering rewrote the base design")
	}
	saved.Enhancements.NodeDualStack = false
	after, err := saved.Render("clash")
	if err != nil || after != before {
		t.Fatalf("disabling enhancement did not restore prior output: %v", err)
	}
}

func TestNodeDualStackFinalProtocolDelivery(t *testing.T) {
	d := Design{Groups: []Group{{Name: "PROXY", Type: "select", Members: []string{"@all"}}}, Final: "PROXY", Enhancements: Enhancements{NodeDualStack: true}}
	tpl, err := d.Render("clash")
	if err != nil {
		t.Fatal(err)
	}
	// Domain preservation is common to every supported adapter. It does not
	// assert that all adapters race their connections (notably WG and Mieru).
	for _, protocol := range []spec.Protocol{spec.VLESS, spec.VMess, spec.Trojan, spec.Shadowsocks, spec.AnyTLS, spec.Snell, spec.SOCKS, spec.HTTP, spec.Hysteria2, spec.TUIC, spec.Mieru, spec.WireGuard} {
		t.Run(string(protocol), func(t *testing.T) {
			line := subscription.Line{Name: "Node", Host: "node.example.com", Port: 443, UUID: "11111111-1111-1111-1111-111111111111", Password: "test-password", UserID: 1,
				Inbound: spec.Inbound{Protocol: protocol, Port: 443, Cipher: "aes-128-gcm", SnellPSK: "test-key", WGPrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}
			out, err := subscription.Clash{}.RenderWith([]subscription.Line{line}, subscription.Account{}, tpl)
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err = yaml.Unmarshal(out, &doc); err != nil {
				t.Fatal(err)
			}
			if doc["ipv6"] != true || doc["tcp-concurrent"] != true {
				t.Fatalf("dialer options lost in final subscription: %s", out)
			}
			proxies, ok := doc["proxies"].([]any)
			if !ok || len(proxies) != 1 || proxies[0].(map[string]any)["server"] != line.Host {
				t.Fatalf("node domain lost: %s", out)
			}
			if _, exists := proxies[0].(map[string]any)["ip-version"]; exists {
				t.Fatal("unnecessary per-node IP version override")
			}
			line.Extra = map[string]any{"ip-version": "ipv4"}
			out, err = subscription.Clash{}.RenderWith([]subscription.Line{line}, subscription.Account{}, tpl)
			if err != nil {
				t.Fatal(err)
			}
			if err = yaml.Unmarshal(out, &doc); err != nil {
				t.Fatal(err)
			}
			if doc["proxies"].([]any)[0].(map[string]any)["ip-version"] != "ipv4" {
				t.Fatalf("explicit single-family policy overwritten: %s", out)
			}
		})
	}
}

func TestNodeDualStackDoesNotEnableDNSAAAA(t *testing.T) {
	for _, protected := range []bool{false, true} {
		d := Design{Groups: []Group{{Name: "PROXY", Type: "select", Members: []string{"@all"}}}, Final: "PROXY", Enhancements: Enhancements{NodeDualStack: true, DNSProtection: protected, DNSPolicy: "PROXY"}}
		tpl, err := d.Render("clash")
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err = yaml.Unmarshal([]byte(tpl), &doc); err != nil {
			t.Fatal(err)
		}
		if dns, ok := doc["dns"].(map[string]any); ok {
			if _, exists := dns["ipv6"]; exists {
				t.Fatal("node enhancement unexpectedly controls client-facing DNS AAAA policy")
			}
		} else if protected {
			t.Fatal("DNS protection disappeared")
		}
	}
}
