package subscription

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
	"github.com/zeptop-dev/bosun/pkg/wg"
	"gopkg.in/yaml.v3"
)

func ipPolicyLine(mode string) Line {
	return Line{Name: "family node", Host: "node.example.com", Port: 443, IPVersion: mode, UUID: "11111111-1111-1111-1111-111111111111", Password: "test-password", Inbound: spec.Inbound{Protocol: spec.Trojan, TLS: &spec.TLS{Mode: spec.TLSStandard, ServerName: "tls.example.com"}}}
}

func TestIPVersionValidation(t *testing.T) {
	for _, mode := range []string{"", "ipv4", "ipv6", "dual"} {
		if err := ValidateIPVersion("node.example.com", mode, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ host, mode string }{{"node.example.com", "v4"}, {"192.0.2.10", "ipv6"}, {"2001:db8::1", "ipv4"}, {"192.0.2.10", "dual"}, {"", "dual"}, {"https://example.com", "ipv4"}, {"host\x00.example.com", "ipv4"}, {"fe80::1%en0", "ipv6"}, {"[2001:db8::1", "ipv6"}, {"\nnode.example.com", "dual"}} {
		if ValidateIPVersion(tc.host, tc.mode, nil) == nil {
			t.Fatalf("accepted %#v", tc)
		}
	}
	for _, tc := range []struct{ host, mode string }{{"192.0.2.10", "ipv4"}, {"2001:db8::1", "ipv6"}, {"[2001:db8::1]", "ipv6"}, {"::ffff:192.0.2.10", "ipv4"}} {
		if err := ValidateIPVersion(tc.host, tc.mode, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, key := range []string{"ip-version", "domain_resolver", "domain_strategy", "dialer-proxy", "detour", "server", "type", "plugin-opts", "transport", "realm", "peers", "IP-Version", "DOMAIN-RESOLVER", "Dialer_Proxy", "Server", "name", "tag"} {
		extra := map[string]any{key: "override"}
		if ValidateIPVersion("node.example.com", "ipv4", extra) == nil {
			t.Fatalf("accepted conflicting %s", key)
		}
		if err := ValidateIPVersion("node.example.com", "", extra); err != nil {
			t.Fatalf("legacy changed: %v", err)
		}
	}
}

func TestIPVersionClashAndSingBox(t *testing.T) {
	for _, mode := range []string{"", "ipv4", "ipv6", "dual"} {
		t.Run(mode, func(t *testing.T) {
			line := ipPolicyLine(mode)
			out, err := (Clash{}).Render([]Line{line}, Account{})
			if err != nil {
				t.Fatal(err)
			}
			var cfg map[string]any
			if err = yaml.Unmarshal(out, &cfg); err != nil {
				t.Fatal(err)
			}
			p := cfg["proxies"].([]any)[0].(map[string]any)
			if p["server"] != line.Host || p["servername"] != "tls.example.com" {
				t.Fatalf("host or TLS mutated: %v", p)
			}
			if mode == "" {
				if _, ok := p["ip-version"]; ok {
					t.Fatal("changed legacy")
				}
				if _, ok := cfg["ipv6"]; ok {
					t.Fatal("changed global legacy")
				}
			} else if p["ip-version"] != mode {
				t.Fatal(p)
			}
			if mode == "ipv6" || mode == "dual" {
				if cfg["ipv6"] != true {
					t.Fatal("IPv6 not enabled")
				}
			}
			out, err = (SingBox{}).Render([]Line{line}, Account{})
			if err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(out, &cfg); err != nil {
				t.Fatal(err)
			}
			p = cfg["outbounds"].([]any)[2].(map[string]any)
			if _, bad := p["ip-version"]; bad {
				t.Fatal("mihomo field leaked")
			}
			if mode == "" {
				if _, ok := p["domain_resolver"]; ok {
					t.Fatal("changed legacy")
				}
				return
			}
			resolver := p["domain_resolver"].(map[string]any)
			if resolver["server"] != "local" {
				t.Fatal(resolver)
			}
			if mode == "dual" {
				if _, set := resolver["strategy"]; set {
					t.Fatal(resolver)
				}
			} else if resolver["strategy"] != mode+"_only" {
				t.Fatal(resolver)
			}
		})
	}
}

func TestIPVersionShadowTLSCarrier(t *testing.T) {
	line := ipPolicyLine("ipv6")
	line.Inbound = spec.Inbound{Protocol: spec.Shadowsocks, Cipher: "aes-128-gcm", ShadowTLS: &spec.ShadowTLS{Handshake: "tls.example.com:443"}}
	out, err := (SingBox{}).Render([]Line{line}, Account{})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct{ Outbounds []map[string]any }
	if err = json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	carrier, inner := cfg.Outbounds[2], cfg.Outbounds[3]
	if carrier["type"] != "shadowtls" || carrier["domain_resolver"].(map[string]any)["strategy"] != "ipv6_only" {
		t.Fatal(carrier)
	}
	if _, bad := inner["domain_resolver"]; bad {
		t.Fatal("resolver belongs on actual carrier")
	}
}

func TestIPVersionUnsupportedNeverWeakensOnlyPolicy(t *testing.T) {
	line := ipPolicyLine("ipv6")
	for _, format := range []string{"uri", "stash", "loon", "qx", "egern", "surfboard"} {
		t.Run(format, func(t *testing.T) {
			line := ipPolicyLine("ipv6")
			if IPVersionSupport(format, line) != "unsupported_family_policy" {
				t.Fatal("claimed support")
			}
			out, err := Pick(format, "").Render([]Line{line}, Account{})
			if err != nil {
				t.Fatal(err)
			}
			if format == "uri" || format == "qx" {
				out, err = base64.StdEncoding.DecodeString(string(out))
				if err != nil {
					t.Fatal(err)
				}
			}
			if strings.Contains(string(out), line.Host) {
				t.Fatal("forced hostname escaped")
			}
			line.IPVersion = "dual"
			if IPVersionSupport(format, line) != "" || !IPVersionUsesClientDefault(format, line) {
				t.Fatal("native dual missing")
			}
			out, err = Pick(format, "").Render([]Line{line}, Account{})
			if err != nil {
				t.Fatal(err)
			}
			if format == "uri" || format == "qx" {
				out, _ = base64.StdEncoding.DecodeString(string(out))
			}
			if !strings.Contains(string(out), line.Host) {
				t.Fatal("native domain missing")
			}
			line.IPVersion = "ipv6"
			line.Host = "2001:db8::10"
			if IPVersionSupport(format, line) != "" {
				t.Fatal("literal does not need DNS selection")
			}
			line.Host = "node.example.com"
		})
	}
	if ShareURI(line) != "" {
		t.Fatal("copy link bypassed restriction")
	}
	line.Host = "2001:db8::10"
	if !strings.Contains(ShareURI(line), "@[2001:db8::10]:443") {
		t.Fatal("bad IPv6 URL")
	}
	line.Inbound.Protocol = spec.WireGuard
	line.Host = "node.example.com"
	if IPVersionSupport("singbox", line) != "unsupported_family_policy" || IPVersionSupport("clash", line) != "unsupported_family_policy" || WGConf(line) != "" {
		t.Fatal("unverified WG endpoint bypass")
	}
}

func TestIPVersionTemplateConflictAndLegacy(t *testing.T) {
	for _, mode := range []string{"ipv6", "dual"} {
		line := ipPolicyLine(mode)
		for _, tc := range []struct{ format, tpl string }{{"clash", "ipv6: false\n"}, {"clash", "ipv6: null\n"}, {"surge", "[General]\nipv6 = false\n[Proxy]\n{{proxies}}\n"}} {
			_, err := Pick(tc.format, "").RenderWith([]Line{line}, Account{}, tc.tpl)
			if !errors.Is(err, ErrIPVersionTemplateConflict) {
				t.Fatalf("%s: %v", tc.format, err)
			}
			line.IPVersion = ""
			if _, err = Pick(tc.format, "").RenderWith([]Line{line}, Account{}, tc.tpl); err != nil {
				t.Fatalf("legacy rejected: %v", err)
			}
			line.IPVersion = mode
		}
	}
	line := ipPolicyLine("ipv6")
	line.Inbound.Protocol = spec.VLESS // Surge omits this protocol.
	if _, err := (Surge{}).RenderWith([]Line{line}, Account{}, "[General]\nipv6=false\n[Proxy]\n{{proxies}}"); err != nil {
		t.Fatal("omitted protocol changed global behavior", err)
	}
}

func TestIPVersionSurge(t *testing.T) {
	for _, mode := range []string{"ipv4", "ipv6", "dual"} {
		line := ipPolicyLine(mode)
		out, err := (Surge{}).Render([]Line{line}, Account{})
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"ipv4": "v4-only", "ipv6": "v6-only", "dual": "dual"}[mode]
		if !strings.Contains(string(out), "ip-version="+want) {
			t.Fatal(string(out))
		}
		if mode != "ipv4" && !strings.Contains(string(out), "ipv6 = true") {
			t.Fatal("IPv6 unavailable")
		}
	}
}

func TestIPVersionLiteralAndWireGuardScope(t *testing.T) {
	line := ipPolicyLine("ipv6")
	line.Host = " [2001:db8::10] "
	for _, format := range []string{"clash", "singbox", "stash"} {
		out, err := Pick(format, "").Render([]Line{line}, Account{})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "[2001:db8") {
			t.Fatalf("%s map server has brackets", format)
		}
		if !strings.Contains(string(out), "2001:db8::10") {
			t.Fatalf("%s missing address", format)
		}
	}
	if !strings.Contains(ShareURI(line), "@[2001:db8::10]:443") {
		t.Fatal("bad literal URI", ShareURI(line))
	}
	priv, pub, err := wg.Keypair()
	if err != nil {
		t.Fatal(err)
	}
	line.Inbound = spec.Inbound{Protocol: spec.WireGuard, WGPrivateKey: priv, WGPublicKey: pub}
	line.UserID = 1
	if !strings.Contains(WGConf(line), "Endpoint = [2001:db8::10]:443") {
		t.Fatal("bad literal WG endpoint")
	}
	for _, mode := range []string{"ipv6", "dual"} {
		line.IPVersion = mode
		if mode == "dual" {
			line.Host = "node.example.com"
		}
		out, err := (Clash{}).Render([]Line{line}, Account{})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "ip-version:") {
			t.Fatal("endpoint policy leaked into tunneled target DNS")
		}
	}
}
