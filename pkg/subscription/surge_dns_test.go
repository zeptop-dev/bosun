package subscription

import (
	"errors"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestSurgeManagedDNSCannotFallbackForDomainProxies(t *testing.T) {
	tpl := "# captain-dns-protection: surge-ip-only\n[Proxy]\n{{proxies}}\n[Proxy Group]\nDNS = select, {{proxy_names}}\n"
	line := Line{Name: "Proxy", Host: "node.example.com", Port: 443, Password: "test", Inbound: spec.Inbound{Protocol: spec.Trojan}}
	if out, err := (Surge{}).RenderWith([]Line{line}, Account{}, tpl); !errors.Is(err, ErrSurgeDNSHostname) || len(out) != 0 {
		t.Fatal("hostname proxy must not produce a DNS-protected profile that falls back to DIRECT")
	}
	for _, host := range []string{"192.0.2.10", "2001:db8::10", "[2001:db8::10]"} {
		line.Host = host
		if out, err := (Surge{}).RenderWith([]Line{line}, Account{}, tpl); err != nil || !strings.Contains(string(out), host) {
			t.Fatalf("IP proxy %q: %v", host, err)
		}
	}
	line.Host = "node.example.com"
	if _, err := (Surge{}).RenderWith([]Line{line}, Account{}, "[Proxy]\n{{proxies}}"); err != nil {
		t.Fatal("ordinary templates must keep allowing hostname proxies")
	}
	line.Inbound.Protocol = spec.VLESS // omitted by the existing Surge renderer
	if _, err := (Surge{}).RenderWith([]Line{line}, Account{}, tpl); err != nil {
		t.Fatal("an omitted protocol must not block an otherwise safe profile")
	}
	for _, injected := range []string{
		"[Proxy]\nStatic = trojan, node.example.com, 443, password=test\n",
		"[Proxy Group]\nDNS = select, policy-path=https://example.com/proxies\n",
		"[Proxy]\nStatic = trojan, [[2001:db8::10]], 443, password=test\n",
		"[Proxy]\nStatic = external, 192.0.2.10, 443\n",
		"[Proxy]\n#!include https://example.com/proxies.conf\n",
		"[General]\nloglevel=notify\n[Proxy] # comment\nStatic = trojan, node.example.com, 443, password=test\n",
		"[General]\n[ Proxy ]\nStatic = trojan, node.example.com, 443, password=test\n",
	} {
		if out, err := (Surge{}).RenderWith(nil, Account{}, tpl+injected); !errors.Is(err, ErrSurgeDNSHostname) || len(out) != 0 {
			t.Fatal("edited managed template bypassed endpoint validation")
		}
	}
	if _, err := (Surge{}).RenderWith(nil, Account{}, tpl+"[Proxy]\nStatic = trojan, 192.0.2.10, 443, password=test\n"); err != nil {
		t.Fatal("static IP proxy should remain supported")
	}
}
