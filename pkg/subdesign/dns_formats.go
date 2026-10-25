package subdesign

import (
	"fmt"
	"strings"
)

// Stash does not implement Mihomo's #policy resolver suffix. Keep resolver
// addresses disjoint so that normal routing rules can select DNSPolicy and
// ClaudePolicy independently, including when the two policies are different.
const claudeDoH = "https://1.0.0.1/dns-query"

// DNS capability is separate from routing-rule capability. Do not silently
// publish a DIRECT DoH configuration when the user requested DNSPolicy.
func (d *Design) dnsFormatSupport(format string) (reasonCodes, reasons, warningCodes, warnings []string) {
	if !d.Enhancements.DNSProtection {
		return
	}
	switch format {
	case "stash":
		warningCodes = append(warningCodes, "dns-stash-version")
		warnings = append(warnings, "DNS protection requires Stash iOS/tvOS 3.6+ or macOS 4.3+ for independent proxy hostname resolution.")
	case "surge":
		warningCodes = append(warningCodes, "dns-surge-ip-proxies", "dns-domestic-suffix-only")
		warnings = append(warnings,
			"DNS protection requires IP-literal proxy endpoints; subscriptions containing hostname proxy endpoints are rejected to prevent Surge falling back to DIRECT.",
			"Only .cn domains use the direct domestic resolver; other domestic domains use the selected proxied DNS resolver.")
	case "egern":
		warningCodes = append(warningCodes, "dns-egern-proxy-direct", "dns-domestic-suffix-only")
		warnings = append(warnings,
			"Egern's default DNS follows the selected proxy policy; its independent proxy-DNS path remains encrypted and direct and bypasses per-domain Forward assignments.",
			"Only .cn domains use the direct domestic resolver; other domestic domains use the selected proxied DNS resolver.")
	case "surfboard":
		reasonCodes = append(reasonCodes, "dns-direct-only")
		reasons = append(reasons, "Surfboard sends encrypted DNS directly and cannot apply the selected DNS proxy policy.")
	case "loon":
		reasonCodes = append(reasonCodes, "dns-loon-policy-unverified")
		reasons = append(reasons, "Loon's documented profile cannot guarantee the selected DNS proxy policy; disabling encrypted-to-plain DNS fallback also requires an app setting.")
	case "qx":
		reasonCodes = append(reasonCodes, "dns-qx-policy-unavailable")
		reasons = append(reasons, "Quantumult X's documented DNS configuration cannot bind local encrypted DNS queries to the selected DNS proxy policy; proxied destinations use remote resolution.")
	}
	return
}

func (d *Design) writeDNS(b *strings.Builder, format string) {
	if !d.Enhancements.DNSProtection {
		return
	}
	switch format {
	case "clash":
		d.writeMihomoDNS(b, format)
	case "stash":
		d.writeStashDNS(b)
	case "surge":
		d.writeSurgeDNSHosts(b)
	case "egern":
		d.writeEgernDNS(b)
	}
}

// writeDNSGeneral writes only keys inside an existing INI General section.
// Keep the historical defaults when the enhancement is disabled.
func (d *Design) writeDNSGeneral(b *strings.Builder, format string) {
	switch format {
	case "surge", "surfboard":
		b.WriteString("dns-server = 223.5.5.5, 119.29.29.29\n")
		if format == "surge" && d.Enhancements.DNSProtection {
			// The subscription renderer must reject non-IP proxy candidates
			// before delivering this template. Surge otherwise falls back to
			// DIRECT when resolving a DNS proxy's own hostname.
			b.WriteString("# captain-dns-protection: surge-ip-only\nencrypted-dns-server = https://1.1.1.1/dns-query, https://8.8.8.8/dns-query\nencrypted-dns-follow-outbound-mode = true\n")
		}
	case "loon":
		b.WriteString("dns-server = system\n")
	}
}

// writeDNSRules must precede all user/provider rules: bootstrap and domestic
// queries must stay direct even in a BackCN design whose final policy proxies
// domestic addresses. Resolver IPs avoid another DNS lookup to dial DoH.
func (d *Design) writeDNSRules(b *strings.Builder, format string) {
	if !d.Enhancements.DNSProtection {
		return
	}
	write := func(ip, policy string) {
		switch format {
		case "stash":
			fmt.Fprintf(b, "  - %s\n", yq("IP-CIDR,"+ip+"/32,"+policy+",no-resolve"))
		case "surge":
			fmt.Fprintf(b, "IP-CIDR,%s/32,%s,no-resolve\n", ip, policy)
		case "egern":
			fmt.Fprintf(b, "  - ip_cidr:\n      match: %s/32\n      policy: %s\n      no_resolve: true\n", ip, yq(policy))
		}
	}
	for _, ip := range []string{"223.5.5.5", "119.29.29.29"} {
		write(ip, "DIRECT")
	}
	for _, ip := range []string{"1.1.1.1", "8.8.8.8"} {
		write(ip, d.Enhancements.DNSPolicy)
	}
	if d.Enhancements.Claude {
		write("1.0.0.1", d.Enhancements.ClaudePolicy)
	}
}

func (d *Design) writeSurgeDNSHosts(b *strings.Builder) {
	b.WriteString("\n[Host]\n")
	if d.Enhancements.Claude {
		for _, rule := range d.Enhancements.claudeRules() {
			fmt.Fprintf(b, "%s = server:%s\n", rule.Value, claudeDoH)
			if rule.Type == "domain" {
				// *example.com would also match notexample.com. Emit the
				// apex separately to preserve a label-aligned suffix.
				fmt.Fprintf(b, "*.%s = server:%s\n", rule.Value, claudeDoH)
			}
		}
	}
	b.WriteString("cn = server:https://223.5.5.5/dns-query\n*.cn = server:https://223.5.5.5/dns-query\n")
}

func (d *Design) writeEgernDNS(b *strings.Builder) {
	// All encrypted upstream addresses are IP literals, so their setup does
	// not need plaintext bootstrap. Egern's independent proxy-DNS path is
	// always direct and must not inherit a user rule that creates a cycle.
	b.WriteString("dns:\n  bootstrap:\n    - 223.5.5.5\n    - 119.29.29.29\n  proxy_nameservers:\n    - https://223.5.5.5/dns-query\n    - https://119.29.29.29/dns-query\n  upstreams:\n    captain-proxy-dns:\n      - https://1.1.1.1/dns-query\n      - https://8.8.8.8/dns-query\n    captain-domestic-dns:\n      - https://223.5.5.5/dns-query\n      - https://119.29.29.29/dns-query\n")
	if d.Enhancements.Claude {
		fmt.Fprintf(b, "    captain-claude-dns:\n      - %s\n", claudeDoH)
	}
	b.WriteString("  forward:\n")
	if d.Enhancements.Claude {
		for _, rule := range d.Enhancements.claudeRules() {
			kind := "domain_suffix"
			if rule.Type == "full" {
				kind = "domain"
			}
			fmt.Fprintf(b, "    - %s:\n        match: %s\n        value: captain-claude-dns\n", kind, yq(rule.Value))
		}
	}
	// A mandatory final match prevents ordinary unresolved names falling
	// through to Egern's plaintext bootstrap servers.
	b.WriteString("    - domain_suffix:\n        match: cn\n        value: captain-domestic-dns\n    - domain_wildcard:\n        match: '*'\n        value: captain-proxy-dns\n")
}

func (d *Design) writeStashDNS(b *strings.Builder) {
	b.WriteString("dns:\n  follow-rule: true\n  default-nameserver:\n    - https://223.5.5.5/dns-query\n  proxy-server-nameserver:\n    - https://223.5.5.5/dns-query\n    - https://119.29.29.29/dns-query\n  nameserver:\n    - https://1.1.1.1/dns-query\n    - https://8.8.8.8/dns-query\n  fake-ip-filter:\n    - '+.lan'\n    - '+.local'\n    - '+.home.arpa'\n    - '+.msftconnecttest.com'\n    - '+.msftncsi.com'\n  nameserver-policy:\n    '+.cn':\n      - https://223.5.5.5/dns-query\n    'geosite:cn':\n      - https://223.5.5.5/dns-query\n")
	if d.Enhancements.Claude {
		for _, rule := range d.Enhancements.claudeRules() {
			domain := rule.Value
			if rule.Type == "domain" {
				domain = "+." + domain
			}
			fmt.Fprintf(b, "    %s:\n      - %s\n", yq(domain), yq(claudeDoH))
		}
	}
}

func (d *Design) writeMihomoDNS(b *strings.Builder, format string) {
	if format != "clash" || !d.Enhancements.DNSProtection {
		return
	}
	policy := d.Enhancements.DNSPolicy
	b.WriteString("dns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  respect-rules: true\n  default-nameserver:\n    - https://223.5.5.5/dns-query#DIRECT\n  proxy-server-nameserver:\n    - https://223.5.5.5/dns-query#DIRECT\n    - https://119.29.29.29/dns-query#DIRECT\n  direct-nameserver:\n    - https://223.5.5.5/dns-query#DIRECT\n    - https://119.29.29.29/dns-query#DIRECT\n  direct-nameserver-follow-policy: false\n  nameserver:\n")
	for _, resolver := range []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"} {
		fmt.Fprintf(b, "    - %s\n", yq(resolver+"#"+policy))
	}
	b.WriteString("  fake-ip-filter:\n    - '+.lan'\n    - '+.local'\n    - '+.home.arpa'\n    - '+.msftconnecttest.com'\n    - '+.msftncsi.com'\n  nameserver-policy:\n    '+.cn':\n      - https://223.5.5.5/dns-query#DIRECT\n    'geosite:cn':\n      - https://223.5.5.5/dns-query#DIRECT\n")
	if d.Enhancements.Claude {
		for _, rule := range d.Enhancements.claudeRules() {
			domain := rule.Value
			if rule.Type == "domain" {
				domain = "+." + domain
			}
			fmt.Fprintf(b, "    %s:\n      - %s\n", yq(domain), yq("https://1.1.1.1/dns-query#"+d.Enhancements.ClaudePolicy))
		}
	}
}
