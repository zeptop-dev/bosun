package subdesign

import (
	"net"
	"net/url"
	"path"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func dnsTestDesign(t *testing.T) Design {
	t.Helper()
	d := Design{
		Groups: []Group{
			{Name: "DNS only", Type: "select", Members: []string{"@all"}},
			{Name: "Claude only", Type: "select", Members: []string{"@all"}},
		},
		Final:        "DNS only",
		Enhancements: Enhancements{DNSProtection: true, DNSPolicy: "DNS only", Claude: true, ClaudePolicy: "Claude only", ClaudeRules: syntheticClaudeRules()},
	}
	effective, err := d.Effective()
	if err != nil {
		t.Fatal(err)
	}
	return effective
}

// Model both the query selection and the outbound selection; checking only
// that a DoH URL is present would miss Stash's default DIRECT behavior and
// policy collisions between general DNS and the pinned Claude domain list.
func TestStashDNSPaths(t *testing.T) {
	d, _ := Preset("basic")
	d.Groups = append(d.Groups,
		Group{Name: "DNS only", Type: "select", Members: []string{"@all"}},
		Group{Name: "Claude only", Type: "select", Members: []string{"@all"}},
	)
	d.Enhancements = Enhancements{DNSProtection: true, DNSPolicy: "DNS only", Claude: true, ClaudePolicy: "Claude only", ClaudeRules: syntheticClaudeRules()}
	effective, err := d.Effective()
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	effective.writeDNS(&b, "stash")
	b.WriteString("rules:\n")
	effective.writeDNSRules(&b, "stash")
	// A BackCN-style catch-all must not catch bootstrap/domestic DNS traffic.
	b.WriteString("  - 'MATCH,Claude only'\n")
	var doc struct {
		DNS struct {
			FollowRule  bool                `yaml:"follow-rule"`
			Bootstrap   []string            `yaml:"default-nameserver"`
			Proxy       []string            `yaml:"proxy-server-nameserver"`
			Nameservers []string            `yaml:"nameserver"`
			Policies    map[string][]string `yaml:"nameserver-policy"`
		} `yaml:"dns"`
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal([]byte(b.String()), &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.DNS.FollowRule || len(doc.DNS.Bootstrap) == 0 || len(doc.DNS.Proxy) == 0 {
		t.Fatal("missing routed DNS or independent node/bootstrap resolution")
	}
	policyFor := func(resolver string) string {
		u, err := url.Parse(resolver)
		if err != nil || u.Scheme != "https" || u.Fragment != "" {
			t.Fatalf("invalid Stash resolver %q", resolver)
		}
		for _, rule := range doc.Rules {
			p := strings.Split(rule, ",")
			if p[0] == "IP-CIDR" && p[1] == u.Hostname()+"/32" && p[len(p)-1] == "no-resolve" {
				return p[2]
			}
		}
		return "unrouted"
	}
	for _, resolver := range append(append([]string{}, doc.DNS.Proxy...), doc.DNS.Bootstrap...) {
		if got := policyFor(resolver); got != "DIRECT" {
			t.Fatalf("bootstrap resolver %s routes to %s", resolver, got)
		}
	}
	for _, key := range []string{"+.cn", "geosite:cn"} {
		for _, resolver := range doc.DNS.Policies[key] {
			if got := policyFor(resolver); got != "DIRECT" {
				t.Fatalf("domestic resolver routes to %s", got)
			}
		}
	}
	for _, resolver := range doc.DNS.Nameservers {
		if got := policyFor(resolver); got != "DNS only" {
			t.Fatalf("general DNS uses %s", got)
		}
	}
	for _, key := range []string{"+.service.example.com", "login.example.net"} {
		resolvers, ok := doc.DNS.Policies[key]
		if !ok || len(resolvers) == 0 {
			t.Fatalf("snapshot DNS entry missing: %s", key)
		}
		for _, resolver := range resolvers {
			if got := policyFor(resolver); got != "Claude only" {
				t.Fatalf("Claude DNS uses %s", got)
			}
		}
	}
	if _, ok := doc.DNS.Policies["+.login.example.net"]; ok {
		t.Fatal("exact snapshot rule widened into a suffix")
	}
	for _, forbidden := range []string{"ipv6:", "tun:", "#DIRECT", "#DNS only", "respect-rules:"} {
		if strings.Contains(b.String(), forbidden) {
			t.Fatalf("Stash received unsupported or unrelated option %q", forbidden)
		}
	}
	if !reflect.DeepEqual(d.Enhancements.ClaudeRules, syntheticClaudeRules()) {
		t.Fatal("DNS rendering mutated the pinned snapshot")
	}
}

func TestDNSDisabledDoesNotEmitEnhancement(t *testing.T) {
	d, _ := Preset("basic")
	for _, format := range Formats {
		var b strings.Builder
		d.writeDNS(&b, format)
		d.writeDNSRules(&b, format)
		if b.Len() != 0 {
			t.Fatalf("disabled %s DNS enhancement rendered: %s", format, b.String())
		}
	}
	for format, want := range map[string]string{"surge": "dns-server = 223.5.5.5, 119.29.29.29\n", "surfboard": "dns-server = 223.5.5.5, 119.29.29.29\n", "loon": "dns-server = system\n"} {
		var b strings.Builder
		d.writeDNSGeneral(&b, format)
		if b.String() != want {
			t.Fatalf("%s default DNS changed: %s", format, b.String())
		}
	}
}

func TestSurgeDNSBindingsAndDeliveryGuard(t *testing.T) {
	d := dnsTestDesign(t)
	var general, hosts, rules strings.Builder
	d.writeDNSGeneral(&general, "surge")
	d.writeDNS(&hosts, "surge")
	d.writeDNSRules(&rules, "surge")
	for _, required := range []string{"# captain-dns-protection: surge-ip-only", "encrypted-dns-follow-outbound-mode = true", "encrypted-dns-server = https://1.1.1.1/dns-query, https://8.8.8.8/dns-query"} {
		if !strings.Contains(general.String(), required) {
			t.Fatalf("Surge is missing DNS routing/guard: %s", required)
		}
	}
	for _, required := range []string{"IP-CIDR,223.5.5.5/32,DIRECT,no-resolve", "IP-CIDR,1.1.1.1/32,DNS only,no-resolve", "IP-CIDR,1.0.0.1/32,Claude only,no-resolve"} {
		if !strings.Contains(rules.String(), required) {
			t.Fatalf("Surge is missing resolver outbound: %s", required)
		}
	}
	resolve := func(domain string) string {
		for _, line := range strings.Split(hosts.String(), "\n") {
			parts := strings.SplitN(line, " = server:", 2)
			if len(parts) != 2 {
				continue
			}
			if ok, _ := path.Match(parts[0], domain); ok {
				return parts[1]
			}
		}
		return "general"
	}
	for name, want := range map[string]string{
		"service.example.com": claudeDoH, "api.service.example.com": claudeDoH,
		"notservice.example.com": "general", "login.example.net": claudeDoH,
		"sub.login.example.net": "general", "example.cn": "https://223.5.5.5/dns-query",
		"example.com": "general",
	} {
		if got := resolve(name); got != want {
			t.Errorf("Surge resolves %s via %s, want %s", name, got, want)
		}
	}
	for _, unsupported := range []string{"ipv6", "tun-", "server:system", "server:223.5.5.5"} {
		if strings.Contains(general.String()+hosts.String(), unsupported) {
			t.Fatalf("unexpected DNS option: %s", unsupported)
		}
	}
}

func TestEgernDNSForwardAndIndependentProxyPath(t *testing.T) {
	d := dnsTestDesign(t)
	var b strings.Builder
	d.writeDNS(&b, "egern")
	b.WriteString("rules:\n")
	d.writeDNSRules(&b, "egern")
	var doc struct {
		DNS struct {
			Proxy     []string                                   `yaml:"proxy_nameservers"`
			Upstreams map[string][]string                        `yaml:"upstreams"`
			Forward   []map[string]struct{ Match, Value string } `yaml:"forward"`
		} `yaml:"dns"`
		Rules []map[string]struct {
			Match, Policy string
			NoResolve     bool `yaml:"no_resolve"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal([]byte(b.String()), &doc); err != nil {
		t.Fatal(err)
	}
	for _, resolver := range doc.DNS.Proxy {
		if resolver != "https://223.5.5.5/dns-query" && resolver != "https://223.6.6.6/dns-query" {
			t.Fatalf("proxy DNS cannot bootstrap independently: %s", resolver)
		}
	}
	if len(doc.DNS.Proxy) == 0 {
		t.Fatal("proxy DNS inherits ordinary query routing")
	}
	policyFor := func(resolver string) string {
		u, err := url.Parse(resolver)
		if err != nil || u.Scheme != "https" || net.ParseIP(u.Hostname()) == nil {
			t.Fatalf("resolver needs plaintext hostname bootstrap: %s", resolver)
		}
		for _, item := range doc.Rules {
			if r, ok := item["ip_cidr"]; ok && r.Match == u.Hostname()+"/32" && r.NoResolve {
				return r.Policy
			}
		}
		return "unrouted"
	}
	resolve := func(domain string) string {
		for _, item := range doc.DNS.Forward {
			for kind, r := range item {
				match := kind == "domain" && r.Match == domain
				match = match || kind == "domain_suffix" && (r.Match == domain || strings.HasSuffix(domain, "."+r.Match))
				match = match || kind == "domain_wildcard" && r.Match == "*"
				if match {
					resolvers := doc.DNS.Upstreams[r.Value]
					if len(resolvers) == 0 {
						t.Fatalf("missing upstream %q", r.Value)
					}
					p := policyFor(resolvers[0])
					for _, resolver := range resolvers {
						if policyFor(resolver) != p {
							t.Fatal("racing resolvers use different policies")
						}
					}
					return p
				}
			}
		}
		return "plaintext-bootstrap"
	}
	for name, want := range map[string]string{
		"service.example.com": "Claude only", "api.service.example.com": "Claude only",
		"notservice.example.com": "DNS only", "login.example.net": "Claude only",
		"sub.login.example.net": "DNS only", "example.cn": "DIRECT", "example.com": "DNS only",
	} {
		if got := resolve(name); got != want {
			t.Errorf("Egern resolves %s via %s, want %s", name, got, want)
		}
	}
	for _, forbidden := range []string{"ipv6:", "tun:", "public_ip_lookup_url:", "skip_tls_verify:"} {
		if strings.Contains(b.String(), forbidden) {
			t.Fatalf("unexpected DNS option: %s", forbidden)
		}
	}
}
