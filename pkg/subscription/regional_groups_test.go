package subscription

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
	"gopkg.in/yaml.v3"
)

func TestRegionSelectorUsesExitMetadataAndUndecoratedName(t *testing.T) {
	cases := []struct {
		name Named
		want string
	}{
		{Named{Name: "🇯🇵 Japan", Region: " hk "}, "HK"},
		{Named{Name: "🇭🇰 host-generated flag", RegionName: "IPLC"}, ""},
		{Named{Name: "US presentation prefix", RegionName: "Tokyo Premium"}, "JP"},
		{Named{Name: "Home broadband", Region: "DE"}, "DE"},
		{Named{Name: "HK CDT 01"}, "HK"},
		{Named{Name: "🇯🇵 01"}, "JP"},
		{Named{Name: "US West"}, "US"},
		{Named{Name: "Australia"}, "AU"},
		{Named{Name: "Business 01"}, ""},
		{Named{Name: "最新节点"}, ""},
		{Named{Name: "Hong Kong 02"}, "HK"},
		{Named{Name: "香港至日本"}, ""},
		{Named{Name: "🇭🇰 → 🇯🇵"}, ""},
		{Named{Name: "JP", Region: "invalid"}, "JP"},
	}
	for _, tc := range cases {
		if got := namedRegion(tc.name); got != tc.want {
			t.Errorf("%+v: got region %q, want %q", tc.name, got, tc.want)
		}
	}
	names := []Named{{Name: "IPLC", Region: "HK"}, {Name: "Australia"}, {Name: "US West"}}
	for selector, want := range map[string][]string{
		"{{proxy_names:region=HK}}": {"IPLC"},
		"{{proxy_names:region=US}}": {"US West"},
		"{{proxy_names:region=}}":   {},
		"{{proxy_names:region=hk}}": {},
		"{{proxy_names:match=US}}":  {"Australia", "US West"}, // Legacy regex remains unchanged.
	} {
		got, ok := expandNames(selector, names)
		if !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %v, %v; want %v", selector, got, ok, want)
		}
	}
}

func TestRegionalGroupsAcrossFormats(t *testing.T) {
	for _, renderer := range []Renderer{Clash{}, Stash{}, Surge{}, Surfboard{}, Loon{}, QuantumultX{}, Egern{}} {
		t.Run(renderer.Name(), func(t *testing.T) {
			lines := []Line{
				regionalLine("IPLC", "HK"),
				regionalLine("🇯🇵 Explicit exit", "HK"),
				regionalLine("HK CDT 02", ""),
				regionalLine("Other region", "JP"),
				regionalLine("🇭🇰 Entry location", ""),
			}
			lines[4].RegionName = "Home broadband"
			groups := renderRegionalGroups(t, renderer, regionalTemplate(renderer.Name(), false), lines)
			wantHK := []string{"HK Auto", "IPLC", "🇯🇵 Explicit exit", "HK CDT 02"}
			if !reflect.DeepEqual(groups["HK"].members, wantHK) || !reflect.DeepEqual(groups["HK Auto"].members, wantHK[1:]) {
				t.Fatalf("HK membership: %+v", groups)
			}
			if !reflect.DeepEqual(groups["JP"].members, []string{"JP Auto", "Other region"}) {
				t.Fatalf("JP membership: %+v", groups["JP"])
			}

			// One remaining region: remove both empty JP groups and the parent reference.
			groups = renderRegionalGroups(t, renderer, regionalTemplate(renderer.Name(), false), lines[:3])
			if _, exists := groups["JP"]; exists {
				t.Fatalf("empty region remains: %+v", groups)
			}
			if _, exists := groups["JP Auto"]; exists || !reflect.DeepEqual(groups["Main"].members, []string{"HK"}) {
				t.Fatalf("empty child or dangling reference: %+v", groups)
			}

			// A rule explicitly targeting an empty region still resolves to REJECT.
			groups = renderRegionalGroups(t, renderer, regionalTemplate(renderer.Name(), true), lines[:3])
			if got := groups["JP"]; got.kind != "select" || !reflect.DeepEqual(got.members, []string{"REJECT"}) {
				t.Fatalf("explicit empty target must reject: %+v", groups)
			}
			if _, exists := groups["JP Auto"]; exists {
				t.Fatalf("unused empty child remains: %+v", groups)
			}

			// Empty final parent must not become an invalid or implicit DIRECT group.
			groups = renderRegionalGroups(t, renderer, regionalTemplate(renderer.Name(), false), nil)
			if len(groups) != 1 || groups["Main"].kind != "select" || !reflect.DeepEqual(groups["Main"].members, []string{"REJECT"}) {
				t.Fatalf("all-empty final parent: %+v", groups)
			}
		})
	}
}

func TestRegionalGroupsUseOnlySupportedClientCandidates(t *testing.T) {
	line := regionalLine("HK VLESS", "HK")
	line.Inbound = spec.Inbound{Protocol: spec.VLESS}
	for _, renderer := range []Renderer{Clash{}, Surfboard{}} {
		groups := renderRegionalGroups(t, renderer, regionalTemplate(renderer.Name(), false), []Line{line})
		_, hasHK := groups["HK"]
		if hasHK != (renderer.Name() == "clash") {
			t.Fatalf("%s: unsupported node kept a region alive: %+v", renderer.Name(), groups)
		}
	}
}

func TestEditedRegionRuleTargetsRemainReject(t *testing.T) {
	for _, renderer := range []Renderer{Clash{}, Stash{}, Surge{}, Surfboard{}, Loon{}, QuantumultX{}, Egern{}} {
		t.Run(renderer.Name(), func(t *testing.T) {
			// Simulate a text edit adding a direct region rule without regenerating
			// the old marker, whose protected bit was still false.
			unprotectedMarker := strings.Split(regionalTemplate(renderer.Name(), false), "\n")[1]
			tpl := regionalTemplate(renderer.Name(), true)
			tpl = strings.Replace(tpl, strings.Split(tpl, "\n")[1], unprotectedMarker, 1)
			groups := renderRegionalGroups(t, renderer, tpl, []Line{regionalLine("IPLC", "HK")})
			if got := groups["JP"]; got.kind != "select" || !reflect.DeepEqual(got.members, []string{"REJECT"}) {
				t.Fatalf("edited rule target removed: %+v", groups)
			}
		})
	}
}

func TestRegionalDNSRemoteRuleAndDialerReferences(t *testing.T) {
	for _, ref := range []string{
		"https://1.1.1.1/dns-query#JP",
		"https://1.1.1.1/dns-query#%4A%50&ecs=0.0.0.0/0",
		"https://example.com/rules, force-policy=JP, enabled=true",
		"https://example.com/rules, policy=JP",
		"Private proxy = socks5, 198.51.100.20, 443, underlying-proxy=JP",
	} {
		if !regionalReference(ref, "JP") {
			t.Errorf("missing region reference: %s", ref)
		}
	}
	for _, value := range []string{"JP Auto", "HK", "https://example.com/JP.list", "DOMAIN-SUFFIX,JP.example.com,Main"} {
		if regionalReference(value, "JP") {
			t.Errorf("substring is not a policy reference: %s", value)
		}
	}
	tpl := regionalTemplate("clash", false) + "dns:\n  nameserver: ['https://1.1.1.1/dns-query#JP']\n"
	groups := renderRegionalGroups(t, Clash{}, tpl, []Line{regionalLine("IPLC", "HK")})
	if !reflect.DeepEqual(groups["JP"].members, []string{"REJECT"}) {
		t.Fatalf("DNS target was removed: %+v", groups)
	}
	line := regionalLine("IPLC", "HK")
	line.Extra = map[string]any{"dialer-proxy": "JP"}
	groups = renderRegionalGroups(t, Clash{}, regionalTemplate("clash", false), []Line{line})
	if !reflect.DeepEqual(groups["JP"].members, []string{"REJECT"}) {
		t.Fatalf("proxy dialer target was removed: %+v", groups)
	}
	for _, renderer := range []Renderer{Surge{}, Surfboard{}, Loon{}, QuantumultX{}} {
		tpl := regionalTemplate(renderer.Name(), false) + "\n[Remote Rule]\nhttps://example.com/rules, policy=JP\n"
		groups := renderRegionalGroups(t, renderer, tpl, []Line{regionalLine("IPLC", "HK")})
		if !reflect.DeepEqual(groups["JP"].members, []string{"REJECT"}) {
			t.Fatalf("%s remote rule target was removed: %+v", renderer.Name(), groups)
		}
	}
}

func TestRegionalMetadataIsExplicitBoundedAndAtomic(t *testing.T) {
	valid := regionalTemplate("clash", false)
	markerLine := strings.Split(valid, "\n")[1]
	encode := func(s string) string { return designerRegionMarker + base64.RawURLEncoding.EncodeToString([]byte(s)) }
	invalid := []string{
		strings.ReplaceAll(valid, designerEmptyMarker, ""),
		strings.ReplaceAll(valid, markerLine, designerRegionMarker+"broken"),
		strings.ReplaceAll(valid, markerLine, encode(`[{"name":"HK","region":"HK"},{"name":"HK","region":"JP"}]`)),
		strings.ReplaceAll(valid, markerLine, encode(`[{"name":"HK","region":"invalid"}]`)),
		strings.ReplaceAll(valid, markerLine, encode(`[{"name":"HK","region":"HK","unknown":true}]`)),
		strings.ReplaceAll(valid, markerLine, encode(`[{"name":"HK","region":"HK"}] {}`)),
		valid + "\n" + markerLine,
		strings.ReplaceAll(valid, markerLine, designerRegionMarker+"\n"+markerLine),
		strings.ReplaceAll(valid, markerLine, designerRegionMarker+strings.Repeat("A", 128*1024+1)),
	}
	for i, tpl := range invalid {
		if regionalGroups(tpl, nil).active {
			t.Errorf("invalid marker %d activated pruning", i)
		}
	}
	// No marker means handwritten templates retain both regional group identities.
	without := strings.ReplaceAll(valid, markerLine, "")
	groups := renderRegionalGroups(t, Clash{}, without, nil)
	if _, exists := groups["HK"]; !exists {
		t.Fatal("unmarked group removed")
	}
	if _, exists := groups["JP"]; !exists {
		t.Fatal("unmarked group removed")
	}
}

func regionalLine(name, region string) Line {
	return Line{Name: name, Region: region, Host: "hk-entry.example.com", Port: 443, Password: "test", UUID: "11111111-1111-1111-1111-111111111111", Inbound: spec.Inbound{Protocol: spec.Shadowsocks, Cipher: "aes-128-gcm"}}
}

func regionalTemplate(format string, protectJP bool) string {
	metadata, _ := json.Marshal([]regionalGroup{{Name: "HK", Region: "HK"}, {Name: "HK Auto", Region: "HK"}, {Name: "JP", Region: "JP", Protected: protectJP}, {Name: "JP Auto", Region: "JP"}})
	prefix := designerEmptyMarker + "\n" + designerRegionMarker + base64.RawURLEncoding.EncodeToString(metadata) + "\n"
	var body string
	switch format {
	case "clash", "stash":
		body = `proxy-groups:
  - {name: Main, type: select, proxies: [HK, JP]}
  - {name: HK, type: select, proxies: [HK Auto, "{{proxy_names:region=HK}}"]}
  - {name: HK Auto, type: url-test, proxies: ["{{proxy_names:region=HK}}"], url: "https://www.gstatic.com/generate_204", interval: 300, tolerance: 50}
  - {name: JP, type: select, proxies: [JP Auto, "{{proxy_names:region=JP}}"]}
  - {name: JP Auto, type: url-test, proxies: ["{{proxy_names:region=JP}}"], url: "https://www.gstatic.com/generate_204", interval: 300, tolerance: 50}
rules: ["DOMAIN-SUFFIX,example.com,JP", "MATCH,Main"]
`
	case "egern":
		body = `policy_groups:
  - select: {name: Main, policies: [HK, JP]}
  - select: {name: HK, policies: [HK Auto, "{{proxy_names:region=HK}}"]}
  - auto_test: {name: HK Auto, policies: ["{{proxy_names:region=HK}}"], latency_test_url: "https://www.gstatic.com/generate_204", interval: 300}
  - select: {name: JP, policies: [JP Auto, "{{proxy_names:region=JP}}"]}
  - auto_test: {name: JP Auto, policies: ["{{proxy_names:region=JP}}"], latency_test_url: "https://www.gstatic.com/generate_204", interval: 300}
rules: [{domain_suffix: {match: example.com, policy: JP}}, {default: {policy: Main}}]
`
	case "qx":
		body = `[server_local]
{{proxies}}
[policy]
static=Main, HK, JP
static=HK, HK Auto, {{proxy_names:region=HK}}
url-latency-benchmark=HK Auto, {{proxy_names:region=HK}}, check-interval=300
static=JP, JP Auto, {{proxy_names:region=JP}}
url-latency-benchmark=JP Auto, {{proxy_names:region=JP}}, check-interval=300
[filter_local]
host-suffix, example.com, JP
final, Main
`
	default:
		body = `[Proxy]
{{proxies}}
[Proxy Group]
Main = select, HK, JP
HK = select, HK Auto, {{proxy_names:region=HK}}
HK Auto = url-test, {{proxy_names:region=HK}}, url=https://www.gstatic.com/generate_204, interval=300
JP = select, JP Auto, {{proxy_names:region=JP}}
JP Auto = url-test, {{proxy_names:region=JP}}, url=https://www.gstatic.com/generate_204, interval=300
[Rule]
DOMAIN-SUFFIX,example.com,JP
FINAL,Main
`
	}
	if !protectJP {
		body = strings.NewReplacer(
			`"DOMAIN-SUFFIX,example.com,JP", `, "",
			`{domain_suffix: {match: example.com, policy: JP}}, `, "",
			"host-suffix, example.com, JP\n", "",
			"DOMAIN-SUFFIX,example.com,JP\n", "",
		).Replace(body)
	}
	return prefix + body
}

type renderedRegionalGroup struct {
	kind    string
	members []string
}

func renderRegionalGroups(t *testing.T, renderer Renderer, tpl string, lines []Line) map[string]renderedRegionalGroup {
	t.Helper()
	out, err := renderer.RenderWith(lines, Account{}, tpl)
	if err != nil {
		t.Fatal(err)
	}
	if renderer.Name() == "qx" {
		out, err = base64.StdEncoding.DecodeString(string(out))
		if err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(string(out), "{{proxy_names") {
		t.Fatalf("unresolved selector: %s", out)
	}
	groups := map[string]renderedRegionalGroup{}
	if renderer.Name() == "clash" || renderer.Name() == "stash" || renderer.Name() == "egern" {
		var doc map[string]any
		if err := yaml.Unmarshal(out, &doc); err != nil {
			t.Fatal(err)
		}
		key, membersKey := "proxy-groups", "proxies"
		if renderer.Name() == "egern" {
			key, membersKey = "policy_groups", "policies"
		}
		for _, item := range doc[key].([]any) {
			body := item.(map[string]any)
			kind, _ := body["type"].(string)
			if renderer.Name() == "egern" {
				for k, v := range body {
					kind, body = k, v.(map[string]any)
				}
			}
			group := renderedRegionalGroup{kind: kind, members: []string{}}
			for _, v := range body[membersKey].([]any) {
				group.members = append(group.members, v.(string))
			}
			groups[body["name"].(string)] = group
		}
		return groups
	}
	section := ""
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(line)
			continue
		}
		if line == "" || section != "[proxy group]" && section != "[policy]" {
			continue
		}
		left, right, _ := strings.Cut(line, "=")
		parts := strings.Split(right, ",")
		name, kind := strings.TrimSpace(left), strings.TrimSpace(parts[0])
		if renderer.Name() == "qx" {
			name, kind = kind, name
			if kind == "static" {
				kind = "select"
			}
		}
		group := renderedRegionalGroup{kind: kind, members: []string{}}
		for _, member := range parts[1:] {
			member = strings.TrimSpace(member)
			if member != "" && !strings.Contains(member, "=") {
				if member == "reject" {
					member = "REJECT"
				}
				group.members = append(group.members, member)
			}
		}
		groups[name] = group
	}
	return groups
}
