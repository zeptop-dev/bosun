package subdesign

import (
	"encoding/base64"
	"encoding/json"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/subscription"
	"gopkg.in/yaml.v3"
)

// The HTTP host binds these public resources when delivering subscriptions.
// Use reserved fixture URLs here, without contacting any service.
func bindTestResources(t *testing.T, text string) string {
	t.Helper()
	text = strings.ReplaceAll(text, "{{resource_parser_url}}", "https://example.com/sub-resources/qx-parser.js")
	return regexp.MustCompile(`\{\{inline_rule_url:(loon|qx):([A-Za-z0-9_-]+)\}\}`).ReplaceAllStringFunc(text, func(token string) string {
		parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(token, "{{"), "}}"), ":")
		decoded, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		if _, err = InlineRuleResource(parts[1], string(decoded)); err != nil {
			t.Fatal(err)
		}
		return "https://example.com/sub-resources/inline/" + parts[1] + "/" + parts[2]
	})
}

func TestEnhancementRulesAcrossSevenFormats(t *testing.T) {
	d, _ := Preset("basic")
	d.Enhancements = Enhancements{Claude: true, WebRTC: true, QUIC: true, ClaudeRules: syntheticClaudeRules()}
	before, _ := json.Marshal(d)
	for _, format := range Formats {
		t.Run(format, func(t *testing.T) {
			text, err := d.Render(format)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(text, "RULE-SET,,") || strings.Contains(text, "match: \"\"\n") {
				t.Fatal("empty remote rule generated")
			}
			if strings.Contains(text, "DOMAIN-SUFFIX,login.example.net") || strings.Contains(text, "host-suffix,login.example.net") {
				t.Fatal("full domain broadened to suffix")
			}
			switch format {
			case "clash", "stash":
				var doc struct {
					Rules     []string                  `yaml:"rules"`
					Providers map[string]map[string]any `yaml:"rule-providers"`
				}
				if err = yaml.Unmarshal([]byte(text), &doc); err != nil {
					t.Fatal(err)
				}
				want := []string{"DOMAIN-SUFFIX,service.example.com," + claudeGroup, "DOMAIN,login.example.net," + claudeGroup}
				assertRuleOrder(t, strings.Join(doc.Rules, "\n"), append(want, "RULE-SET,lan,DIRECT"))
				udp := "NETWORK,UDP"
				if format == "stash" {
					udp = "NETWORK,udp"
				}
				if !strings.Contains(doc.Rules[0], udp) || !strings.Contains(strings.Join(doc.Rules, "\n"), "AND,(("+udp+"),(DST-PORT,443)),REJECT") {
					t.Fatal("UDP condition missing", doc.Rules)
				}
				if doc.Providers["lan"]["format"] != "text" {
					t.Fatal("raw ACL rules treated as YAML")
				}
			case "surge", "surfboard", "loon":
				if !strings.Contains(text, "AND,((PROTOCOL,UDP),(DEST-PORT,443)),REJECT") {
					t.Fatal("UDP 443 widened or omitted")
				}
				assertRuleOrder(t, text[strings.Index(text, "[Rule]"):], []string{"AND,((PROTOCOL,UDP),(DEST-PORT,3478-3481)),REJECT", "DOMAIN-SUFFIX,service.example.com," + claudeGroup, "DOMAIN,login.example.net," + claudeGroup, "FINAL,"})
			case "qx":
				if !strings.Contains(text, "udp_drop_list = 3478-3481, 5349, 19302, 443") {
					t.Fatal("UDP packet filter incorrect")
				}
				if strings.Contains(text, "dst-port,") || strings.Contains(text, "dest-port,") {
					t.Fatal("TCP traffic would be restricted")
				}
				assertRuleOrder(t, text[strings.Index(text, "[filter_local]"):], []string{"host,stun.l.google.com,reject", "host-suffix,service.example.com," + claudeGroup, "host,login.example.net," + claudeGroup, "final,"})
				if !strings.Contains(text, "resource_parser_url={{resource_parser_url}}") {
					t.Fatal("remote parser missing")
				}
			case "egern":
				var doc struct {
					Rules []map[string]map[string]any `yaml:"rules"`
				}
				if err = yaml.Unmarshal([]byte(text), &doc); err != nil {
					t.Fatal(err)
				}
				first := doc.Rules[0]["and"]
				children := first["match"].([]any)
				if first["policy"] != "REJECT" || children[0].(map[string]any)["protocol"].(map[string]any)["match"] != "udp" || children[1].(map[string]any)["dest_port"].(map[string]any)["match"] != "3478-3481" {
					t.Fatal("logical predicate lost", first)
				}
				assertRuleOrder(t, text, []string{"domain_suffix:\n      match: \"service.example.com\"", "domain:\n      match: \"login.example.net\"", "  - rule_set:"})
			}
			// Empty filtered subscriptions must still reject the generated
			// Claude group instead of implicitly falling back to DIRECT.
			renderer := subscription.Pick(format, "").(interface {
				RenderWith([]subscription.Line, subscription.Account, string) ([]byte, error)
			})
			out, err := renderer.RenderWith(nil, subscription.Account{}, bindTestResources(t, text))
			if err != nil {
				t.Fatal(err)
			}
			if format == "qx" {
				out, err = base64.StdEncoding.DecodeString(string(out))
				if err != nil {
					t.Fatal(err)
				}
			}
			if strings.Contains(string(out), "{{") {
				t.Fatal("unexpanded template")
			}
			if format == "surge" || format == "surfboard" || format == "loon" {
				if !strings.Contains(string(out), claudeGroup+" = select, REJECT") {
					t.Fatal("empty protection group not guarded")
				}
			} else if format == "qx" {
				if !strings.Contains(string(out), "static="+claudeGroup+", reject") {
					t.Fatal("empty protection group not guarded")
				}
			}
		})
	}
	after, _ := json.Marshal(d)
	if string(before) != string(after) {
		t.Fatal("render mutated saved design")
	}
}

func assertRuleOrder(t *testing.T, text string, want []string) {
	t.Helper()
	last := -1
	for _, needle := range want {
		i := strings.Index(text, needle)
		if i < 0 || i <= last {
			t.Fatalf("missing/reordered rule %q", needle)
		}
		last = i
	}
}

func TestRemoteInlineRulesKeepOriginalPosition(t *testing.T) {
	d := Design{Groups: []Group{{Name: "Proxy", Type: "select", Members: []string{"@all"}}}, Final: "Proxy",
		RuleSets: []RuleSet{{Key: "first", Name: "First", Inline: "DOMAIN,first.example.com"}, {Key: "middle", Name: "Middle", Inline: "GEOIP,CN"}, {Key: "last", Name: "Last", Inline: "IP-CIDR,192.0.2.0/24,no-resolve"}},
		Rules:    []Rule{{"first", "Proxy"}, {"ads", "REJECT"}, {"middle", "DIRECT"}, {"lan", "DIRECT"}, {"last", "REJECT"}}}
	for _, format := range []string{"loon", "qx"} {
		text, err := d.Render(format)
		if err != nil {
			t.Fatal(err)
		}
		firstURL := inlineRuleURL(format, "GEOIP,CN")
		lastURL := inlineRuleURL(format, "IP-CIDR,192.0.2.0/24,no-resolve")
		assertRuleOrder(t, text, []string{acl + "BanAD.list", firstURL, acl + "LocalAreaNetwork.list", lastURL})
		if strings.Contains(text, "GEOIP,CN,DIRECT") || strings.Contains(text, "geoip,CN,direct") {
			t.Fatal("remote tail rule promoted to local")
		}
		resource, err := InlineRuleResource(format, "IP-CIDR,192.0.2.0/24,no-resolve")
		if err != nil || resource != "IP-CIDR,192.0.2.0/24,no-resolve\n" {
			t.Fatal(resource, err)
		}
		_ = bindTestResources(t, text)
	}
}

func TestImportedRulesSupportedByContent(t *testing.T) {
	input := "[custom]\nenable_rule_generator=true\noverwrite_original_rules=true\ncustom_proxy_group=Proxy`select`.*\nruleset=Proxy,[]DOMAIN,first.example.com\nruleset=DIRECT,rules/ACL4SSR/Clash/ChinaDomain.list\nruleset=DIRECT,[]GEOIP,CN\nruleset=Proxy,[]FINAL\n"
	d, err := ParseACL4SSR("example.ini", input)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.RuleSets) == 0 {
		t.Fatal("missing imported rules")
	}
	all, err := d.RenderAll()
	if err != nil || len(all) != 7 {
		t.Fatal("imported rules blanket rejected", err)
	}
	for _, s := range d.Support() {
		if !s.Supported {
			t.Fatal(s)
		}
	}
}

func TestQXRejectsNonEquivalentPortRules(t *testing.T) {
	for _, rules := range [][]Rule{{{"domain", "DIRECT"}, {"udp", "REJECT"}}, {{"udp", "DIRECT"}}, {{"lan", "DIRECT"}, {"udp", "REJECT"}}} {
		d := Design{Groups: []Group{{Name: "Proxy", Type: "select", Members: []string{"@all"}}}, Final: "Proxy", Rules: rules,
			RuleSets: []RuleSet{{Key: "domain", Name: "Domain", Inline: "DOMAIN,example.com"}, {Key: "udp", Name: "UDP", Inline: quicRule}}}
		if _, err := d.Render("qx"); err == nil {
			t.Fatal("unordered UDP filter changed rule meaning")
		}
		if _, err := d.Render("surge"); err != nil {
			t.Fatal("native logical rules rejected", err)
		}
	}
}

func TestEnhancementTogglesStayIndependent(t *testing.T) {
	for _, format := range Formats {
		d, _ := Preset("basic")
		d.Enhancements.WebRTC = true
		text, err := d.Render(format)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(text, "DST-PORT,443") || strings.Contains(text, "DEST-PORT,443") || strings.Contains(text, ", 443\n") {
			t.Fatalf("%s WebRTC enabled UDP443", format)
		}
		d.Enhancements = Enhancements{QUIC: true}
		text, err = d.Render(format)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(text, "3478") || strings.Contains(text, "stun.l.google.com") {
			t.Fatalf("%s UDP443 enabled WebRTC", format)
		}
	}
}

func TestGroupTimeoutCapabilityPreservesUnits(t *testing.T) {
	d, _ := Preset("basic")
	d.Groups[1].Timeout = 3
	want := map[string]bool{"clash": true, "surfboard": true, "egern": true}
	for _, s := range d.Support() {
		if s.Supported != want[s.Format] {
			t.Fatalf("%s timeout support incorrect: %+v", s.Format, s)
		}
	}
	for format, needle := range map[string]string{"clash": "timeout: 3000", "surfboard": "timeout=3", "egern": "timeout: 3"} {
		text, err := d.Render(format)
		if err != nil || !strings.Contains(text, needle) {
			t.Fatal(format, text, err)
		}
	}
	d.Groups[1].Timeout = 61
	if _, err := d.Render("egern"); err == nil {
		t.Fatal("Egern max timeout exceeded")
	}
	d.Groups[1].Timeout = 0
	d.Groups[1].URL = "https://example.com/test"
	if _, err := d.Render("surfboard"); err == nil {
		t.Fatal("Surfboard unsupported HTTPS test URL accepted")
	}
}

func TestSurgeCommonTestURLIncludesDirectCandidates(t *testing.T) {
	d, _ := Preset("basic")
	d.Groups[1].URL = "http://example.com/check"
	d.Groups[1].Members = append(d.Groups[1].Members, "DIRECT")
	text, err := d.Render("surge")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"proxy-test-url = http://example.com/check", "internet-test-url = http://example.com/check"} {
		if !strings.Contains(text, want) {
			t.Fatal("group candidates use different test URLs", text)
		}
	}
}

func TestInlineResourceValidation(t *testing.T) {
	for _, format := range []string{"loon", "qx"} {
		for _, expr := range []string{"DOMAIN,example.com\nFINAL,DIRECT", "DOMAIN,example.com,DIRECT", "IP-CIDR,invalid/32", "AND,((NETWORK,TCP),(DST-PORT,443))", "DOMAIN,,no-resolve"} {
			if _, err := InlineRuleResource(format, expr); err == nil {
				t.Fatal("invalid resource accepted", format, expr)
			}
		}
	}
	if _, err := InlineRuleResource("qx", quicRule); err == nil {
		t.Fatal("QX ordered logical filter accepted")
	}
	if _, err := InlineRuleResource("unknown", "DOMAIN,example.com"); err == nil {
		t.Fatal("unknown format accepted")
	}
	r, err := InlineRuleResource("loon", quicRule)
	if err != nil || r != "AND,((PROTOCOL,UDP),(DEST-PORT,443))\n" {
		t.Fatal(r, err)
	}
}

func TestQuantumultXRuleParserRuntime(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for the client JavaScript parser test")
	}
	run := func(input string) map[string]string {
		t.Helper()
		script := "const $resource={content:require('fs').readFileSync(0,'utf8')}; let calls=0; function $done(r){ if(++calls!==1) throw Error('multiple completion');process.stdout.write(JSON.stringify(r)); }\n" + QuantumultXRuleParser()
		cmd := exec.Command(node, "-e", script)
		cmd.Stdin = strings.NewReader(input)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("parser runtime: %v %s", err, out)
		}
		var result map[string]string
		if err = json.Unmarshal(out, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	valid := run("\ufeff# source\r\nDOMAIN,example.com\nDOMAIN-SUFFIX,service.example.com\nDOMAIN-KEYWORD,ads\nIP-CIDR,192.0.2.0/24,no-resolve\nIP-CIDR6,2001:db8::/32,no-resolve\nGEOIP,CN\n")
	if valid["error"] != "" {
		t.Fatal(valid)
	}
	lines := strings.Split(strings.TrimSpace(valid["content"]), "\n")
	if !reflect.DeepEqual(lines[2:], []string{"host,example.com,reject", "host-suffix,service.example.com,reject", "host-keyword,ads,reject", "ip-cidr,192.0.2.0/24,reject,no-resolve", "ip6-cidr,2001:db8::/32,reject,no-resolve", "geoip,CN,reject"}) {
		t.Fatal(lines)
	}
	for _, bad := range []string{"DOMAIN,example.com\nPROCESS-NAME,app", "DOMAIN,example.com\nDOMAIN-SUFFIX,other.example.com,DIRECT", "DOMAIN,example.com\nIP-CIDR,999.0.0.1/32", "DOMAIN,example.com\nAND,((NETWORK,UDP),(DST-PORT,443))", "DOMAIN,example.com\nDOMAIN,example.net,no-resolve"} {
		result := run(bad)
		if result["error"] == "" || result["content"] != "" {
			t.Fatal("partial/unknown conversion accepted", result)
		}
	}
	for _, valid := range []string{
		"IP-CIDR6,::/0", "IP-CIDR6,2001:db8:0:1:2:3:4:5/128",
		"IP-CIDR6,::ffff:192.0.2.1/128", "IP-CIDR6,2001:db8:0:1:2:3:192.0.2.1/128",
		"DOMAIN,_ldap._tcp.example.com", "DOMAIN-SUFFIX,example.com.",
		"DOMAIN," + strings.Repeat("a", 63) + ".example.com",
	} {
		result := run(valid)
		if result["error"] != "" || result["content"] == "" {
			t.Fatal("valid address rejected", valid, result)
		}
		if valid == "DOMAIN-SUFFIX,example.com." && !strings.Contains(result["content"], "host-suffix,example.com,reject") {
			t.Fatal("final DNS root dot not normalized", result)
		}
	}
	for _, invalid := range []string{
		"IP-CIDR6,::::/64", "IP-CIDR6,1:2:3/64", "IP-CIDR6,1:2:3:4:5:6:7:8:9/64",
		"IP-CIDR6,1::2::3/64", "IP-CIDR6,1:2:3:4:5:6:7::8/64", "IP-CIDR6,1::10000/64",
		"IP-CIDR6,::ffff:999.0.0.1/128", "IP-CIDR6,::ffff:192.0.2.001/128",
		"IP-CIDR6,2001:db8::%eth0/64", "IP-CIDR6,2001:db8::/129", "IP-CIDR6,2001:db8::/064",
		"DOMAIN,foo..example.com", "DOMAIN,-foo.example.com", "DOMAIN,foo-.example.com",
		"DOMAIN,example.com..", "DOMAIN,.", "DOMAIN," + strings.Repeat("a", 64) + ".example.com",
		"DOMAIN," + strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("a", 62),
	} {
		result := run("DOMAIN,example.com\n" + invalid)
		if result["error"] == "" || result["content"] != "" {
			t.Fatal("invalid address produced partial content", invalid, result)
		}
	}
}
