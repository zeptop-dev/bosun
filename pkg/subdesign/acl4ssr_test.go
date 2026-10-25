package subdesign

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
	"github.com/zeptop-dev/bosun/pkg/subscription"
	"gopkg.in/yaml.v3"
)

// Synthetic fixture, authored for these tests; no upstream preset is bundled.
const syntheticINI = `[custom]
ruleset=BLOCK,rules/ACL4SSR/Clash/BanAD.list
ruleset=DIRECT,[]DOMAIN-SUFFIX,example.com
ruleset=DIRECT,[]GEOIP,CN
ruleset=CHOOSE,[]FINAL
custom_proxy_group=CHOOSE` + "`select`[]AUTO`.*\n" +
	"custom_proxy_group=AUTO`url-test`^HK[0-9]{2}$`https://example.com/check`600,3,150\n" +
	"custom_proxy_group=BLOCK`select`[]REJECT\n" +
	"enable_rule_generator=true\noverwrite_original_rules=true\n"

func testLines() []subscription.Line {
	return []subscription.Line{
		{Name: "HK01", Host: "203.0.113.30", Port: 443, Inbound: spec.Inbound{Protocol: spec.Shadowsocks, Cipher: "aes-128-gcm", Port: 443}, Password: "test-password"},
		{Name: "hk02", Host: "203.0.113.30", Port: 444, Inbound: spec.Inbound{Protocol: spec.Shadowsocks, Cipher: "aes-128-gcm", Port: 444}, Password: "test-password"},
	}
}

func TestACLImportPreservesSemantics(t *testing.T) {
	d, err := ParseACL4SSR("synthetic.ini", syntheticINI)
	if err != nil {
		t.Fatal(err)
	}
	if d.Final != "CHOOSE" || len(d.Rules) != 3 || d.Groups[1].Timeout != 3 || d.Groups[1].Interval != 600 || *d.Groups[1].Tolerance != 150 {
		t.Fatalf("lost semantics: %#v", d)
	}
	rs, _ := d.ruleSet(d.Rules[0].Set)
	if rs.URL != acl+"BanAD.list" {
		t.Fatalf("local reference: %s", rs.URL)
	}
	text, err := d.Render("clash")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "timeout: 3000") || !strings.Contains(text, "tolerance: 150") || !strings.Contains(text, "DOMAIN-SUFFIX,example.com,DIRECT") {
		t.Fatalf("bad output:\n%s", text)
	}
	rendered, err := subscription.Clash{}.RenderWith(testLines(), subscription.Account{}, text)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Groups []struct {
			Name    string   `yaml:"name"`
			Proxies []string `yaml:"proxies"`
		} `yaml:"proxy-groups"`
	}
	if err = yaml.Unmarshal(rendered, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Groups[1].Proxies) != 1 || doc.Groups[1].Proxies[0] != "HK01" {
		t.Fatalf("regex case or quantifiers changed: %+v", doc.Groups[1])
	}
	if !strings.Contains(string(rendered), "CC-BY-SA-4.0") || !strings.Contains(string(rendered), "synthetic.ini") {
		t.Fatal("source attribution lost during YAML rendering")
	}
}

func TestACLImportRejectsUnsupportedSemantics(t *testing.T) {
	cases := map[string]string{
		"directive":           syntheticINI + "rename=old@new\n",
		"disabled-generation": strings.Replace(syntheticINI, "enable_rule_generator=true", "enable_rule_generator=false", 1),
		"missing-final":       strings.Replace(syntheticINI, "ruleset=CHOOSE,[]FINAL\n", "", 1),
		"rule-after-final":    strings.Replace(syntheticINI, "ruleset=CHOOSE,[]FINAL", "ruleset=CHOOSE,[]FINAL\nruleset=DIRECT,[]GEOIP,US", 1),
		"pcre":                strings.Replace(syntheticINI, "^HK[0-9]{2}$", "(?=HK).*", 1),
		"unknown-group":       strings.Replace(syntheticINI, "[]AUTO", "[]ABSENT", 1),
		"cycle":               strings.Replace(syntheticINI, "[]AUTO", "[]BLOCK", 1) + "custom_proxy_group=BACK`select`[]CHOOSE\n",
		"external-url":        strings.Replace(syntheticINI, "rules/ACL4SSR/Clash/BanAD.list", "https://example.com/rules.list", 1),
		"url-traversal":       strings.Replace(syntheticINI, "rules/ACL4SSR/Clash/BanAD.list", "rules/ACL4SSR/Clash/../BanAD.list", 1),
		"inline-policy":       strings.Replace(syntheticINI, "[]GEOIP,CN", "[]GEOIP,CN,DIRECT", 1),
		"url-injection":       strings.Replace(syntheticINI, "https://example.com/check", "https://example.com/check\nmode: global", 1),
	}
	cases["cycle"] = strings.Replace(syntheticINI, "custom_proxy_group=BLOCK`select`[]REJECT", "custom_proxy_group=BLOCK`select`[]CHOOSE", 1)
	cases["cycle"] = strings.Replace(cases["cycle"], "[]AUTO", "[]BLOCK", 1)
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseACL4SSR("bad.ini", src); err == nil {
				t.Fatal("unsupported change accepted")
			}
		})
	}
}

func TestBasicHasNoHiddenAdBlock(t *testing.T) {
	d, _ := Preset("basic")
	for _, r := range d.Rules {
		if r.Policy == "REJECT" || r.Set == "ads" {
			t.Fatal("basic includes ad blocking")
		}
	}
}

func TestEnhancementDerivationDoesNotModifyBase(t *testing.T) {
	d, _ := Preset("basic")
	d.Enhancements = Enhancements{Regions: true, DNSProtection: true, Claude: true, WebRTC: true, QUIC: true}
	before := clone(d)
	a, err := d.Effective()
	if err != nil {
		t.Fatal(err)
	}
	b, err := d.Effective()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d, before) || !reflect.DeepEqual(a, b) {
		t.Fatal("base changed or enhancement is not repeatable")
	}
	again, err := a.Effective()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, again) {
		t.Fatal("effective design duplicated enhancements")
	}
	if len(a.Groups) != len(d.Groups)+7 {
		t.Fatalf("expected 6 region groups and Claude group: %d", len(a.Groups))
	}
	for _, g := range a.Groups {
		if g.Name == claudeGroup {
			if !reflect.DeepEqual(g.Members, []string{"@all"}) {
				t.Fatal("Claude default includes unintended direct fallback")
			}
		}
	}
	d.Enhancements = Enhancements{}
	plain, err := d.Effective()
	if err != nil {
		t.Fatal(err)
	}
	if len(plain.Groups) != len(before.Groups) || len(plain.Rules) != len(before.Rules) {
		t.Fatal("disabled overlay polluted base")
	}
}

func TestEnhancementConflictsAndRegionReuse(t *testing.T) {
	d, _ := Preset("basic")
	d.Groups = append(d.Groups, Group{Name: "custom HK", Type: "select", Members: []string{"@all"}, Region: "HK"})
	d.Enhancements.Regions = true
	eff, err := d.Effective()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, g := range eff.Groups {
		if g.Region == "HK" {
			count++
		}
	}
	if count != 1 {
		t.Fatal("duplicated existing regional group")
	}
	d.Groups = append(d.Groups, Group{Name: claudeGroup, Type: "select", Members: []string{"@all"}})
	d.Enhancements.Claude = true
	if _, err = d.Effective(); err == nil {
		t.Fatal("name collision silently reused custom group")
	}
	d.Enhancements.ClaudePolicy = claudeGroup
	if _, err = d.Effective(); err != nil {
		t.Fatal(err)
	}
	d.Enhancements.ClaudePolicy = "DIRECT"
	if _, err = d.Effective(); err == nil {
		t.Fatal("DIRECT accepted as protected policy")
	}
}

func TestMihomoEnhancementOutputAndSupport(t *testing.T) {
	d, _ := Preset("basic")
	d.Enhancements = Enhancements{DNSProtection: true, Claude: true, WebRTC: true}
	text, err := d.Render("clash")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = yaml.Unmarshal([]byte(text), &doc); err != nil {
		t.Fatal(err)
	}
	dns := doc["dns"].(map[string]any)
	if dns["respect-rules"] != true || !strings.Contains(dns["nameserver"].([]any)[0].(string), "#"+claudeGroup) {
		t.Fatal("DNS not using explicit proxy policy")
	}
	if _, ok := doc["tun"]; ok {
		t.Fatal("enhancement forced TUN")
	}
	if _, ok := doc["external-controller"]; ok {
		t.Fatal("enhancement changed controller")
	}
	if _, ok := doc["ipv6"]; ok {
		t.Fatal("enhancement globally disabled IPv6")
	}
	if strings.Contains(text, "DOMAIN-KEYWORD") || strings.Contains(text, "sentry.io") || strings.Contains(text, "category-ntp") {
		t.Fatal("unreviewed broad rules present")
	}
	if strings.Contains(text, quicRule) {
		t.Fatal("WebRTC option silently enabled QUIC restriction")
	}
	d.Enhancements.QUIC = true
	text, err = d.Render("clash")
	if err != nil || !strings.Contains(text, quicRule) {
		t.Fatal("QUIC option absent", err)
	}
	expected := 0
	for _, s := range d.Support() {
		if s.Format == "clash" && !s.Supported {
			t.Fatal(s)
		}
		_, renderErr := d.Render(s.Format)
		if s.Supported {
			expected++
			if renderErr != nil {
				t.Fatalf("%s declared support but failed: %v", s.Format, renderErr)
			}
		} else if renderErr == nil || len(s.Reasons) == 0 {
			t.Fatalf("%s silently accepted an unsupported option", s.Format)
		}
	}
	all, support, err := d.RenderSupported()
	if err != nil || len(all) != expected || len(support) != len(Formats) {
		t.Fatalf("supported report %v %v %v", all, support, err)
	}
}

func TestDesignerEmptyGroupsRejectWithoutChangingManualTemplates(t *testing.T) {
	d, _ := Preset("basic")
	d.Enhancements.Regions = true
	all, err := d.RenderAll()
	if err != nil {
		t.Fatal(err)
	}
	for format, tpl := range all {
		renderer := subscription.Pick(format, "").(interface {
			RenderWith([]subscription.Line, subscription.Account, string) ([]byte, error)
		})
		out, err := renderer.RenderWith(nil, subscription.Account{}, tpl)
		if err != nil {
			t.Fatalf("%s %v", format, err)
		}
		if format == "clash" || format == "stash" {
			var doc struct {
				Groups []struct {
					Type    string   `yaml:"type"`
					Proxies []string `yaml:"proxies"`
				} `yaml:"proxy-groups"`
			}
			if err = yaml.Unmarshal(out, &doc); err != nil {
				t.Fatal(err)
			}
			for _, g := range doc.Groups {
				if len(g.Proxies) == 0 {
					t.Fatalf("%s empty group", format)
				}
				if g.Type != "select" {
					t.Fatalf("%s empty probe group did not become reject selection", format)
				}
			}
		}
	}
	manual := "proxies: []\nproxy-groups:\n - name: KEEP\n   type: select\n   proxies: [\"{{proxy_names}}\"]\n"
	out, err := subscription.Clash{}.RenderWith(nil, subscription.Account{}, manual)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "REJECT") {
		t.Fatal("modified hand-written template")
	}
}

// Optional network-free integration over an administrator-downloaded upstream
// snapshot. The CC-BY-SA source files stay outside this MIT repository.
func TestACL4SSRDownloadedCatalogue(t *testing.T) {
	dir := os.Getenv("BOSUN_ACL4SSR_PRESET_DIR")
	if dir == "" {
		t.Skip("set BOSUN_ACL4SSR_PRESET_DIR to a downloaded ACL4SSR snapshot")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.ini"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no catalogue: %v", err)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			d, err := ParseACL4SSR(filepath.Base(f), string(data))
			if err != nil {
				t.Fatal(err)
			}
			d.Enhancements = Enhancements{Regions: true, DNSProtection: true, Claude: true, WebRTC: true, QUIC: true}
			tpl, err := d.Render("clash")
			if err != nil {
				t.Fatal(err)
			}
			out, err := subscription.Clash{}.RenderWith(testLines(), subscription.Account{}, tpl)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(out), "{{proxy_names") {
				t.Fatal("unresolved placeholder")
			}
		})
	}
}

func TestACLAttributionSurvivesCustomSaveAndRawSource(t *testing.T) {
	d, err := ParseACL4SSR("synthetic.ini", syntheticINI)
	if err != nil {
		t.Fatal(err)
	}
	d.Source = &PresetSource{Key: "custom:example", Name: "Custom", Revision: strings.Repeat("a", 40), URL: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/" + strings.Repeat("a", 40) + "/Clash/config/synthetic.ini"}
	tpl, err := d.Render("clash")
	if err != nil {
		t.Fatal(err)
	}
	out, err := subscription.Clash{}.RenderWith(testLines(), subscription.Account{}, tpl)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), d.Source.URL) || !strings.Contains(string(out), "CC-BY-SA-4.0") {
		t.Fatal("custom save lost upstream attribution")
	}
}

func TestValidateProtectsGeneratedConfiguration(t *testing.T) {
	cases := map[string]func(*Design){
		"indirect-cycle":     func(d *Design) { d.Groups[1].Members = []string{d.Groups[0].Name} },
		"newline-name":       func(d *Design) { d.Groups[0].Name = "group\nmode: global" },
		"ini-name":           func(d *Design) { d.Groups[0].Name = "group = direct" },
		"url-newline":        func(d *Design) { d.Groups[1].URL = "https://example.com\nmode: global" },
		"negative-tolerance": func(d *Design) { v := -1; d.Groups[1].Tolerance = &v },
		"shadow-set":         func(d *Design) { d.RuleSets = []RuleSet{{Key: "lan", Name: "bad", Inline: "DOMAIN,example.com"}} },
		"source-newline":     func(d *Design) { d.Source = &PresetSource{URL: "https://github.com/ACL4SSR/ACL4SSR/\nmode: global"} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			d, _ := Preset("basic")
			change(&d)
			if err := d.Validate(); err == nil {
				t.Fatal("invalid generated configuration accepted")
			}
		})
	}
}

func TestProtectionPoliciesCannotFallBackToDirect(t *testing.T) {
	for _, enhancement := range []string{"dns", "claude"} {
		t.Run(enhancement, func(t *testing.T) {
			d, _ := Preset("basic")
			d.Groups = append(d.Groups, Group{Name: "INNER", Type: "select", Members: []string{"@all", "DIRECT"}}, Group{Name: "OUTER", Type: "select", Members: []string{"INNER"}})
			if enhancement == "dns" {
				d.Enhancements = Enhancements{DNSProtection: true, DNSPolicy: "OUTER"}
			} else {
				d.Enhancements = Enhancements{Claude: true, ClaudePolicy: "OUTER"}
			}
			if _, err := d.Render("clash"); err == nil || !strings.Contains(err.Error(), "DIRECT") {
				t.Fatalf("nested direct policy accepted: %v", err)
			}
			d.Groups[len(d.Groups)-2].Members = []string{"@all", "REJECT"}
			if _, err := d.Render("clash"); err != nil {
				t.Fatalf("fail-closed policy rejected: %v", err)
			}
		})
	}
}

func TestDNSPolicyFragmentInjectionIsRejected(t *testing.T) {
	for _, name := range []string{"Proxy&DIRECT", "Proxy%26DIRECT", "Proxy%20Group", "RULES"} {
		for _, claude := range []bool{false, true} {
			d, _ := Preset("basic")
			d.Groups = append(d.Groups, Group{Name: name, Type: "select", Members: []string{"@all"}})
			d.Enhancements.DNSProtection = true
			if claude {
				d.Enhancements.Claude = true
				d.Enhancements.ClaudePolicy = name
			} else {
				d.Enhancements.DNSPolicy = name
			}
			if _, err := d.Render("clash"); err == nil {
				t.Fatalf("fragment policy accepted: %q", name)
			}
		}
	}
}

func TestMihomoRuleStringsAndUnicodeLineSeparators(t *testing.T) {
	d := Design{Groups: []Group{{Name: "A: B", Type: "select", Members: []string{"@all"}}}, Rules: []Rule{{Set: GeoIPCN, Policy: "A: B"}}, Final: "A: B"}
	tpl, err := d.Render("clash")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = yaml.Unmarshal([]byte(tpl), &doc); err != nil {
		t.Fatal(err)
	}
	for _, rule := range doc["rules"].([]any) {
		if _, ok := rule.(string); !ok {
			t.Fatalf("rule parsed as non-string: %#v", rule)
		}
	}
	for _, separator := range []string{"\u2028", "\u2029"} {
		x, _ := Preset("basic")
		x.Source = &PresetSource{URL: "https://github.com/ACL4SSR/ACL4SSR/" + separator + "external-controller: 0.0.0.0:9090" + separator + "#"}
		if _, err := x.Render("clash"); err == nil {
			t.Fatal("Unicode source line separator accepted")
		}
		x.Source = nil
		x.Groups[0].Name = "BAD" + separator + "NAME"
		if err := x.Validate(); err == nil {
			t.Fatal("Unicode INI line separator accepted")
		}
	}
}

func TestDesignRejectsNonCanonicalRuleURL(t *testing.T) {
	d, _ := Preset("basic")
	d.RuleSets = []RuleSet{{Key: "extra", Name: "extra", URL: "rules/ACL4SSR/Clash/BanAD.list"}}
	if err := d.Validate(); err == nil {
		t.Fatal("relative HTTP provider URL accepted")
	}
}

func TestDNSBootstrapAndDomesticResolversAreExplicitlyDirect(t *testing.T) {
	d, _ := Preset("basic")
	d.Enhancements.DNSProtection = true
	tpl, err := d.Render("clash")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = yaml.Unmarshal([]byte(tpl), &doc); err != nil {
		t.Fatal(err)
	}
	dns := doc["dns"].(map[string]any)
	for _, key := range []string{"default-nameserver", "proxy-server-nameserver", "direct-nameserver"} {
		for _, resolver := range dns[key].([]any) {
			if !strings.HasSuffix(resolver.(string), "#DIRECT") {
				t.Fatalf("%s may follow user routing: %s", key, resolver)
			}
		}
	}
	for _, value := range dns["nameserver-policy"].(map[string]any) {
		for _, resolver := range value.([]any) {
			if !strings.HasSuffix(resolver.(string), "#DIRECT") {
				t.Fatalf("domestic policy may follow proxy routing: %s", resolver)
			}
		}
	}
}

func TestEnhancementRuleKeyCollisionCannotReplaceContent(t *testing.T) {
	expr := "DOMAIN-SUFFIX,anthropic.com"
	sum := sha256.Sum256([]byte(expr))
	key := fmt.Sprintf("enh-%x", sum[:8])
	for _, conflict := range []RuleSet{
		{Key: key, Name: "custom", Inline: "DOMAIN-SUFFIX,example.com"},
		{Key: key, Name: "custom", URL: acl + "BanAD.list"},
	} {
		d, _ := Preset("basic")
		d.Enhancements.Claude = true
		d.RuleSets = []RuleSet{conflict}
		before := clone(d)
		if _, err := d.Render("clash"); err == nil || !strings.Contains(err.Error(), "conflicts") {
			t.Fatalf("enhancement key collision accepted: %v", err)
		}
		if !reflect.DeepEqual(d, before) {
			t.Fatal("collision check modified base design")
		}
	}
	d, _ := Preset("basic")
	d.Enhancements.Claude = true
	d.RuleSets = []RuleSet{{Key: key, Name: "existing identical rule", Inline: expr}}
	effective, err := d.Effective()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, rs := range effective.RuleSets {
		if rs.Key == key {
			count++
			if rs.Inline != expr {
				t.Fatal("identical content changed")
			}
		}
	}
	if count != 1 {
		t.Fatal("identical rule was duplicated")
	}
	text, err := d.Render("clash")
	if err != nil || !strings.Contains(text, expr) {
		t.Fatalf("Claude rule missing: %v", err)
	}
}
