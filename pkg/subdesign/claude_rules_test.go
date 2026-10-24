package subdesign

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func syntheticClaudeRules() *ClaudeRuleSnapshot {
	return &ClaudeRuleSnapshot{
		Source: "v2fly", Revision: strings.Repeat("a", 40),
		Rules: []ClaudeRule{
			{Type: "domain", Value: "service.example.com"},
			{Type: "full", Value: "login.example.net"},
		},
	}
}

func TestClaudeRuleLegacyFallback(t *testing.T) {
	d, _ := Preset("basic")
	// Loading an older design keeps its omitted snapshot and original routes.
	if err := json.Unmarshal([]byte(`{"claude":true,"dns_protection":true}`), &d.Enhancements); err != nil {
		t.Fatal(err)
	}
	if d.Enhancements.ClaudeRules != nil {
		t.Fatal("legacy design acquired an explicit snapshot")
	}
	implicit, err := d.Render("clash")
	if err != nil {
		t.Fatal(err)
	}
	d.Enhancements.ClaudeRules = BuiltinClaudeRules()
	explicit, err := d.Render("clash")
	if err != nil || implicit != explicit {
		t.Fatalf("legacy and pinned built-in rules differ: %v", err)
	}
	want := []string{
		"DOMAIN-SUFFIX,anthropic.com", "DOMAIN-SUFFIX,claude.ai", "DOMAIN-SUFFIX,claude.com", "DOMAIN-SUFFIX,clau.de",
		"DOMAIN-SUFFIX,claudemcpclient.com", "DOMAIN-SUFFIX,claudemcpcontent.com", "DOMAIN-SUFFIX,claudeusercontent.com",
		"DOMAIN,anthropic.auth0.com", "DOMAIN,servd-anthropic-website.b-cdn.net", "DOMAIN,anthropic.com.cdn.cloudflare.net",
	}
	effective, err := d.Effective()
	if err != nil {
		t.Fatal(err)
	}
	if len(effective.Rules) != len(d.Rules)+len(want) {
		t.Fatal("built-in route count changed")
	}
	for i, expr := range want {
		rs, ok := effective.ruleSet(effective.Rules[i].Set)
		if !ok || rs.Inline != expr || effective.Rules[i].Policy != claudeGroup {
			t.Fatalf("legacy rule %d changed: %+v", i, rs)
		}
	}
	var document struct {
		DNS struct {
			Policies map[string][]string `yaml:"nameserver-policy"`
		} `yaml:"dns"`
	}
	if err := yaml.Unmarshal([]byte(implicit), &document); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"anthropic.auth0.com", "servd-anthropic-website.b-cdn.net", "anthropic.com.cdn.cloudflare.net"} {
		if _, ok := document.DNS.Policies[host]; !ok {
			t.Fatalf("exact DNS entry missing for %s", host)
		}
		if _, ok := document.DNS.Policies["+."+host]; ok {
			t.Fatalf("exact DNS entry widened for %s", host)
		}
	}
}

func TestClaudeSnapshotRoutesDNSAndDisable(t *testing.T) {
	d, _ := Preset("basic")
	d.Enhancements = Enhancements{Claude: true, DNSProtection: true, ClaudeRules: syntheticClaudeRules()}
	before := clone(d)
	text, err := d.Render("clash")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "DOMAIN-SUFFIX,service.example.com,"+claudeGroup) || !strings.Contains(text, "DOMAIN,login.example.net,"+claudeGroup) {
		t.Fatal("snapshot routes not selected")
	}
	if strings.Contains(text, "anthropic.com") || strings.Contains(text, "DOMAIN-SUFFIX,login.example.net") {
		t.Fatal("snapshot combined with stale fallback or widened exact route")
	}
	var document struct {
		DNS struct {
			Policies map[string][]string `yaml:"nameserver-policy"`
		} `yaml:"dns"`
	}
	if err := yaml.Unmarshal([]byte(text), &document); err != nil {
		t.Fatal(err)
	}
	wantResolver := []string{"https://1.1.1.1/dns-query#" + claudeGroup}
	for _, key := range []string{"+.service.example.com", "login.example.net"} {
		if !reflect.DeepEqual(document.DNS.Policies[key], wantResolver) {
			t.Fatalf("snapshot DNS entry %s: %v", key, document.DNS.Policies[key])
		}
	}
	if _, ok := document.DNS.Policies["+.login.example.net"]; ok {
		t.Fatal("full rule widened to DNS suffix")
	}
	if !reflect.DeepEqual(d, before) {
		t.Fatal("rendering mutated the draft")
	}
	d.Enhancements.Claude = false
	disabled, err := d.Render("clash")
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"service.example.com", "login.example.net", claudeGroup} {
		if strings.Contains(disabled, host) {
			t.Fatalf("disabled enhancement still emitted %s", host)
		}
	}
	if !reflect.DeepEqual(d.Enhancements.ClaudeRules, before.Enhancements.ClaudeRules) {
		t.Fatal("disabling discarded the pinned snapshot")
	}
	d.Enhancements.Claude = true
	again, err := d.Render("clash")
	if err != nil || again != text {
		t.Fatalf("re-enabling did not restore pinned rules: %v", err)
	}
}

func TestClaudeSnapshotDeepCopy(t *testing.T) {
	a, b := BuiltinClaudeRules(), BuiltinClaudeRules()
	a.Rules[0].Value = "example.com"
	if b.Rules[0].Value != "anthropic.com" || BuiltinClaudeRules().Rules[0].Value != "anthropic.com" {
		t.Fatal("built-in snapshots share mutable content")
	}
	d, _ := Preset("basic")
	d.Enhancements = Enhancements{Claude: true, ClaudeRules: syntheticClaudeRules()}
	effective, err := d.Effective()
	if err != nil {
		t.Fatal(err)
	}
	effective.Enhancements.ClaudeRules.Source = "changed"
	effective.Enhancements.ClaudeRules.Rules[0].Value = "changed.example.com"
	if !reflect.DeepEqual(d.Enhancements.ClaudeRules, syntheticClaudeRules()) {
		t.Fatal("derived design shares the saved snapshot")
	}
	encoded, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var restored Design
	if err := json.Unmarshal(encoded, &restored); err != nil || !reflect.DeepEqual(restored.Enhancements.ClaudeRules, d.Enhancements.ClaudeRules) {
		t.Fatalf("saved snapshot lost in JSON round trip: %v", err)
	}
}

func TestClaudeSnapshotValidation(t *testing.T) {
	valid := []*ClaudeRuleSnapshot{nil, BuiltinClaudeRules(), syntheticClaudeRules()}
	idn := syntheticClaudeRules()
	idn.Rules = []ClaudeRule{{Type: "domain", Value: "xn--bcher-kva.example"}, {Type: "full", Value: "EXAMPLE.COM"}}
	valid = append(valid, idn)
	reordered := BuiltinClaudeRules()
	reordered.Rules[0], reordered.Rules[1] = reordered.Rules[1], reordered.Rules[0]
	valid = append(valid, reordered)
	limit := syntheticClaudeRules()
	limit.Rules = nil
	for i := range 256 {
		limit.Rules = append(limit.Rules, ClaudeRule{Type: "domain", Value: fmt.Sprintf("n%d.example.com", i)})
	}
	valid = append(valid, limit)
	for i, snapshot := range valid {
		if err := ValidateClaudeRules(snapshot); err != nil {
			t.Fatalf("valid snapshot %d: %v", i, err)
		}
	}
	bad := map[string]*ClaudeRuleSnapshot{}
	mutate := func(name string, fn func(*ClaudeRuleSnapshot)) {
		s := syntheticClaudeRules()
		fn(s)
		bad[name] = s
	}
	mutate("empty", func(s *ClaudeRuleSnapshot) { s.Rules = nil })
	mutate("oversize", func(s *ClaudeRuleSnapshot) {
		s.Rules = append(limit.Rules, ClaudeRule{Type: "domain", Value: "last.example.com"})
	})
	mutate("source", func(s *ClaudeRuleSnapshot) { s.Source = "https://example.com" })
	mutate("short-commit", func(s *ClaudeRuleSnapshot) { s.Revision = "aaaaaaa" })
	mutate("uppercase-commit", func(s *ClaudeRuleSnapshot) { s.Revision = strings.Repeat("A", 40) })
	mutate("nonhex-commit", func(s *ClaudeRuleSnapshot) { s.Revision = strings.Repeat("g", 40) })
	mutate("keyword", func(s *ClaudeRuleSnapshot) { s.Rules[0].Type = "keyword" })
	mutate("duplicate", func(s *ClaudeRuleSnapshot) { s.Rules = append(s.Rules, s.Rules[0]) })
	mutate("duplicate-case", func(s *ClaudeRuleSnapshot) {
		s.Rules = append(s.Rules, ClaudeRule{Type: "domain", Value: "SERVICE.EXAMPLE.COM"})
	})
	mutate("pretend-builtin", func(s *ClaudeRuleSnapshot) { s.Source, s.Revision = "builtin", "captain-v1" })
	for name, domain := range map[string]string{
		"empty-domain": "", "ipv4": "192.0.2.10", "ipv6": "2001:db8::1", "url": "https://example.com",
		"comma": "example.com,DIRECT", "newline": "example.com\n", "space": " example.com", "tab": "example\t.com", "nul": "example\x00.com",
		"unicode": "bücher.example", "invalid-punycode": "xn--a.example", "trailing-dot": "example.com.", "leading-dot": ".example.com",
		"double-dot": "example..com", "wildcard": "*.example.com", "underscore": "_service.example.com", "leading-hyphen": "-service.example.com",
		"trailing-hyphen": "service-.example.com", "long-label": strings.Repeat("a", 64) + ".example.com", "long-domain": strings.Repeat(strings.Repeat("a", 63)+".", 4) + "com",
	} {
		mutate(name, func(s *ClaudeRuleSnapshot) { s.Rules[0].Value = domain })
	}
	wrongVersion := BuiltinClaudeRules()
	wrongVersion.Revision = "captain-v2"
	bad["builtin-version"] = wrongVersion
	wrongContent := BuiltinClaudeRules()
	wrongContent.Rules[0].Value = "example.com"
	bad["builtin-content"] = wrongContent
	for name, snapshot := range bad {
		t.Run(name, func(t *testing.T) {
			if err := ValidateClaudeRules(snapshot); err == nil {
				t.Fatal("invalid snapshot accepted")
			}
			d, _ := Preset("basic")
			d.Enhancements.ClaudeRules = snapshot
			if _, err := d.Render("clash"); err == nil {
				t.Fatal("disabled enhancement bypassed snapshot validation")
			}
		})
	}
}
