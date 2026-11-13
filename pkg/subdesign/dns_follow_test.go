package subdesign

import (
	"strings"
	"testing"
)

func TestDNSFollowMainKeepsSelectionAndLegacy(t *testing.T) {
	d, _ := Preset("basic")
	d.Groups = []Group{{Name: "Main", Type: "select", Members: []string{"@all", "DIRECT"}}, {Name: "Auto", Type: "url-test", Members: []string{"@all"}}}
	d.Final = "Main"
	d.Enhancements = Enhancements{DNSProtection: true, DNSMode: "follow"}
	e, err := d.Effective()
	if err != nil {
		t.Fatal(err)
	}
	if e.Enhancements.DNSPolicy != "Main" || len(e.Groups) != 2 {
		t.Fatal(e)
	}
	text, err := d.Render("clash")
	if err != nil || !strings.Contains(text, "dns-query#Main") {
		t.Fatal(err, text)
	}
	d.Enhancements.DNSMode = ""
	e, err = d.Effective()
	if err != nil || e.Enhancements.DNSPolicy != dnsGroup {
		t.Fatal(err, e)
	}
	d.Enhancements.DNSMode = "custom"
	d.Enhancements.DNSPolicy = "Main"
	if err := d.Validate(); err == nil {
		t.Fatal("independent DNS allowed DIRECT")
	}
	d.Enhancements.DNSMode = "follow"
	d.Groups[1].Members = append(d.Groups[1].Members, "DIRECT")
	d.Groups[0].Members = append(d.Groups[0].Members, "Auto")
	if err := d.Validate(); err == nil {
		t.Fatal("automatic DIRECT accepted")
	}
}
func TestDNSModesSeparateClaudeAndRetainBootstrap(t *testing.T) {
	d, _ := Preset("basic")
	d.Enhancements = Enhancements{DNSProtection: true, DNSMode: "follow", Claude: true, ClaudeRules: syntheticClaudeRules()}
	e, err := d.Effective()
	if err != nil {
		t.Fatal(err)
	}
	if e.Enhancements.DNSPolicy == e.Enhancements.ClaudePolicy {
		t.Fatal("main DNS switched to Claude")
	}
	d.Enhancements.DNSMode = "dedicated"
	e, err = d.Effective()
	if err != nil || e.Enhancements.DNSPolicy != dnsGroup || e.Enhancements.ClaudePolicy != claudeGroup {
		t.Fatal(err, e)
	}
	for _, format := range []string{"clash", "stash", "surge", "egern"} {
		if _, err := d.Render(format); err != nil {
			t.Fatal(format, err)
		}
	}
	d.Enhancements.DNSMode = ""
	e, err = d.Effective()
	if err != nil || e.Enhancements.DNSPolicy != e.Enhancements.ClaudePolicy {
		t.Fatal("legacy changed", err)
	}
	d.Enhancements.DNSMode = "wrong"
	if d.Validate() == nil {
		t.Fatal("unknown DNS mode")
	}
}
