package subdesign

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func regionalMetadataFromTemplate(t *testing.T, tpl string) map[string]regionalGroupMetadata {
	t.Helper()
	out := map[string]regionalGroupMetadata{}
	for _, line := range strings.Split(tpl, "\n") {
		if !strings.HasPrefix(line, regionalMarker) {
			continue
		}
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(line, regionalMarker))
		if err != nil {
			t.Fatal(err)
		}
		var records []regionalGroupMetadata
		if err := json.Unmarshal(b, &records); err != nil {
			t.Fatal(err)
		}
		for _, record := range records {
			if _, duplicate := out[record.Name]; duplicate {
				t.Fatalf("duplicate metadata for %q", record.Name)
			}
			out[record.Name] = record
		}
	}
	return out
}

func TestRegionalEnhancementOffersAutomaticAndManualMembers(t *testing.T) {
	d, _ := Preset("basic")
	d.Enhancements.Regions = true
	before := clone(d)
	eff, err := d.Effective()
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Group{}
	for _, g := range eff.Groups {
		byName[g.Name] = g
	}
	for _, r := range Regions {
		entry, auto := byName[r.Name], byName[r.Name+" · 自动"]
		if entry.Type != "select" || !reflect.DeepEqual(entry.Members, []string{auto.Name, "@region:" + r.Code}) {
			t.Fatalf("region entry cannot choose both automatic and manual members: %+v", entry)
		}
		if auto.Type != "url-test" || !reflect.DeepEqual(auto.Members, []string{"@region:" + r.Code}) || auto.interval() != 300 || auto.tolerance() != 50 {
			t.Fatalf("automatic region policy: %+v", auto)
		}
	}
	if !reflect.DeepEqual(before, d) {
		t.Fatal("effective regional grouping changed the saved design")
	}
	for _, format := range Formats {
		tpl, err := d.Render(format)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		metadata := regionalMetadataFromTemplate(t, tpl)
		if len(metadata) != len(Regions)*2 {
			t.Fatalf("%s: incomplete empty-group metadata: %#v", format, metadata)
		}
		if !strings.Contains(tpl, "{{proxy_names:region=HK}}") {
			t.Fatalf("%s: typed region selector missing", format)
		}
	}
}

func TestRegionalPresetMetadataSurvivesSaveAndGroupReordering(t *testing.T) {
	d, _ := Preset("acl4ssr-regions")
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	// The new preset puts each entry first, but saved designs may be reordered.
	d.Groups[2], d.Groups[3] = d.Groups[3], d.Groups[2]
	d.Enhancements.Regions = true
	eff, err := d.Effective()
	if err != nil {
		t.Fatal(err)
	}
	if len(eff.Groups) != len(d.Groups) {
		t.Fatal("enhancement duplicated an existing region pair")
	}
	for _, member := range eff.Groups[0].Members {
		if member == "🇭🇰 香港 · 自动" {
			t.Fatal("top-level selector received the automatic child instead of the manual region entry")
		}
	}
	if len(regionalMetadataFromTemplate(t, eff.regionalMetadata())) != 12 {
		t.Fatal("saved region pairs lost their delivery metadata")
	}
}

func TestRegionalMetadataProtectsExplicitPolicyTargets(t *testing.T) {
	d, _ := Preset("basic")
	d.Groups = append(d.Groups, regionalPair(Regions[0])...)
	d.Groups = append(d.Groups, regionalPair(Regions[1])...)
	d.Rules = append(d.Rules, Rule{Set: "google-cn", Policy: "🇭🇰 香港"})
	d.Final = "🇹🇼 台湾 · 自动"
	metadata := regionalMetadataFromTemplate(t, d.regionalMetadata())
	if !metadata["🇭🇰 香港"].Protected || !metadata["🇹🇼 台湾 · 自动"].Protected || metadata["🇭🇰 香港 · 自动"].Protected || metadata["🇹🇼 台湾"].Protected {
		t.Fatalf("rule/final protection did not preserve only the explicit targets: %#v", metadata)
	}
	d.Enhancements = Enhancements{Claude: true, ClaudePolicy: "🇭🇰 香港 · 自动", DNSProtection: true, DNSPolicy: "🇹🇼 台湾"}
	eff, err := d.Effective()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range regionalMetadataFromTemplate(t, eff.regionalMetadata()) {
		if !entry.Protected {
			t.Fatalf("explicit DNS/Claude policy was left prunable: %+v", entry)
		}
	}
}

func TestRegionalEnhancementPreservesCustomAndImportedGroups(t *testing.T) {
	for _, g := range []Group{
		{Name: "Custom Hong Kong", Type: "select", Members: []string{"@all"}, Region: "HK"},
		{Name: "🇭🇰 香港节点", Type: "url-test", Members: []string{"@match:HongKong|港"}, Region: "HK", Interval: 1800},
		{Name: Regions[0].Name, Type: "url-test", Members: []string{"@match:" + Regions[0].Match}, URL: testURL, Interval: 300},
	} {
		t.Run(g.Name, func(t *testing.T) {
			d, _ := Preset("basic")
			d.Groups = append(d.Groups, g)
			d.Enhancements.Regions = true
			eff, err := d.Effective()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(eff.Groups[2], g) {
				t.Fatalf("existing regional group was rewritten: %+v", eff.Groups[2])
			}
			if _, ok := regionalMetadataFromTemplate(t, eff.regionalMetadata())[g.Name]; ok {
				t.Fatal("manual/imported group was made eligible for pruning")
			}
		})
	}
	d, _ := Preset("basic")
	pair := regionalPair(Regions[0])
	pair[0].Members = append(pair[0].Members, "@all")
	pair[1].Members = []string{"@tag:premium"}
	d.Groups = append(d.Groups, pair...)
	if got := d.regionalMetadata(); got != "" {
		t.Fatal("manually broadened group still carries empty-region pruning metadata")
	}
}

func TestRegionalSelectorsAndNameConflictsAreValidated(t *testing.T) {
	for _, code := range []string{"HK", "DE", "NZ"} {
		d := Design{Groups: []Group{{Name: "Region", Type: "select", Members: []string{"@region:" + code}, Region: code}}, Final: "Region"}
		if err := d.Validate(); err != nil {
			t.Fatalf("valid custom region %s: %v", code, err)
		}
	}
	for _, code := range []string{"", "hk", "HKG", "H1", "香港", "HK\n", "HK}}"} {
		d := Design{Groups: []Group{{Name: "Region", Type: "select", Members: []string{"@region:" + code}}}, Final: "Region"}
		if err := d.Validate(); err == nil {
			t.Fatalf("invalid region selector %q accepted", code)
		}
	}
	for _, name := range []string{"🇭🇰 香港", "🇭🇰 香港 · 自动", "@region:HK"} {
		d, _ := Preset("basic")
		d.Groups = append(d.Groups, Group{Name: name, Type: "select", Members: []string{"@all"}})
		d.Enhancements.Regions = true
		if _, err := d.Effective(); err == nil || !strings.Contains(err.Error(), "conflicts") {
			t.Fatalf("manual group collision for %q not rejected: %v", name, err)
		}
	}
}

func TestRegionalSelectorDoesNotReinterpretExistingGroupName(t *testing.T) {
	d := Design{
		Groups: []Group{
			{Name: "Main", Type: "select", Members: []string{"@region:HK"}},
			{Name: "@region:HK", Type: "select", Members: []string{"@all"}},
		},
		Final: "Main",
	}
	for _, format := range Formats {
		tpl, err := d.Render(format)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if strings.Contains(tpl, "{{proxy_names:region=HK}}") {
			t.Fatalf("%s: old literal group reference became a region selector", format)
		}
		if strings.Count(tpl, "@region:HK") != 2 {
			t.Fatalf("%s: lost the original group name or reference:\n%s", format, tpl)
		}
	}
	// A legacy group can also have a region role; a coincidentally canonical
	// shape does not make its literal member safe to prune as a region selector.
	d.Groups = append(d.Groups, Group{Name: "Region", Type: "url-test", Members: []string{"@region:HK"}, Region: "HK"})
	if d.regionalMetadata() != "" {
		t.Fatal("literal group reference acquired typed-region pruning semantics")
	}
}
