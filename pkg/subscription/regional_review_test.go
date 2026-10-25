package subscription

import (
	"reflect"
	"strings"
	"testing"
)

func TestReviewEditedRegionalMembersDoNotFollowStaleMetadata(t *testing.T) {
	for _, renderer := range []Renderer{Clash{}, Stash{}, Surge{}, Surfboard{}, Loon{}, QuantumultX{}, Egern{}} {
		t.Run(renderer.Name(), func(t *testing.T) {
			// A text edit changes a former region group to an explicit candidate.
			// The old comment must not keep claiming it is a dynamic HK group.
			tpl := strings.ReplaceAll(regionalTemplate(renderer.Name(), false), "{{proxy_names:region=HK}}", "Manual exit")
			groups := renderRegionalGroups(t, renderer, tpl, []Line{regionalLine("Manual exit", "JP")})
			if !reflect.DeepEqual(groups["HK Auto"].members, []string{"Manual exit"}) || !reflect.DeepEqual(groups["HK"].members, []string{"HK Auto", "Manual exit"}) {
				t.Fatalf("stale metadata deleted manually assigned candidates: %+v", groups)
			}
		})
	}
}

func TestReviewEncodedDNSOptionsProtectRegionalPolicy(t *testing.T) {
	// Mihomo decodes the fragment before splitting proxy and DNS options.
	tpl := regionalTemplate("clash", false) + "dns:\n  nameserver: ['https://1.1.1.1/dns-query#JP%26ecs=0.0.0.0/0']\n"
	groups := renderRegionalGroups(t, Clash{}, tpl, []Line{regionalLine("IPLC", "HK")})
	if !reflect.DeepEqual(groups["JP"].members, []string{"REJECT"}) {
		t.Fatalf("encoded DNS option made an actual policy reference disappear: %+v", groups)
	}
}

func TestEditedRegionalHalfPreservesPairButPrunesOtherRegions(t *testing.T) {
	for _, renderer := range []Renderer{Clash{}, Stash{}, Surge{}, Surfboard{}, Loon{}, QuantumultX{}, Egern{}} {
		for _, changed := range []string{"entry", "automatic"} {
			t.Run(renderer.Name()+"/"+changed, func(t *testing.T) {
				tpl := regionalTemplate(renderer.Name(), false)
				selector := "{{proxy_names:region=HK}}"
				index := strings.Index(tpl, selector)
				if changed == "automatic" {
					index = strings.LastIndex(tpl, selector)
				}
				tpl = tpl[:index] + "Manual exit" + tpl[index+len(selector):]
				groups := renderRegionalGroups(t, renderer, tpl, []Line{regionalLine("Manual exit", "US")})
				wantEntry, wantAuto := []string{"HK Auto", "Manual exit"}, []string{"REJECT"}
				if changed == "automatic" {
					wantEntry, wantAuto = []string{"HK Auto"}, []string{"Manual exit"}
				}
				if !reflect.DeepEqual(groups["HK"].members, wantEntry) || !reflect.DeepEqual(groups["HK Auto"].members, wantAuto) {
					t.Fatalf("one manually edited half lost its pair: %+v", groups)
				}
				if _, exists := groups["JP"]; exists {
					t.Fatalf("unmodified empty region was retained: %+v", groups)
				}
			})
		}
	}
}

func TestRegionalDNSFragmentPreservesLiteralPlus(t *testing.T) {
	for _, value := range []string{
		"https://1.1.1.1/dns-query#JP+Pool",
		"https://1.1.1.1/dns-query#JP%2BPool%26ecs=0.0.0.0/0",
	} {
		if !regionalReference(value, "JP+Pool") || regionalReference(value, "JP Pool") {
			t.Fatalf("fragment used query-string plus semantics: %s", value)
		}
	}
}
