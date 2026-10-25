package subdesign

import (
	"encoding/base64"
	"encoding/json"
)

const regionalMarker = "# captain-designer-region-groups: "

// Region selectors use a canonical code rather than an unbounded regular
// expression. Matching and metadata precedence are resolved at delivery time,
// after the user's access and each client's protocol support have been applied.
func validRegionCode(code string) bool {
	return len(code) == 2 && code[0] >= 'A' && code[0] <= 'Z' && code[1] >= 'A' && code[1] <= 'Z'
}

func regionalPair(r Region) []Group {
	autoName := r.Name + " · 自动"
	selector := "@region:" + r.Code
	return []Group{
		{Name: r.Name, Type: "select", Members: []string{autoName, selector}, Region: r.Code},
		{Name: autoName, Type: "url-test", Members: []string{selector}, URL: testURL, Interval: 300, Region: r.Code},
	}
}

// regionalGroupMetadata is a private compiler-to-renderer contract. It is not a
// client option. Only narrowly identified region groups are eligible for empty
// pruning; a manually broadened group must retain its existing semantics.
type regionalGroupMetadata struct {
	Name      string `json:"name"`
	Region    string `json:"region"`
	Protected bool   `json:"protected,omitempty"`
}

func (d *Design) regionalMetadata() string {
	byName := make(map[string]Group, len(d.Groups))
	for _, g := range d.Groups {
		byName[g.Name] = g
	}
	protected := map[string]bool{d.Final: true}
	for _, r := range d.Rules {
		protected[r.Policy] = true
	}
	if d.Enhancements.Claude {
		protected[d.Enhancements.ClaudePolicy] = true
	}
	if d.Enhancements.DNSProtection {
		protected[d.Enhancements.DNSPolicy] = true
	}
	var groups []regionalGroupMetadata
	for _, g := range d.Groups {
		if !validRegionCode(g.Region) {
			continue
		}
		selector := "@region:" + g.Region
		managed := g.Type == "url-test" && len(g.Members) == 1 && g.Members[0] == selector
		if g.Type == "select" && len(g.Members) == 2 && g.Members[1] == selector {
			auto, found := byName[g.Members[0]]
			managed = found && auto.Type == "url-test" && auto.Region == g.Region && len(auto.Members) == 1 && auto.Members[0] == selector
		}
		if managed {
			groups = append(groups, regionalGroupMetadata{Name: g.Name, Region: g.Region, Protected: protected[g.Name]})
		}
	}
	if len(groups) == 0 {
		return ""
	}
	b, _ := json.Marshal(groups)
	return regionalMarker + base64.RawURLEncoding.EncodeToString(b) + "\n"
}
