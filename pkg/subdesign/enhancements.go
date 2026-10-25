package subdesign

import (
	"crypto/sha256"
	"fmt"
)

const claudeGroup = "🤖 Claude"
const dnsGroup = "🔒 DNS 代理"
const quicRule = "AND,((NETWORK,UDP),(DST-PORT,443))"

var webRTCRules = []string{
	"AND,((NETWORK,UDP),(DST-PORT,3478-3481))",
	"AND,((NETWORK,UDP),(DST-PORT,5349))",
	"AND,((NETWORK,UDP),(DST-PORT,19302))",
	"DOMAIN,stun.l.google.com", "DOMAIN,stun1.l.google.com", "DOMAIN,stun2.l.google.com", "DOMAIN,stun3.l.google.com", "DOMAIN,stun4.l.google.com",
	"DOMAIN-SUFFIX,stun.services.mozilla.com",
}
var regionCodes = []string{"HK", "TW", "JP", "SG", "US", "KR"}

func knownRegion(s string) bool {
	for _, r := range regionCodes {
		if r == s {
			return true
		}
	}
	return false
}

// Effective derives a render-only design. The base and its manual edits stay
// unchanged; disabling an enhancement simply stops generating that layer.
func (d *Design) Effective() (Design, error) {
	if err := d.Validate(); err != nil {
		return Design{}, err
	}
	out := clone(*d)
	if out.effective {
		return out, nil
	}
	out.effective = true
	names := map[string]bool{}
	for _, g := range out.Groups {
		names[g.Name] = true
	}
	addGroup := func(name string) (string, error) {
		if names[name] {
			return "", fmt.Errorf("enhancement group %q conflicts with a base group; select the existing group explicitly or rename it", name)
		}
		out.Groups = append(out.Groups, Group{Name: name, Type: "select", Members: []string{"@all"}})
		names[name] = true
		return name, nil
	}
	if out.Enhancements.Regions {
		// Add regions to the first all-nodes selection group, never to an arbitrary
		// final policy (which can be a direct/block group in official presets).
		target := -1
		for i, g := range out.Groups {
			if g.Type == "select" {
				for _, m := range g.Members {
					if m == "@all" {
						target = i
						break
					}
				}
			}
			if target >= 0 {
				break
			}
		}
		if target < 0 {
			for i, g := range out.Groups {
				if g.Type == "select" {
					target = i
					break
				}
			}
		}
		if target < 0 {
			return Design{}, fmt.Errorf("regional groups require a selection group")
		}
		for i, r := range Regions {
			role := regionCodes[i]
			existing := ""
			for _, g := range out.Groups {
				if g.Region == role {
					existing = g.Name
					break
				}
				if g.Name == r.Name && len(g.Members) == 1 && g.Members[0] == "@match:"+r.Match {
					existing = g.Name
					break
				}
			}
			if existing == "" {
				if names[r.Name] {
					return Design{}, fmt.Errorf("regional group %q conflicts with a base group", r.Name)
				}
				existing = r.Name
				out.Groups = append(out.Groups, Group{Name: r.Name, Type: "url-test", Members: []string{"@match:" + r.Match}, URL: testURL, Interval: 300, Region: role})
				names[r.Name] = true
			}
			if existing != out.Groups[target].Name {
				found := false
				for _, m := range out.Groups[target].Members {
					if m == existing {
						found = true
						break
					}
				}
				if !found {
					out.Groups[target].Members = append(out.Groups[target].Members, existing)
				}
			}
		}
	}
	claudePolicy := out.Enhancements.ClaudePolicy
	if out.Enhancements.Claude && claudePolicy == "" {
		var err error
		claudePolicy, err = addGroup(claudeGroup)
		if err != nil {
			return Design{}, err
		}
	}
	if out.Enhancements.DNSProtection && out.Enhancements.DNSPolicy == "" {
		if out.Enhancements.Claude {
			out.Enhancements.DNSPolicy = claudePolicy
		} else {
			p, err := addGroup(dnsGroup)
			if err != nil {
				return Design{}, err
			}
			out.Enhancements.DNSPolicy = p
		}
	}
	if out.Enhancements.Claude {
		out.Enhancements.ClaudePolicy = claudePolicy
	}
	var prefix []Rule
	appendRule := func(expr, policy string) error {
		sum := sha256.Sum256([]byte(expr))
		key := fmt.Sprintf("enh-%x", sum[:8])
		rs := RuleSet{Key: key, Name: expr, Inline: expr}
		found := false
		for _, old := range out.RuleSets {
			if old.Key == key {
				if old.URL != "" || old.Inline != expr {
					return fmt.Errorf("enhancement rule set %q conflicts with a base rule set", key)
				}
				found = true
				break
			}
		}
		if !found {
			out.RuleSets = append(out.RuleSets, rs)
		}
		prefix = append(prefix, Rule{Set: key, Policy: policy})
		return nil
	}
	if out.Enhancements.WebRTC {
		for _, r := range webRTCRules {
			if err := appendRule(r, "REJECT"); err != nil {
				return Design{}, err
			}
		}
	}
	if out.Enhancements.QUIC {
		if err := appendRule(quicRule, "REJECT"); err != nil {
			return Design{}, err
		}
	}
	if out.Enhancements.Claude {
		for _, rule := range out.Enhancements.claudeRules() {
			kind := "DOMAIN-SUFFIX"
			if rule.Type == "full" {
				kind = "DOMAIN"
			}
			if err := appendRule(kind+","+rule.Value, claudePolicy); err != nil {
				return Design{}, err
			}
		}
	}
	if len(prefix) > 0 {
		out.Rules = append(prefix, out.Rules...)
	}
	if err := out.Validate(); err != nil {
		return Design{}, err
	}
	return out, nil
}
