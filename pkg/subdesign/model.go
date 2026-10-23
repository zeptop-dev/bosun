package subdesign

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

const designerMarker = "# captain-designer-empty-groups: reject-v1"

// PresetSource identifies the administrator-selected, immutable preset snapshot.
// It is informational; rendering uses the saved design, never a remote source.
type PresetSource struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	Revision string `json:"revision"`
	URL      string `json:"url"`
}

// Enhancements are applied to a copy of the base design on every render.
type Enhancements struct {
	Regions       bool   `json:"regions,omitempty"`
	DNSProtection bool   `json:"dns_protection,omitempty"`
	Claude        bool   `json:"claude,omitempty"`
	WebRTC        bool   `json:"webrtc,omitempty"`
	QUIC          bool   `json:"quic,omitempty"`
	ClaudePolicy  string `json:"claude_policy,omitempty"`
	DNSPolicy     string `json:"dns_policy,omitempty"`
}

// FormatSupport is explicit: unsupported options never silently disappear.
type FormatSupport struct {
	Format    string   `json:"format"`
	Supported bool     `json:"supported"`
	Reasons   []string `json:"reasons"`
}

func (d *Design) Support() []FormatSupport {
	out := make([]FormatSupport, 0, len(Formats))
	for _, format := range Formats {
		s := FormatSupport{Format: format, Supported: true, Reasons: []string{}}
		if format != "clash" {
			if len(d.RuleSets) > 0 {
				s.Reasons = append(s.Reasons, "Imported rule sets and inline rules currently require mihomo")
			}
			if d.Enhancements.DNSProtection {
				s.Reasons = append(s.Reasons, "DNS protection currently requires mihomo")
			}
			if d.Enhancements.Claude {
				s.Reasons = append(s.Reasons, "Claude rule priority currently requires mihomo")
			}
			if d.Enhancements.WebRTC {
				s.Reasons = append(s.Reasons, "WebRTC mitigation currently requires mihomo")
			}
			if d.Enhancements.QUIC {
				s.Reasons = append(s.Reasons, "UDP 443 restriction currently requires mihomo")
			}
			for _, g := range d.Groups {
				if g.Timeout > 0 {
					s.Reasons = append(s.Reasons, "Explicit group timeout currently requires mihomo")
					break
				}
			}
		}
		s.Supported = len(s.Reasons) == 0
		out = append(out, s)
	}
	return out
}

// RenderSupported returns both generated templates and a report of formats not
// generated. Callers must present that report before selectively publishing.
func (d *Design) RenderSupported() (map[string]string, []FormatSupport, error) {
	if err := d.Validate(); err != nil {
		return nil, nil, err
	}
	support := d.Support()
	out := map[string]string{}
	for _, s := range support {
		if !s.Supported {
			continue
		}
		v, err := d.Render(s.Format)
		if err != nil {
			return nil, support, err
		}
		out[s.Format] = v
	}
	return out, support, nil
}

func (d *Design) ruleSet(key string) (RuleSet, bool) {
	for _, r := range d.RuleSets {
		if r.Key == key {
			return r, true
		}
	}
	return ruleSet(key)
}

func (g Group) tolerance() int {
	if g.Tolerance != nil {
		return *g.Tolerance
	}
	return 50
}

func safeLabel(s string) bool {
	return strings.TrimSpace(s) == s && s != "" && len(s) <= 256 && !strings.ContainsAny(s, ",=;#\"'`{}[]\\") && !strings.ContainsFunc(s, unicode.IsControl)
}

func validURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" && u.User == nil && u.Fragment == "" && !strings.ContainsAny(s, ",`\n\r\t {}") && !strings.ContainsFunc(s, unicode.IsControl)
}

var setKey = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,100}$`)

func validInline(s string) bool {
	for _, x := range webRTCRules {
		if s == x {
			return true
		}
	}
	if s == quicRule {
		return true
	}
	p := strings.Split(s, ",")
	if len(p) < 2 || len(p) > 3 {
		return false
	}
	if len(p) == 3 && p[2] != "no-resolve" {
		return false
	}
	switch p[0] {
	case "DOMAIN", "DOMAIN-SUFFIX":
		return len(p) == 2 && len(p[1]) <= 253 && regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$`).MatchString(p[1])
	case "GEOIP":
		return len(p[1]) == 2 && regexp.MustCompile(`^[A-Z]{2}$`).MatchString(p[1])
	case "IP-CIDR", "IP-CIDR6":
		addr, err := netip.ParsePrefix(p[1])
		return err == nil && (p[0] == "IP-CIDR6") == addr.Addr().Is6()
	}
	return false
}

// Validate checks both base structure and enhancement references. It does not
// mutate the saved design, so rejected input and previews leave drafts intact.
func (d *Design) Validate() error {
	if len(d.Groups) == 0 || len(d.Groups) > 256 {
		return fmt.Errorf("between 1 and 256 proxy groups are required")
	}
	if len(d.Rules) > 1024 || len(d.RuleSets) > 1024 {
		return fmt.Errorf("too many rule sets")
	}
	names := map[string]bool{}
	for _, g := range d.Groups {
		if !safeLabel(g.Name) || g.Name == "DIRECT" || g.Name == "REJECT" {
			return fmt.Errorf("group name %q is not allowed", g.Name)
		}
		if names[g.Name] {
			return fmt.Errorf("duplicate group name %q", g.Name)
		}
		names[g.Name] = true
		if !groupTypes[g.Type] {
			return fmt.Errorf("group %q: unknown type %q", g.Name, g.Type)
		}
		if len(g.Members) == 0 || len(g.Members) > 512 {
			return fmt.Errorf("group %q must have 1 to 512 members", g.Name)
		}
		if g.Interval < 0 || g.Interval > 604800 || g.Timeout < 0 || g.Timeout > 300 || (g.Tolerance != nil && (*g.Tolerance < 0 || *g.Tolerance > 60000)) {
			return fmt.Errorf("group %q: invalid timing", g.Name)
		}
		if g.URL != "" && !validURL(g.URL) {
			return fmt.Errorf("group %q: invalid test URL", g.Name)
		}
		if g.Region != "" && !knownRegion(g.Region) {
			return fmt.Errorf("group %q: unknown region", g.Name)
		}
	}
	for _, g := range d.Groups {
		for _, m := range g.Members {
			switch {
			case m == "@all", m == "DIRECT", m == "REJECT", names[m]:
			case strings.HasPrefix(m, "@tag:"):
				if len(m) > 512 || strings.TrimSpace(m[5:]) == "" || strings.ContainsFunc(m, unicode.IsControl) {
					return fmt.Errorf("group %q: invalid tag filter", g.Name)
				}
			case strings.HasPrefix(m, "@match:"):
				if len(m) > 2048 || strings.ContainsFunc(m, unicode.IsControl) {
					return fmt.Errorf("group %q: invalid pattern", g.Name)
				}
				if _, err := regexp.Compile("(?i)" + m[7:]); err != nil {
					return fmt.Errorf("group %q: bad pattern %q", g.Name, m[7:])
				}
			default:
				return fmt.Errorf("group %q: unknown member %q", g.Name, m)
			}
		}
	}
	// Reject indirect group cycles, not just direct self references.
	state := map[string]uint8{}
	byName := map[string]Group{}
	for _, g := range d.Groups {
		byName[g.Name] = g
	}
	var visit func(string) error
	visit = func(n string) error {
		if state[n] == 1 {
			return fmt.Errorf("proxy group cycle at %q", n)
		}
		if state[n] == 2 {
			return nil
		}
		state[n] = 1
		for _, m := range byName[n].Members {
			if names[m] {
				if err := visit(m); err != nil {
					return err
				}
			}
		}
		state[n] = 2
		return nil
	}
	for _, g := range d.Groups {
		if err := visit(g.Name); err != nil {
			return err
		}
	}
	sets := map[string]bool{}
	for _, r := range d.RuleSets {
		if !setKey.MatchString(r.Key) || sets[r.Key] {
			return fmt.Errorf("invalid or duplicate rule set key %q", r.Key)
		}
		if _, exists := ruleSet(r.Key); exists {
			return fmt.Errorf("rule set %q shadows a built-in rule set", r.Key)
		}
		sets[r.Key] = true
		if r.Name == "" || len(r.Name) > 256 || strings.ContainsFunc(r.Name, unicode.IsControl) {
			return fmt.Errorf("invalid rule set name")
		}
		if (r.URL == "") == (r.Inline == "") {
			return fmt.Errorf("rule set %q requires exactly one URL or inline rule", r.Key)
		}
		if r.URL != "" {
			if _, err := aclRuleURL(r.URL); err != nil {
				return fmt.Errorf("rule set %q: %w", r.Key, err)
			}
		}
		if r.Inline != "" && !validInline(r.Inline) {
			return fmt.Errorf("rule set %q: unsupported inline rule", r.Key)
		}
	}
	policy := func(p string) bool { return p == "DIRECT" || p == "REJECT" || names[p] }
	for _, r := range d.Rules {
		if _, ok := d.ruleSet(r.Set); !ok {
			return fmt.Errorf("unknown rule set %q", r.Set)
		}
		if !policy(r.Policy) {
			return fmt.Errorf("rule %s: unknown policy %q", r.Set, r.Policy)
		}
	}
	if !policy(d.Final) {
		return fmt.Errorf("final policy %q is not a group", d.Final)
	}
	if p := d.Enhancements.ClaudePolicy; d.Enhancements.Claude && p != "" && !names[p] {
		return fmt.Errorf("Claude policy %q is not a base proxy group", p)
	}
	if p := d.Enhancements.DNSPolicy; d.Enhancements.DNSProtection && p != "" && !names[p] {
		return fmt.Errorf("DNS policy %q is not a base proxy group", p)
	}
	if d.Source != nil {
		if strings.ContainsFunc(d.Source.Key+d.Source.Name+d.Source.Revision+d.Source.URL, unicode.IsControl) {
			return fmt.Errorf("invalid preset source metadata")
		}
		if len(d.Source.Key) > 256 || len(d.Source.Name) > 512 || len(d.Source.Revision) > 128 || len(d.Source.URL) > 2048 {
			return fmt.Errorf("preset source metadata is too large")
		}
	}
	return nil
}

func clone(d Design) Design {
	b, _ := json.Marshal(d)
	var out Design
	_ = json.Unmarshal(b, &out)
	out.effective = d.effective
	return out
}

func withPolicy(expr, policy string) string {
	if strings.HasSuffix(expr, ",no-resolve") {
		return strings.TrimSuffix(expr, ",no-resolve") + "," + policy + ",no-resolve"
	}
	return expr + "," + policy
}

func (d *Design) attribution() string {
	if d.Source == nil || (!strings.HasPrefix(d.Source.URL, "https://github.com/ACL4SSR/ACL4SSR/") && !strings.HasPrefix(d.Source.URL, "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/")) {
		return ""
	}
	return "# Preset source: " + d.Source.URL + " (revision " + d.Source.Revision + ")\n" +
		"# ACL4SSR license: CC-BY-SA-4.0 https://creativecommons.org/licenses/by-sa/4.0/\n" +
		"# Preset adaptation: generated and adjusted by Captain; enhancement options may change the source layout and rules.\n"
}
