package subdesign

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"path"
	"strconv"
	"strings"
)

// ParseACL4SSR imports the documented subconverter INI subset used by the
// official ACL4SSR catalogue. Unknown directives are errors: accepting them
// while dropping their behavior could silently change routing.
// This function performs no I/O. Its caller pins and attributes the source.
func ParseACL4SSR(name, source string) (Design, error) {
	d := Design{Groups: []Group{}, Rules: []Rule{}, RuleSets: []RuleSet{}}
	if len(source) > 512*1024 {
		return d, fmt.Errorf("preset is too large")
	}
	if !safeLabel(name) {
		return d, fmt.Errorf("invalid preset name")
	}
	d.Source = &PresetSource{Key: "acl4ssr:" + name, Name: name, URL: "https://github.com/ACL4SSR/ACL4SSR/blob/master/Clash/config/" + name}
	source = strings.TrimPrefix(source, "\ufeff")
	scanner := bufio.NewScanner(strings.NewReader(source))
	scanner.Buffer(make([]byte, 4096), 64*1024)
	section := ""
	line := 0
	seenFinal := false
	seenFlags := map[string]bool{}
	fail := func(msg string) (Design, error) { return Design{}, fmt.Errorf("%s line %d: %s", name, line, msg) }
	for scanner.Scan() {
		line++
		s := strings.TrimSpace(scanner.Text())
		if s == "" || strings.HasPrefix(s, ";") || strings.HasPrefix(s, "#") {
			continue
		}
		if strings.HasPrefix(s, "[") {
			if s != "[custom]" {
				return fail("unsupported section")
			}
			section = s
			continue
		}
		if section != "[custom]" {
			return fail("expected [custom] section")
		}
		key, value, ok := strings.Cut(s, "=")
		if !ok {
			return fail("expected key=value")
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "enable_rule_generator", "overwrite_original_rules":
			if seenFlags[key] || value != "true" {
				return fail("unsupported or duplicate " + key)
			}
			seenFlags[key] = true
		case "ruleset":
			if seenFinal {
				return fail("rules after FINAL are not supported")
			}
			policy, expr, ok := strings.Cut(value, ",")
			if !ok {
				return fail("invalid ruleset")
			}
			policy = strings.TrimSpace(policy)
			expr = strings.TrimSpace(expr)
			if expr == "[]FINAL" || expr == "[]MATCH" {
				d.Final = policy
				seenFinal = true
				continue
			}
			rs := RuleSet{}
			if strings.HasPrefix(expr, "[]") {
				rs.Inline = strings.TrimPrefix(expr, "[]")
				if !validInline(rs.Inline) {
					return fail("unsupported inline rule " + rs.Inline)
				}
				rs.Name = rs.Inline
			} else {
				u, err := aclRuleURL(expr)
				if err != nil {
					return fail(err.Error())
				}
				rs.URL = u
				rs.Name = path.Base(u)
			}
			sum := sha256.Sum256([]byte(rs.URL + "\x00" + rs.Inline))
			rs.Key = fmt.Sprintf("acl-%x", sum[:8])
			exists := false
			for _, r := range d.RuleSets {
				if r.Key == rs.Key {
					exists = true
					break
				}
			}
			if !exists {
				d.RuleSets = append(d.RuleSets, rs)
			}
			d.Rules = append(d.Rules, Rule{Set: rs.Key, Policy: policy})
		case "custom_proxy_group":
			g, err := parseACLGroup(value)
			if err != nil {
				return fail(err.Error())
			}
			d.Groups = append(d.Groups, g)
		default:
			return fail("unsupported directive " + key)
		}
	}
	if err := scanner.Err(); err != nil {
		return Design{}, fmt.Errorf("%s: line too long or unreadable", name)
	}
	if !seenFlags["enable_rule_generator"] || !seenFlags["overwrite_original_rules"] {
		return Design{}, fmt.Errorf("%s: explicit rule generation and replacement flags are required", name)
	}
	if !seenFinal {
		return Design{}, fmt.Errorf("%s: FINAL rule is required", name)
	}
	if err := d.Validate(); err != nil {
		return Design{}, fmt.Errorf("%s: %w", name, err)
	}
	return d, nil
}

func aclRuleURL(s string) (string, error) {
	const local = "rules/ACL4SSR/Clash/"
	if strings.HasPrefix(s, local) {
		s = acl + strings.TrimPrefix(s, local)
	}
	if !strings.HasPrefix(s, acl) {
		return "", fmt.Errorf("only official ACL4SSR rule-list URLs are supported")
	}
	suffix := strings.TrimPrefix(s, acl)
	if configurationControl(suffix) || suffix == "" || strings.ContainsAny(suffix, "?#%\\,` \t\r\n{}") || path.Clean(suffix) != suffix || strings.HasPrefix(suffix, "/") || strings.HasPrefix(suffix, "../") || !strings.HasSuffix(suffix, ".list") {
		return "", fmt.Errorf("invalid ACL4SSR rule-list path")
	}
	return s, nil
}

func parseACLGroup(s string) (Group, error) {
	p := strings.Split(s, "`")
	if len(p) < 3 {
		return Group{}, fmt.Errorf("invalid proxy group")
	}
	g := Group{Name: p[0], Type: p[1], MatchCaseSensitive: true}
	if !groupTypes[g.Type] {
		return g, fmt.Errorf("unsupported proxy group type %q", g.Type)
	}
	members := p[2:]
	if g.Type != "select" {
		if len(p) < 5 {
			return g, fmt.Errorf("group %q: missing test URL/timing", g.Name)
		}
		g.URL = p[len(p)-2]
		timing := strings.Split(p[len(p)-1], ",")
		if len(timing) > 3 {
			return g, fmt.Errorf("group %q: unsupported timing", g.Name)
		}
		fields := []*int{&g.Interval, &g.Timeout}
		for i, value := range timing {
			if value == "" {
				continue
			}
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 {
				return g, fmt.Errorf("group %q: invalid timing", g.Name)
			}
			if i < 2 {
				*fields[i] = n
			} else {
				g.Tolerance = &n
			}
		}
		if g.Interval == 0 {
			return g, fmt.Errorf("group %q: positive interval is required", g.Name)
		}
		members = p[2 : len(p)-2]
	}
	for _, m := range members {
		if strings.HasPrefix(m, "[]") {
			g.Members = append(g.Members, strings.TrimPrefix(m, "[]"))
		} else if m == ".*" {
			g.Members = append(g.Members, "@all")
		} else if m == "" || strings.HasPrefix(m, "!!") {
			return g, fmt.Errorf("group %q: unsupported member selector", g.Name)
		} else {
			g.Members = append(g.Members, "@match:"+m)
		}
	}
	// Only explicit known upstream labels on a sole regex group get a region
	// role; arbitrary custom names are never used to infer ownership.
	if len(g.Members) == 1 && strings.HasPrefix(g.Members[0], "@match:") {
		g.Region = aclRegionNames[g.Name]
	}
	return g, nil
}

var aclRegionNames = map[string]string{
	"🇭🇰 香港节点": "HK", "🇨🇳 台湾节点": "TW", "🇹🇼 台湾节点": "TW", "🇯🇵 日本节点": "JP",
	"🇸🇬 狮城节点": "SG", "🇸🇬 新加坡节点": "SG", "🇺🇲 美国节点": "US", "🇺🇸 美国节点": "US", "🇰🇷 韩国节点": "KR",
}
