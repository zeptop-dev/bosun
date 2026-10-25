package subscription

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

const designerRegionMarker = "# captain-designer-region-groups: "

func namedLine(l Line) Named {
	return Named{Name: l.Name, Tags: l.Tags, Region: l.Region, RegionName: l.RegionName}
}

func normalizeRegionCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return ""
	}
	return code
}

var nameRegionFlags = regexp.MustCompile(`[\x{1F1E6}-\x{1F1FF}]{2}`)

// namedRegion only uses exit metadata or the original display name. In
// particular, an entry host and a flag inferred from that host are not proof
// of the exit location. Legacy flag generation and regexp selectors retain
// their existing behaviour independently of this stricter grouping selector.
func namedRegion(n Named) string {
	if code := normalizeRegionCode(n.Region); code != "" {
		return code
	}
	name := n.Name
	if n.RegionName != "" {
		name = n.RegionName
	}
	flags := map[string]bool{}
	for _, f := range nameRegionFlags.FindAllString(name, -1) {
		r := []rune(f)
		flags[string([]byte{byte(r[0]-0x1F1E6) + 'A', byte(r[1]-0x1F1E6) + 'A'})] = true
	}
	if len(flags) != 0 {
		return uniqueRegion(flags)
	}
	words := " " + strings.Join(asciiWord.FindAllString(strings.ToLower(name), -1), " ") + " "
	matches := map[string]bool{}
	for code, aliases := range regionWords {
		for _, alias := range aliases {
			if alias[0] < 0x80 {
				if strings.Contains(words, " "+alias+" ") {
					matches[code] = true
				}
			} else if len([]rune(alias)) > 1 && strings.Contains(name, alias) {
				matches[code] = true
			}
		}
	}
	return uniqueRegion(matches)
}

func uniqueRegion(matches map[string]bool) string {
	if len(matches) == 1 {
		for code := range matches {
			return code
		}
	}
	return ""
}

type regionalGroup struct {
	Name      string `json:"name"`
	Region    string `json:"region"`
	Protected bool   `json:"protected,omitempty"`
}

type regionalGroupPlan struct {
	active bool
	remove map[string]bool
	reject map[string]bool
}

// regionalGroups is evaluated only after a renderer has removed unsupported
// protocols. The marker applies only to explicitly managed groups: an empty
// user-written group keeps the prior template semantics. Malformed metadata
// disables pruning as a whole rather than guessing which groups to delete.
func regionalGroups(tpl string, names []Named) regionalGroupPlan {
	var none regionalGroupPlan
	if !strings.Contains(tpl, designerEmptyMarker) {
		return none
	}
	encoded := ""
	found := false
	for _, line := range strings.Split(tpl, "\n") {
		if strings.HasPrefix(line, designerRegionMarker) {
			if found {
				return none
			}
			found = true
			encoded = strings.TrimPrefix(line, designerRegionMarker)
		}
	}
	if encoded == "" || len(encoded) > 128*1024 {
		return none
	}
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return none
	}
	var groups []regionalGroup
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields()
	if d.Decode(&groups) != nil || len(groups) == 0 || len(groups) > 256 {
		return none
	}
	if d.Decode(new(any)) != io.EOF {
		return none
	}
	seen := map[string]bool{}
	for _, group := range groups {
		if group.Name == "" || len(group.Name) > 256 || strings.TrimSpace(group.Name) != group.Name ||
			strings.IndexFunc(group.Name, unicode.IsControl) >= 0 || seen[group.Name] ||
			group.Region == "" || normalizeRegionCode(group.Region) != group.Region {
			return none
		}
		seen[group.Name] = true
	}
	available := map[string]bool{}
	for _, name := range names {
		available[namedRegion(name)] = true
	}
	plan := regionalGroupPlan{active: true, remove: map[string]bool{}, reject: map[string]bool{}}
	for _, group := range groups {
		if !available[group.Region] {
			if group.Protected {
				plan.reject[group.Name] = true
			} else {
				plan.remove[group.Name] = true
			}
		}
	}
	return plan
}

func pruneRegionalYAML(doc map[string]any, egern bool, plan regionalGroupPlan) {
	if !plan.active {
		return
	}
	groupKey, memberKey := "proxy-groups", "proxies"
	if egern {
		groupKey, memberKey = "policy_groups", "policies"
	}
	groups, ok := doc[groupKey].([]any)
	if !ok {
		return
	}
	// A saved text template may have gained a direct rule, DNS or dialer
	// reference after the designer emitted its marker. Retain such empty
	// targets rather than producing a dangling reference or a different route.
	for key, value := range doc {
		if key != groupKey {
			protectRegionalReferences(value, plan)
		}
	}
	kept := make([]any, 0, len(groups))
	for _, item := range groups {
		group, ok := item.(map[string]any)
		if !ok {
			kept = append(kept, item)
			continue
		}
		body := group
		kind := ""
		if egern {
			if len(group) != 1 {
				kept = append(kept, item)
				continue
			}
			for key, value := range group {
				kind = key
				body, _ = value.(map[string]any)
			}
			if body == nil {
				kept = append(kept, item)
				continue
			}
		}
		name, _ := body["name"].(string)
		if plan.remove[name] {
			continue
		}
		if plan.reject[name] {
			body[memberKey] = []any{"REJECT"}
			if egern {
				delete(group, kind)
				group["select"] = body
			} else {
				body["type"] = "select"
			}
			for _, key := range []string{"url", "latency_test_url", "interval", "tolerance", "timeout", "strategy"} {
				delete(body, key)
			}
		} else if members, ok := body[memberKey].([]any); ok {
			filtered := make([]any, 0, len(members))
			for _, member := range members {
				if value, ok := member.(string); ok && plan.remove[value] {
					continue
				}
				filtered = append(filtered, member)
			}
			body[memberKey] = filtered
		}
		kept = append(kept, item)
	}
	doc[groupKey] = kept
}

func pruneRegionalINI(tpl, format string, plan regionalGroupPlan) string {
	if !plan.active {
		return tpl
	}
	lines := strings.Split(tpl, "\n")
	section := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			section = strings.ToLower(trimmed)
			continue
		}
		if section != "[proxy group]" && section != "[policy]" &&
			!strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, ";") {
			protectRegionalReferences(trimmed, plan)
		}
	}
	section = ""
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(line, designerRegionMarker) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			section = strings.ToLower(trimmed)
		}
		if section != "[proxy group]" && section != "[policy]" {
			out = append(out, line)
			continue
		}
		left, right, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			out = append(out, line)
			continue
		}
		parts := strings.Split(right, ",")
		if len(parts) < 2 {
			out = append(out, line)
			continue
		}
		name := strings.TrimSpace(left)
		if format == "qx" {
			name = strings.TrimSpace(parts[0])
		}
		if plan.remove[name] {
			continue
		}
		if plan.reject[name] {
			if format == "qx" {
				out = append(out, "static="+name+", reject")
			} else {
				out = append(out, name+" = select, REJECT")
			}
			continue
		}
		kept := []string{strings.TrimSpace(parts[0])}
		for _, member := range parts[1:] {
			member = strings.TrimSpace(member)
			if !plan.remove[member] {
				kept = append(kept, member)
			}
		}
		if len(kept) == 1 {
			kept = append(kept, "") // Let the existing empty-group guard reject it.
		}
		out = append(out, strings.TrimSpace(left)+" = "+strings.Join(kept, ", "))
	}
	return strings.Join(out, "\n")
}

func protectRegionalReferences(value any, plan regionalGroupPlan) {
	switch value := value.(type) {
	case string:
		for name := range plan.remove {
			if regionalReference(value, name) {
				delete(plan.remove, name)
				plan.reject[name] = true
			}
		}
	case []any:
		for _, item := range value {
			protectRegionalReferences(item, plan)
		}
	case map[string]any:
		for key, item := range value {
			if key != "name" {
				protectRegionalReferences(item, plan)
			}
		}
	}
}

func regionalReference(value, name string) bool {
	for _, field := range strings.Split(value, ",") {
		field = strings.Trim(strings.TrimSpace(field), "\"'")
		if field == name {
			return true
		}
		if _, rhs, ok := strings.Cut(field, "="); ok && strings.Trim(strings.TrimSpace(rhs), "\"'") == name {
			return true
		}
	}
	if _, fragment, ok := strings.Cut(value, "#"); ok {
		fragment = strings.SplitN(fragment, "&", 2)[0]
		if decoded, err := url.QueryUnescape(fragment); err == nil && decoded == name {
			return true
		}
	}
	return false
}
