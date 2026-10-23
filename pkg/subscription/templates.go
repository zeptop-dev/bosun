package subscription

import (
	"bytes"
	"embed"
	"encoding/base64"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Templates let the operator reshape the document around the server list.
// Placeholders:
//
//	{{proxies}}      INI formats (surge, surfboard, loon, qx): the rendered server lines
//	{{proxy_names}}  INI formats: all names comma-joined; YAML formats (clash,
//	                 stash): a list entry inside any proxy-group's "proxies"
//
// {{proxy_names}} takes an optional filter so a group can hold a subset:
// {{proxy_names:tag=hk}} keeps servers carrying that entry tag and
// {{proxy_names:match=RE}} keeps names matching the (case-insensitive)
// regular expression, e.g. {{proxy_names:match=HK|香港|🇭🇰}}.
//	                 that expands to every server name
//
// Loon and Quantumult X default to a bare node list because their remote
// subscriptions are node lists, not full configs; a full config template
// works when the user imports the URL as a configuration instead.

//go:embed templates/*.tpl
var templateFS embed.FS

// DefaultTemplate returns the built-in template for a format ("" if the
// format is not templated).
func DefaultTemplate(name string) string {
	b, err := templateFS.ReadFile("templates/" + name + ".tpl")
	if err != nil {
		return ""
	}
	return string(b)
}

// TemplateNames lists the formats that accept a custom template.
func TemplateNames() []string {
	entries, _ := templateFS.ReadDir("templates")
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, strings.TrimSuffix(e.Name(), ".tpl"))
	}
	sort.Strings(names)
	return names
}

const (
	phProxies = "{{proxies}}"
	phNames   = "{{proxy_names}}"
)

// Named is a rendered server as the placeholders see it.
type Named struct {
	Name string
	Tags []string
}

var namesPH = regexp.MustCompile(`\{\{proxy_names(?::(tag|match|tag64|match64|matchcase64)=([^}]*))?\}\}`)

// expandNames resolves one {{proxy_names...}} placeholder; ok is false when
// s is not a placeholder. A filter nobody matches yields an empty list.
func expandNames(s string, names []Named) ([]string, bool) {
	m := namesPH.FindStringSubmatch(s)
	if m == nil || m[0] != s {
		return nil, false
	}
	out := []string{}
	if m[1] == "tag64" || m[1] == "match64" || m[1] == "matchcase64" {
		b, err := base64.RawURLEncoding.DecodeString(m[2])
		if err != nil {
			return out, true
		}
		m[2] = string(b)
		m[1] = strings.TrimSuffix(m[1], "64")
	}
	var re *regexp.Regexp
	if m[1] == "match" || m[1] == "matchcase" {
		var err error
		pattern := m[2]
		if m[1] == "match" {
			pattern = "(?i)" + pattern
		}
		if re, err = regexp.Compile(pattern); err != nil {
			return out, true
		}
	}
	for _, n := range names {
		switch m[1] {
		case "tag":
			if !hasTag(n.Tags, m[2]) {
				continue
			}
		case "match", "matchcase":
			if !re.MatchString(n.Name) {
				continue
			}
		}
		out = append(out, n.Name)
	}
	return out, true
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if strings.EqualFold(strings.TrimSpace(t), strings.TrimSpace(want)) {
			return true
		}
	}
	return false
}

// applyINI fills an INI-like template with rendered lines and names.
func applyINI(tpl, format, lines string, names []Named) []byte {
	if tpl == "" {
		tpl = DefaultTemplate(format)
	}
	out := strings.ReplaceAll(tpl, phProxies, lines)
	out = namesPH.ReplaceAllStringFunc(out, func(ph string) string {
		list, _ := expandNames(ph, names)
		return strings.Join(list, ", ")
	})
	if strings.Contains(tpl, designerEmptyMarker) {
		out = guardEmptyINI(out, format)
	}
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return []byte(out)
}

// applyYAML fills a YAML skeleton: proxies replaces the "proxies" key and
// every "{{proxy_names}}" entry in a proxy-group's list expands in place.
func applyYAML(tpl, format string, proxies []any, names []Named) ([]byte, error) {
	if tpl == "" {
		tpl = DefaultTemplate(format)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(tpl), &doc); err != nil {
		return nil, err
	}
	if doc == nil {
		doc = map[string]any{}
	}
	if proxies == nil {
		proxies = []any{}
	}
	doc["proxies"] = proxies
	if groups, ok := doc["proxy-groups"].([]any); ok {
		for _, g := range groups {
			gm, ok := g.(map[string]any)
			if !ok {
				continue
			}
			list, ok := gm["proxies"].([]any)
			if !ok {
				continue
			}
			expanded := make([]any, 0, len(list)+len(names))
			for _, item := range list {
				if s, ok := item.(string); ok {
					if list, ok := expandNames(s, names); ok {
						for _, n := range list {
							expanded = append(expanded, n)
						}
						continue
					}
				}
				expanded = append(expanded, item)
			}
			gm["proxies"] = expanded
			if len(expanded) == 0 && strings.Contains(tpl, designerEmptyMarker) {
				gm["type"] = "select"
				gm["proxies"] = []any{"REJECT"}
				for _, key := range []string{"url", "interval", "tolerance", "timeout", "strategy"} {
					delete(gm, key)
				}
			}
		}
	}
	b, err := yaml.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return append(designerAttribution(tpl), unescapeAstral(b)...), nil
}

// yaml.v3 escapes every character above U+FFFF (emoji flags included) as
// \U0001F1EF inside double-quoted scalars. Valid, but ugly for anyone who
// opens the file, so restore the literal characters. An even number of
// backslashes means the "\\U" was an escaped backslash, not an escape.
var astralEscape = regexp.MustCompile(`(\\+)U([0-9A-Fa-f]{8})`)

func unescapeAstral(b []byte) []byte {
	return astralEscape.ReplaceAllFunc(b, func(m []byte) []byte {
		i := bytes.LastIndexByte(m, '\\') + 1
		if i%2 == 0 {
			return m
		}
		n, _ := strconv.ParseUint(string(m[i+1:]), 16, 32)
		if n > 0x10FFFF || !utf8.ValidRune(rune(n)) {
			return m
		}
		return append(m[:i-1:i-1], []byte(string(rune(n)))...)
	})
}

// This marker is emitted only by the visual designer. Hand-written templates
// retain their existing semantics; generated empty groups must never become an
// implicit direct route or an invalid client configuration.
const designerEmptyMarker = "# captain-designer-empty-groups: reject-v1"

func guardEmptyINI(text, format string) string {
	lines := strings.Split(text, "\n")
	section := ""
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == designerEmptyMarker {
			lines[i] = ""
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			section = strings.ToLower(trimmed)
			continue
		}
		if section != "[proxy group]" && section != "[policy]" {
			continue
		}
		left, right, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		parts := strings.Split(right, ",")
		if len(parts) < 2 {
			continue
		}
		prefix := strings.TrimSpace(parts[0])
		members := []string{}
		params := []string{}
		for _, p := range parts[1:] {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if strings.Contains(p, "=") {
				params = append(params, p)
			} else {
				members = append(members, p)
			}
		}
		if len(members) == 0 {
			if format == "qx" {
				lines[i] = "static=" + prefix + ", reject"
			} else {
				lines[i] = strings.TrimSpace(left) + " = select, REJECT"
			}
		} else {
			fields := append([]string{prefix}, members...)
			fields = append(fields, params...)
			lines[i] = strings.TrimSpace(left) + " = " + strings.Join(fields, ", ")
		}
	}
	return strings.Join(lines, "\n")
}

// Preserve source and adaptation notices when YAML parsing discards comments.
func designerAttribution(tpl string) []byte {
	if !strings.Contains(tpl, designerEmptyMarker) {
		return nil
	}
	var out strings.Builder
	for _, line := range strings.Split(tpl, "\n") {
		if strings.HasPrefix(line, "# Preset source:") || strings.HasPrefix(line, "# ACL4SSR license:") || strings.HasPrefix(line, "# Preset adaptation:") {
			out.WriteString(line)
			out.WriteByte('\n')
		}
	}
	return []byte(out.String())
}
