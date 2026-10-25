package subdesign

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// Inline remains the stable saved/API representation. Parse it before changing
// dialects: replacing words in an expression could also change a domain or a
// policy name. Validation bounds the accepted grammar before this parser runs.
type rulePredicate struct {
	kind, value string
	noResolve   bool
	all         []rulePredicate
}

func parseRulePredicate(expr string) (rulePredicate, error) {
	if !validInline(expr) {
		return rulePredicate{}, fmt.Errorf("unsupported inline rule")
	}
	if strings.HasPrefix(expr, "AND,(") {
		// The public grammar currently admits only the generated UDP/port
		// conjunctions, not arbitrary nested logical rules.
		body := strings.TrimSuffix(strings.TrimPrefix(expr, "AND,(("), "))")
		parts := strings.Split(body, "),(")
		if len(parts) != 2 {
			return rulePredicate{}, fmt.Errorf("invalid conjunction")
		}
		a := strings.Split(parts[0], ",")
		b := strings.Split(parts[1], ",")
		if len(a) != 2 || len(b) != 2 || a[0] != "NETWORK" || a[1] != "UDP" || b[0] != "DST-PORT" {
			return rulePredicate{}, fmt.Errorf("unsupported conjunction")
		}
		return rulePredicate{kind: "AND", all: []rulePredicate{{kind: "NETWORK", value: a[1]}, {kind: "DST-PORT", value: b[1]}}}, nil
	}
	p := strings.Split(expr, ",")
	return rulePredicate{kind: p[0], value: p[1], noResolve: len(p) == 3}, nil
}

func (p rulePredicate) ini(format string) string {
	if p.kind == "AND" {
		parts := make([]string, len(p.all))
		for i, child := range p.all {
			parts[i] = "(" + child.ini(format) + ")"
		}
		return "AND,(" + strings.Join(parts, ",") + ")"
	}
	kind, value := p.kind, p.value
	switch format {
	case "stash":
		if kind == "NETWORK" {
			value = strings.ToLower(value)
		}
		if kind == "DST-PORT" && strings.Contains(value, "-") {
			// Stash documents a single DST-PORT value. Expand the small,
			// validated enhancement range instead of relying on an alias.
			bounds := strings.Split(value, "-")
			first, _ := strconv.Atoi(bounds[0])
			last, _ := strconv.Atoi(bounds[1])
			parts := make([]string, 0, last-first+1)
			for port := first; port <= last; port++ {
				parts = append(parts, fmt.Sprintf("(DST-PORT,%d)", port))
			}
			return "OR,(" + strings.Join(parts, ",") + ")"
		}
	case "surge", "surfboard", "loon":
		if kind == "NETWORK" {
			kind = "PROTOCOL"
		}
		if kind == "DST-PORT" {
			kind = "DEST-PORT"
		}
	case "qx":
		kind = map[string]string{"DOMAIN": "host", "DOMAIN-SUFFIX": "host-suffix", "GEOIP": "geoip", "IP-CIDR": "ip-cidr", "IP-CIDR6": "ip6-cidr"}[kind]
	}
	out := kind + "," + value
	if p.noResolve {
		out += ",no-resolve"
	}
	return out
}

func (p rulePredicate) egern(b *strings.Builder, indent, policy string) {
	kind := map[string]string{"DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix", "GEOIP": "geoip", "IP-CIDR": "ip_cidr", "IP-CIDR6": "ip_cidr6", "NETWORK": "protocol", "DST-PORT": "dest_port", "AND": "and"}[p.kind]
	fmt.Fprintf(b, "%s- %s:\n", indent, kind)
	if p.kind == "AND" {
		fmt.Fprintf(b, "%s    match:\n", indent)
		for _, child := range p.all {
			child.egern(b, indent+"      ", "")
		}
	} else {
		value := p.value
		if p.kind == "NETWORK" {
			value = strings.ToLower(value)
		}
		fmt.Fprintf(b, "%s    match: %s\n", indent, yq(value))
	}
	if policy != "" {
		fmt.Fprintf(b, "%s    policy: %s\n", indent, yq(policy))
	}
	if p.noResolve {
		fmt.Fprintf(b, "%s    no_resolve: true\n", indent)
	}
}

func (p rulePredicate) udpPort() (string, bool) {
	if p.kind == "AND" && len(p.all) == 2 && p.all[0].kind == "NETWORK" && p.all[0].value == "UDP" && p.all[1].kind == "DST-PORT" {
		return p.all[1].value, true
	}
	return "", false
}

func (d *Design) ruleFormatSupport(format string, s *FormatSupport) {
	qxDropPrefix := true
	for _, r := range d.Rules {
		rs, _ := d.ruleSet(r.Set)
		if rs.URL != "" {
			// This maintained source includes process and full-URL rules.
			// Do not advertise complete support when a client's native parser
			// cannot represent them. No rules are removed from remote resources.
			if rs.URL == acl+"ProxyMedia.list" {
				switch format {
				case "clash":
					// Preserve the established native-source path for existing
					// Mihomo designs, while disclosing its unsupported URL rule.
					s.addWarning("remote_native_unsupported", "The existing Mihomo source is retained for compatibility, but ACL4SSR ProxyMedia.list contains URL-REGEX, which Mihomo does not support; this source is not fully equivalent")
				case "qx":
					s.addReason("remote_rules_unsupported", "Quantumult X cannot preserve PROCESS-NAME and URL-REGEX rules in ACL4SSR ProxyMedia.list")
				case "surfboard":
					s.addReason("remote_rules_unsupported", "Surfboard cannot preserve URL-REGEX rules in ACL4SSR ProxyMedia.list")
				case "egern":
					s.addReason("remote_rules_unsupported", "Egern cannot preserve PROCESS-NAME rules in ACL4SSR ProxyMedia.list")
				case "stash", "surge", "loon":
					s.addWarning("remote_process_macos", "This rule resource includes process rules that only work on macOS; iOS/tvOS ignore them")
				}
			}
			qxDropPrefix = false
			continue
		}
		if r.Set == GeoIPCN {
			qxDropPrefix = qxDropPrefix && r.Policy == "REJECT"
			continue
		}
		p, err := parseRulePredicate(rs.Inline)
		if err != nil {
			s.addReason("inline_rule_unsupported", fmt.Sprintf("Rule %s cannot be represented: %v", r.Set, err))
			continue
		}
		if format == "qx" {
			if _, ok := p.udpPort(); ok {
				// udp_drop_list is a packet prefilter, not an ordered policy
				// rule. It is equivalent only for leading unconditional rejects.
				if r.Policy != "REJECT" || !qxDropPrefix {
					s.addReason("udp_rule_order_unsupported", "Quantumult X can express UDP destination-port rejection only as a leading packet filter")
				}
			} else {
				qxDropPrefix = qxDropPrefix && r.Policy == "REJECT"
			}
		}
	}
	if format == "loon" {
		s.addWarning("native_rule_priority", "Loon evaluates domain rules before IP rules and local rules before remote rules")
		if d.Enhancements.WebRTC || d.Enhancements.QUIC {
			s.addWarning("loon_rule_version", "UDP destination-port restrictions require Loon 3.1.7 or later")
		}
	}
	if format == "qx" && (d.Enhancements.WebRTC || d.Enhancements.QUIC) {
		s.addWarning("qx_udp_tunnel", "Quantumult X applies UDP destination-port rejection to traffic captured by its tunnel")
	}
	commonURL := ""
	for _, g := range d.Groups {
		if g.Type == "select" {
			continue
		}
		if format == "surge" || format == "qx" {
			if commonURL != "" && commonURL != g.url() {
				s.addReason("group_test_url_unsupported", fmt.Sprintf("%s cannot preserve different per-group test URLs", format))
			}
			commonURL = g.url()
		}
		if format == "surfboard" && !strings.HasPrefix(g.url(), "http://") {
			s.addReason("group_test_url_http", "Surfboard automatic groups require an HTTP test URL")
		}
		if g.Timeout == 0 {
			continue
		}
		supported := format == "clash" || (format == "surfboard" && (g.Type == "url-test" || g.Type == "fallback")) || (format == "egern" && (g.Type == "url-test" || g.Type == "fallback") && g.Timeout <= 60)
		if !supported {
			s.addReason("group_timeout_unsupported", fmt.Sprintf("%s cannot preserve the explicit %d-second test timeout for group %s", format, g.Timeout, g.Name))
		}
	}
}

// InlineRuleResource serves a bounded, validated rule as a tiny remote list.
// Loon and Quantumult X place local rules before all remote lists. Representing
// a later inline rule as a remote resource preserves its position instead of
// moving it ahead of an earlier list. This endpoint content never carries the
// policy: each resource reference binds its own policy in the profile.
func InlineRuleResource(format, expression string) (string, error) {
	p, err := parseRulePredicate(expression)
	if err != nil {
		return "", err
	}
	switch format {
	case "loon":
		return p.ini(format) + "\n", nil
	case "qx":
		if _, ok := p.udpPort(); ok {
			return "", fmt.Errorf("Quantumult X has no ordered UDP port filter rule")
		}
		// The same resource parser handles both upstream classical lists and
		// our tiny lists; a source update cannot change the matching dialect.
		return p.ini("clash") + "\n", nil
	default:
		return "", fmt.Errorf("unsupported inline rule resource format")
	}
}

func inlineRuleURL(format, expression string) string {
	return "{{inline_rule_url:" + format + ":" + base64.RawURLEncoding.EncodeToString([]byte(expression)) + "}}"
}

type orderedRemoteRule struct{ url, key, policy string }

func (d *Design) remoteRules(format string) []orderedRemoteRule {
	var out []orderedRemoteRule
	remoteStarted := false
	for i, r := range d.Rules {
		rs, _ := d.ruleSet(r.Set)
		url := rs.URL
		if url != "" {
			remoteStarted = true
		} else if remoteStarted {
			expression := rs.Inline
			if r.Set == GeoIPCN {
				expression = "GEOIP,CN"
			}
			url = inlineRuleURL(format, expression)
		} else {
			continue
		}
		out = append(out, orderedRemoteRule{url, fmt.Sprintf("%s-%d", r.Set, i), r.Policy})
	}
	return out
}

func (d *Design) localRules() []Rule {
	for i, r := range d.Rules {
		rs, _ := d.ruleSet(r.Set)
		if rs.URL != "" {
			return d.Rules[:i]
		}
	}
	return d.Rules
}

func (d *Design) commonTestURL() string {
	for _, g := range d.Groups {
		if g.Type != "select" {
			return g.url()
		}
	}
	return testURL
}

func (d *Design) writeQXUDPDrop(b *strings.Builder) {
	ports := []string{}
	for _, r := range d.Rules {
		rs, _ := d.ruleSet(r.Set)
		if rs.Inline == "" {
			continue
		}
		p, _ := parseRulePredicate(rs.Inline)
		if port, ok := p.udpPort(); ok {
			ports = append(ports, port)
		}
	}
	if len(ports) > 0 {
		fmt.Fprintf(b, "udp_drop_list = %s\n", strings.Join(ports, ", "))
	}
}
