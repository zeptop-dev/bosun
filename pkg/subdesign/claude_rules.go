package subdesign

import (
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// ClaudeRule uses v2fly's domain (suffix) and full (exact host) semantics.
// The compiler deliberately does not accept regular expressions or keywords.
type ClaudeRule struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ClaudeRuleSnapshot pins the administrator-selected rules into the design.
// Rendering uses this saved content and never fetches the source revision.
type ClaudeRuleSnapshot struct {
	Source   string       `json:"source"`
	Revision string       `json:"revision"`
	Rules    []ClaudeRule `json:"rules"`
}

// BuiltinClaudeRules returns a fresh copy of the original Captain rules. A nil
// snapshot in an older design continues to use this fixed, versioned fallback.
func BuiltinClaudeRules() *ClaudeRuleSnapshot {
	// Excludes blanket telemetry keywords, shared third-party suffixes, IP
	// ranges/ASNs and NTP claims. See Anthropic's network requirements:
	// https://code.claude.com/docs/en/network-config
	return &ClaudeRuleSnapshot{
		Source: "builtin", Revision: "captain-v1",
		Rules: []ClaudeRule{
			{Type: "domain", Value: "anthropic.com"},
			{Type: "domain", Value: "claude.ai"},
			{Type: "domain", Value: "claude.com"},
			{Type: "domain", Value: "clau.de"},
			{Type: "domain", Value: "claudemcpclient.com"},
			{Type: "domain", Value: "claudemcpcontent.com"},
			{Type: "domain", Value: "claudeusercontent.com"},
			{Type: "full", Value: "anthropic.auth0.com"},
			{Type: "full", Value: "servd-anthropic-website.b-cdn.net"},
			{Type: "full", Value: "anthropic.com.cdn.cloudflare.net"},
		},
	}
}

// ValidateClaudeRules validates saved snapshots even while the enhancement is
// disabled. Nil is reserved for backward-compatible built-in fallback behavior.
func ValidateClaudeRules(snapshot *ClaudeRuleSnapshot) error {
	if snapshot == nil {
		return nil
	}
	if len(snapshot.Rules) == 0 || len(snapshot.Rules) > 256 {
		return fmt.Errorf("Claude rules must contain between 1 and 256 domains")
	}
	switch snapshot.Source {
	case "builtin":
		if snapshot.Revision != "captain-v1" {
			return fmt.Errorf("unknown built-in Claude rules revision")
		}
	case "v2fly":
		if len(snapshot.Revision) != 40 || strings.Trim(snapshot.Revision, "0123456789abcdef") != "" {
			return fmt.Errorf("Claude rules require a full lowercase source commit")
		}
	default:
		return fmt.Errorf("unknown Claude rules source")
	}
	seen := make(map[ClaudeRule]bool, len(snapshot.Rules))
	for _, rule := range snapshot.Rules {
		if rule.Type != "domain" && rule.Type != "full" {
			return fmt.Errorf("Claude rules support only domain and full matches")
		}
		if !validClaudeDomain(rule.Value) {
			return fmt.Errorf("invalid Claude rule domain")
		}
		key := ClaudeRule{Type: rule.Type, Value: strings.ToLower(rule.Value)}
		if seen[key] {
			return fmt.Errorf("duplicate Claude rule")
		}
		seen[key] = true
	}
	if snapshot.Source == "builtin" {
		builtin := BuiltinClaudeRules()
		if len(snapshot.Rules) != len(builtin.Rules) {
			return fmt.Errorf("built-in Claude rules content does not match its revision")
		}
		for _, rule := range builtin.Rules {
			if !seen[rule] {
				return fmt.Errorf("built-in Claude rules content does not match its revision")
			}
		}
	}
	return nil
}

func validClaudeDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
				return false
			}
		}
	}
	// ASCII shape alone accepts malformed xn-- labels; IDNA checks those too.
	ascii, err := idna.Lookup.ToASCII(domain)
	return err == nil && ascii == strings.ToLower(domain)
}

func (e Enhancements) claudeRules() []ClaudeRule {
	if e.ClaudeRules != nil {
		return e.ClaudeRules.Rules
	}
	return BuiltinClaudeRules().Rules
}
