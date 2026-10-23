package xray

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Newer Xray freedom outbounds have their own default destination policy,
// including a deny-all default for VLESS Reverse. State our existing policy
// explicitly instead of relying on that version-dependent default. Old Xray
// ignores finalRules and continues to use the existing routing/nft checks.
func applyFreedomFinalRules(cfg m, node *spec.Node, users []spec.User) error {
	if err := separatePrivateDNS(cfg, node); err != nil {
		return err
	}
	grants, err := node.PrivateGrants(users)
	if err != nil {
		return err
	}
	byMark := make(map[int64]spec.PrivateGrant, len(grants))
	for _, grant := range grants {
		if !grant.CoreOnly {
			byMark[grant.Mark] = grant
		}
	}
	for _, raw := range configObjects(cfg["outbounds"]) {
		if raw["protocol"] != "freedom" && raw["protocol"] != "direct" {
			continue
		}
		settings, valid := raw["settings"].(map[string]any)
		if raw["settings"] != nil && !valid {
			return fmt.Errorf("xray: freedom settings must be an object")
		}
		if settings == nil {
			settings = m{}
			raw["settings"] = settings
		}
		explicit := false
		for key := range settings {
			explicit = explicit || strings.EqualFold(key, "finalRules")
		}
		if explicit {
			continue // operator-authored policies are not widened or replaced
		}
		var rules []any
		tag, _ := raw["tag"].(string)
		if strings.HasPrefix(tag, "private-") && node.HasPrivateAccess() {
			ss, _ := raw["streamSettings"].(map[string]any)
			sock, _ := ss["sockopt"].(map[string]any)
			grant, ok := byMark[numericMark(sock["mark"])]
			if !ok {
				return fmt.Errorf("xray: private outbound has no matching destination grant")
			}
			rules = append(rules, m{"action": "block", "ip": spec.PrivateAccessProtectedRanges, "blockDelay": 0})
			for _, access := range grant.Rules {
				rule := m{"action": "allow", "ip": []string{access.CIDR}}
				if access.Protocol != "" {
					rule["network"] = access.Protocol
				}
				if access.PortStart > 0 {
					rule["port"] = strconv.Itoa(access.PortStart) + "-" + strconv.Itoa(access.PortEnd)
				}
				rules = append(rules, rule)
			}
		}
		if !node.AllowPrivateDest {
			for _, text := range node.PrivateDestAllow {
				text = strings.TrimSpace(text)
				if _, _, err := net.ParseCIDR(text); err != nil {
					if net.ParseIP(text) == nil {
						continue // matches PrivateDestRules' historical handling
					}
				}
				rules = append(rules, m{"action": "allow", "ip": []string{text}})
			}
			rules = append(rules, m{"action": "block", "ip": spec.PrivateRanges, "blockDelay": 0})
		}
		// Only addresses outside the denies above reach this rule, unless the
		// operator explicitly enabled the existing global private exemption.
		settings["finalRules"] = append(rules, m{"action": "allow"})
	}
	return nil
}

// PrivateRoutes already separates the core's own DNS from subscriber routes.
// Preserve that exception on its own socket path: applying the subscriber
// finalRules to it would break private resolvers authorized by egress guard.
// This does not add firewall exceptions or routes for subscriber destinations.
func separatePrivateDNS(cfg m, node *spec.Node) error {
	if !node.HasPrivateAccess() {
		return nil
	}
	dns, _ := cfg["dns"].(map[string]any)
	if dns["tag"] != "bosun-private-dns" {
		return nil
	}
	for _, inbound := range configObjects(cfg["inbounds"]) {
		if inbound["tag"] == "bosun-private-dns" {
			return fmt.Errorf("xray: bosun-private-dns is reserved for internal DNS queries")
		}
	}
	for _, outbound := range configObjects(cfg["outbounds"]) {
		if outbound["tag"] == "private-dns" {
			return fmt.Errorf("xray: private-dns is reserved for internal DNS queries")
		}
	}
	routing, _ := cfg["routing"].(map[string]any)
	for _, rule := range configObjects(routing["rules"]) {
		tags, _ := rule["inboundTag"].([]string)
		if len(tags) == 1 && tags[0] == "bosun-private-dns" && rule["outboundTag"] == "direct" {
			rule["outboundTag"] = "private-dns"
			outbounds, _ := cfg["outbounds"].([]any)
			cfg["outbounds"] = append(outbounds, m{"tag": "private-dns", "protocol": "freedom", "settings": m{"finalRules": []m{{"action": "allow"}}}})
			return nil
		}
	}
	return nil
}

func numericMark(value any) int64 {
	switch v := value.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64: // PrivateRoutes deep-copies JSON maps
		return int64(v)
	}
	return 0
}

func configObjects(value any) []m {
	var result []m
	switch values := value.(type) {
	case []m:
		return values
	case []any:
		for _, item := range values {
			if object, ok := item.(map[string]any); ok {
				result = append(result, object)
			}
		}
	}
	return result
}
