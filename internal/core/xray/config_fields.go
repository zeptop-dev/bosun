package xray

import (
	"fmt"
	"strings"
)

// Xray's encoding/json configuration loader accepts case-insensitive struct
// fields. Normalize only the structures this adapter inspects; otherwise an
// alias such as Settings could be missed or shadowed by generated settings.
// Copy-on-write avoids modifying the panel's nested Settings maps/slices.
// Header names, domains and other free-form maps are deliberately untouched.
func normalizeXrayConfigFields(input m) (m, error) {
	cfg, err := canonicalFields(input, "inbounds", "outbounds", "routing", "dns", "api")
	if err != nil {
		return nil, err
	}
	for _, field := range []string{"inbounds", "outbounds"} {
		value, err := mapConfigObjects(cfg[field], func(input m) (m, error) {
			object, err := canonicalFields(input, "protocol", "tag", "settings", "streamSettings")
			if err != nil {
				return nil, err
			}
			if protocol, ok := object["protocol"].(string); ok {
				object["protocol"] = strings.ToLower(protocol) // upstream LoadWithID does the same
			}
			if stream, ok := object["streamSettings"].(map[string]any); ok {
				object["streamSettings"], err = canonicalFields(stream, "security")
				if err != nil {
					return nil, err
				}
			}
			if settings, ok := object["settings"].(map[string]any); ok {
				protocol, _ := object["protocol"].(string)
				object["settings"], err = canonicalProxySettings(protocol, settings)
				if err != nil {
					return nil, err
				}
			}
			return object, nil
		})
		if err != nil {
			return nil, err
		}
		if _, present := cfg[field]; present {
			cfg[field] = value
		}
	}
	if dns, ok := cfg["dns"].(map[string]any); ok {
		cfg["dns"], err = canonicalFields(dns, "tag", "servers")
		if err != nil {
			return nil, err
		}
	}
	if routing, ok := cfg["routing"].(map[string]any); ok {
		routing, err = canonicalFields(routing, "rules")
		if err != nil {
			return nil, err
		}
		if rules, present := routing["rules"]; present {
			routing["rules"], err = mapConfigObjects(rules, func(rule m) (m, error) {
				return canonicalFields(rule, "inboundTag", "outboundTag")
			})
			if err != nil {
				return nil, err
			}
		}
		cfg["routing"] = routing
	}
	return cfg, nil
}

func canonicalProxySettings(protocol string, input m) (m, error) {
	var fields []string
	switch protocol {
	case "freedom", "direct":
		fields = []string{"finalRules", "ipsBlocked"}
	case "vless":
		fields = []string{"address", "vnext", "users", "clients", "encryption"}
	case "trojan":
		fields = []string{"address", "servers"}
	case "vmess":
		fields = []string{"address", "vnext", "users", "clients", "security"}
	case "shadowsocks":
		fields = []string{"address", "servers", "users", "clients", "method"}
	}
	settings, err := canonicalFields(input, fields...)
	if err != nil {
		return nil, err
	}
	// These arrays are schema-defined peer/account records, not arbitrary
	// user maps. Recursing into them cannot rename HTTP headers or domains.
	for _, field := range fields {
		if field != "vnext" && field != "servers" && field != "users" && field != "clients" {
			continue
		}
		if value, present := settings[field]; present {
			settings[field], err = mapConfigObjects(value, func(record m) (m, error) {
				return canonicalProxySettings(protocol, record)
			})
			if err != nil {
				return nil, err
			}
		}
	}
	return settings, nil
}

func canonicalFields(input m, fields ...string) (m, error) {
	output := make(m, len(input))
	for key, value := range input {
		canonical := key
		for _, field := range fields {
			if strings.EqualFold(key, field) {
				canonical = field
				break
			}
		}
		if _, duplicate := output[canonical]; duplicate {
			return nil, fmt.Errorf("xray: ambiguous duplicate configuration field %q", canonical)
		}
		output[canonical] = value
	}
	return output, nil
}

func mapConfigObjects(value any, fn func(m) (m, error)) (any, error) {
	var values []any
	switch typed := value.(type) {
	case []any:
		values = typed
	case []m:
		for _, object := range typed {
			values = append(values, object)
		}
	default:
		return value, nil // retain invalid shapes for the core's config check
	}
	output := make([]any, len(values))
	for index, item := range values {
		output[index] = item
		if object, ok := item.(map[string]any); ok {
			var err error
			output[index], err = fn(object)
			if err != nil {
				return nil, err
			}
		}
	}
	return output, nil
}
