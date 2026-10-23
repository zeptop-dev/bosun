package xray

import (
	"fmt"
	"net/netip"
	"strings"
)

// Check rendered JSON as well as managed resources: advanced outbounds and
// overrides can use either the flat or legacy nested upstream schemas. Do not
// let a removed value silently fall back to a different security mode.
func validateXrayConfigCompatibility(cfg m, opt renderOptions) error {
	if !opt.ModernConfig && !opt.StrictOutboundSecurity {
		return nil
	}
	for _, out := range configObjects(cfg["outbounds"]) {
		settings, _ := out["settings"].(map[string]any)
		protocol, _ := out["protocol"].(string)
		if opt.ModernConfig && (protocol == "freedom" || protocol == "direct") {
			if _, present := settings["ipsBlocked"]; present {
				return fmt.Errorf("xray: selected core removed freedom ipsBlocked; migrate the explicit policy to finalRules before switching cores")
			}
		}
		if !opt.StrictOutboundSecurity {
			continue
		}
		if err := rejectRemovedCipher(protocol, settings); err != nil {
			return err
		}
		if protocol != "vless" && protocol != "trojan" {
			continue
		}
		stream, _ := out["streamSettings"].(map[string]any)
		if security, _ := stream["security"].(string); security != "" && security != "none" {
			continue // the core's own config check validates TLS/REALITY details
		}
		receivers := configObjects(settings["vnext"])
		if protocol == "trojan" {
			receivers = configObjects(settings["servers"])
		}
		if _, flat := settings["address"]; flat {
			receivers = []m{settings}
		}
		for _, receiver := range receivers {
			host, _ := receiver["address"].(string)
			if host == "" || xrayCleartextPrivateHost(host) {
				continue // missing/invalid addresses are rejected by xray -test
			}
			if protocol == "vless" {
				accounts := configObjects(receiver["users"])
				if len(accounts) == 0 {
					accounts = []m{receiver}
				}
				encrypted := true
				for _, account := range accounts {
					value, _ := account["encryption"].(string)
					encrypted = encrypted && value != "" && value != "none"
				}
				if encrypted {
					continue
				}
			}
			return fmt.Errorf("xray: selected core requires encryption for public %s outbounds, including reverse connections; configure TLS/REALITY or retain the previous core", protocol)
		}
	}
	if opt.StrictOutboundSecurity {
		for _, in := range configObjects(cfg["inbounds"]) {
			protocol, _ := in["protocol"].(string)
			settings, _ := in["settings"].(map[string]any)
			if err := rejectRemovedCipher(protocol, settings); err != nil {
				return err
			}
		}
	}
	return nil
}

func rejectRemovedCipher(protocol string, settings m) error {
	if protocol != "vmess" && protocol != "shadowsocks" {
		return nil
	}
	key := "security"
	if protocol == "shadowsocks" {
		key = "method"
	}
	var removed func(any) bool
	removed = func(value any) bool {
		switch typed := value.(type) {
		case map[string]any:
			for field, item := range typed {
				if strings.EqualFold(field, key) {
					text, _ := item.(string)
					switch strings.ToLower(text) {
					case "none", "zero", "plain":
						return true
					}
				}
				if removed(item) {
					return true
				}
			}
		case []any:
			for _, item := range typed {
				if removed(item) {
					return true
				}
			}
		case []m:
			for _, item := range typed {
				if removed(item) {
					return true
				}
			}
		}
		return false
	}
	if removed(settings) {
		return fmt.Errorf("xray: selected core removed unencrypted %s modes; choose a supported cipher or retain the previous core", protocol)
	}
	return nil
}

// This is the upstream v26.7.28 transport-security classification, not the
// subscriber private-access policy (spec.PrivateRanges). Keeping these roles
// separate preserves that upstream also permits test-network transport peers.
func xrayCleartextPrivateHost(host string) bool {
	if address, err := netip.ParseAddr(host); err == nil {
		address = address.Unmap()
		for _, cidr := range []string{
			"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
			"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
			"::/127", "fc00::/7", "fe80::/10", "ff00::/8",
		} {
			if netip.MustParsePrefix(cidr).Contains(address) {
				return true
			}
		}
		return false
	}
	domain := strings.TrimSuffix(strings.ToLower(host), ".")
	for _, suffix := range []string{"lan", "localdomain", "example", "invalid", "localhost", "test", "local", "home.arpa", "internal"} {
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}
	if len(domain) < 1 || len(domain) > 63 || domain[0] < 'a' || domain[0] > 'z' || strings.HasSuffix(domain, "-") {
		return false
	}
	for _, character := range domain {
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '-' {
			return false
		}
	}
	return true // a single local hostname
}
