package core

import (
	"fmt"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"reflect"
)

type wgMap = map[string]any

// WireGuardRoutes binds managed business sockets to their owned tunnel address.
func WireGuardRoutes(kind string, node *spec.Node, inbounds []spec.Inbound, users []spec.User) ([]any, []any, error) {
	if err := node.ValidateWireGuardLinks(); err != nil {
		return nil, nil, err
	}
	links := map[int]spec.WireGuardLink{}
	for _, c := range node.WireGuardLinks {
		links[c.Slot] = c
	}
	if kind != "xray" && kind != "singbox" {
		return nil, nil, fmt.Errorf("unsupported WireGuard core family")
	}
	var rules, outs []any
	seen := map[string]bool{}
	for _, ib := range inbounds {
		if ib.WireGuardSlot == 0 {
			continue
		}
		c, ok := links[ib.WireGuardSlot]
		if !ok || c.Exit {
			return nil, nil, fmt.Errorf("missing WireGuard transit link")
		}
		// Render may receive a core-specific inbound slice rather than exactly
		// node.Inbounds. Validate that slice too; never let caller selection
		// bypass transport ownership or destination authorization.
		if err := ib.Validate(); err != nil {
			return nil, nil, err
		}
		if !reflect.DeepEqual(ib.PrivateAccess.EffectiveRules(), c.PrivateAccess.EffectiveRules()) {
			return nil, nil, fmt.Errorf("WireGuard inbound and link private grants must match")
		}
		add := func(v6, matchFamily bool, user *spec.User) {
			family, strategy := "v4", "UseIPv4"
			if v6 {
				family, strategy = "v6", "UseIPv6"
			}
			tag := fmt.Sprintf("wireguard-%d-%s", c.Slot, family)
			out := wgMap{"protocol": "freedom", "sendThrough": c.Address(false, v6), "settings": wgMap{"domainStrategy": strategy}}
			tagName := ib.Tag
			if kind == "singbox" && ib.ShadowTLS != nil {
				tagName = spec.ShadowTLSTag(tagName)
			}
			rule := wgMap{"type": "field", "inboundTag": []string{tagName}}
			if kind == "singbox" {
				bindKey, dnsStrategy := "inet4_bind_address", "ipv4_only"
				if v6 {
					bindKey, dnsStrategy = "inet6_bind_address", "ipv6_only"
				}
				out = wgMap{"type": "direct", bindKey: c.Address(false, v6), "inet4_bind_address": c.Address(false, false), "inet6_bind_address": c.Address(false, true), "domain_resolver": wgMap{"server": wireGuardDNSServer(node), "strategy": dnsStrategy}}
				rule = wgMap{"inbound": []string{tagName}}
			}
			if matchFamily {
				cidr := "0.0.0.0/0"
				if v6 {
					cidr = "::/0"
				}
				if kind == "singbox" {
					rule["ip_cidr"] = []string{cidr}
				} else {
					rule["ip"] = []string{cidr}
				}
			}
			if user != nil {
				tag += fmt.Sprintf("-u%d", user.ID)
				out["streamSettings"] = wgMap{"sockopt": wgMap{"mark": spec.SpeedMark(user.ID)}}
				rule["user"] = []string{spec.InboundUser(user.Name, ib.Tag)}
				if kind == "singbox" {
					delete(out, "streamSettings")
					delete(rule, "user")
					out["routing_mark"] = spec.SpeedMark(user.ID)
					rule["auth_user"] = []string{spec.InboundAuthName(ib, *user)}
				}
			}
			out["tag"], rule["outboundTag"] = tag, tag
			if kind == "singbox" {
				delete(rule, "outboundTag")
				rule["outbound"] = tag
			}
			if !seen[tag] {
				outs = append(outs, out)
				seen[tag] = true
			}
			rules = append(rules, rule)
		}
		addFamilies := func(user *spec.User) {
			// IPOnDemand matches any DNS answer. A bounded IPv4 rule must
			// precede IPv6 only when selected; a catch-all here would also
			// capture IPv6 literals and AAAA-only domains.
			if c.DomainPreference == "ipv4" {
				add(false, true, user)
			}
			add(true, true, user)
			add(false, false, user)
		}
		for _, u := range ib.EffectiveUsers(users) {
			if node.EffectiveSpeedLimit(u) > 0 {
				addFamilies(&u)
			}
		}
		addFamilies(nil)
	}
	return rules, outs, nil
}

func wireGuardDNSServer(node *spec.Node) string {
	if len(node.DNS) > 0 {
		return "dns-0"
	}
	return "private-dns"
}
