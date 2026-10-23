package spec

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// CoreCapabilities describes the features implemented by a bosun adapter,
// rather than everything the upstream binary may support.
type CoreCapabilities struct {
	PrivateAccessPolicy    *PrivateAccessPolicyCapabilities `json:"private_access_policy,omitempty"`
	CoreOnlyPrivateAccess  bool                             `json:"core_only_private_access,omitempty"`
	PrivateAccessReadiness *PrivateAccessReadiness          `json:"private_access_readiness,omitempty"`
	WireGuardReverse       bool                             `json:"wireguard_reverse,omitempty"`
	// WireGuardDevices requires a binary that binds WG source addresses to
	// users for accounting. Runtime adapters report this from the actual binary.
	WireGuardDevices bool       `json:"wireguard_devices,omitempty"`
	PrivateAccess    bool       `json:"private_access,omitempty"`
	VLESSReverse     bool       `json:"vless_reverse,omitempty"`
	Protocols        []Protocol `json:"protocols"`
	Transports       []string   `json:"transports,omitempty"`
	Shadowsocks2022  bool       `json:"shadowsocks2022,omitempty"`
	HotUserReload    bool       `json:"hot_user_reload,omitempty"`
	Fallbacks        bool       `json:"fallbacks,omitempty"`
	ProxyProtocol    bool       `json:"proxy_protocol,omitempty"`
	SnellMultiUser   bool       `json:"snell_multi_user,omitempty"`
	SnellObfsTLS     bool       `json:"snell_obfs_tls,omitempty"`
	ShadowTLS        bool       `json:"shadow_tls,omitempty"`
	// MieruWildcardOnly marks embedded versions without listen IP support.
	MieruWildcardOnly bool `json:"mieru_wildcard_only,omitempty"`
}

func (c CoreCapabilities) Supports(ib Inbound) bool { return c.UnsupportedReason(ib) == "" }

// UnsupportedReason is a stable, translatable reason code. Shape validation
// (keys, addresses, required TLS, etc.) remains Inbound.Validate's job.
func (c CoreCapabilities) UnsupportedReason(ib Inbound) string {
	if ib.PrivateAccess.Enabled() && ib.PrivateAccess.Enforcement == "auto" {
		if c.PrivateAccessPolicy == nil || !c.PrivateAccessPolicy.Scoped {
			return "privateAccessPolicyUnknown"
		}
		r := c.PrivateAccessReadiness
		if r == nil || (r.EffectiveMode != "dual" && r.EffectiveMode != "core_only") {
			return "privateAccessRuntime"
		}
		if r.EffectiveMode == "core_only" && !c.PrivateAccessPolicy.IndependentDNS {
			return "privateAccessCoreOnly"
		}
		for _, check := range r.Checks {
			if check.ID != "guard" && !check.OK {
				return "privateAccessRuntime"
			}
		}
		p, err := ResolvePrivateAccess(ib.PrivateAccess, r.EffectiveMode == "core_only")
		if err != nil {
			return "privateAccessConfirmation"
		}
		ib.PrivateAccess = p
	}

	switch {
	case ib.WireGuardSlot != 0 && !c.WireGuardReverse:
		return "wireguardReverse"
	case ib.Protocol == Mieru && c.MieruWildcardOnly && ib.Listen != "" && ib.Listen != "::" && ib.Listen != "0.0.0.0":
		return "listenAddress"
	case ib.PrivateAccess.CoreOnly() && (!c.CoreOnlyPrivateAccess || ib.Reverse != nil || ib.WireGuardSlot != 0):
		return "privateAccessCoreOnly"
	case ib.PrivateAccess.Enabled() && ((!ib.PrivateAccess.CoreOnly() && !c.PrivateAccess) || ib.Protocol == WireGuard || (ib.Protocol == Snell && !ib.SnellMultiUser) || (c.VLESSReverse && (ib.Protocol == SOCKS || ib.Protocol == HTTP))):
		return "privateAccess"
	case ib.Reverse != nil && (!c.VLESSReverse || (!ib.Reverse.Receiver && (ib.Protocol == WireGuard || ib.Protocol == SOCKS || ib.Protocol == HTTP))):
		return "reverse"
	case !slices.Contains(c.Protocols, ib.Protocol):
		return "protocol"
	case ib.Protocol == Shadowsocks && strings.HasPrefix(ib.Cipher, "2022-") && !c.Shadowsocks2022:
		return "ss2022"
	case ib.ShadowTLS != nil && !c.ShadowTLS:
		return "shadowTLS"
	case len(ib.Fallbacks) > 0 && !c.Fallbacks:
		return "fallbacks"
	case ib.AcceptProxyProtocol && !c.ProxyProtocol:
		return "proxyProtocol"
	case ib.Protocol == Snell && ib.SnellMultiUser && !c.SnellMultiUser:
		return "snellMultiUser"
	case ib.Protocol == Snell && strings.EqualFold(ib.SnellObfs, "tls") && !c.SnellObfsTLS:
		return "snellTLS"
	case ib.TransportType() != "tcp" && !slices.Contains(c.Transports, ib.TransportType()):
		return "transport"
	default:
		return ""
	}
}

type CoreCandidate struct {
	Name         string           `json:"name"`
	Capabilities CoreCapabilities `json:"capabilities"`
}

// CoreCatalog is also the default preference order. Each call returns fresh
// values so a registry/test cannot mutate the shared catalog.
func CoreCatalog() []CoreCandidate {
	return []CoreCandidate{
		{"singbox", CoreCapabilities{CoreOnlyPrivateAccess: true, PrivateAccess: true, Protocols: []Protocol{VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, SOCKS, HTTP, Naive, Snell}, Transports: []string{"ws", "grpc", "httpupgrade", "http"}, Shadowsocks2022: true, SnellMultiUser: true, ShadowTLS: true}},
		{"xray", CoreCapabilities{WireGuardReverse: true, PrivateAccess: true, Protocols: []Protocol{VLESS, VMess, Trojan, Shadowsocks, SOCKS, HTTP, WireGuard}, Transports: []string{"ws", "grpc", "httpupgrade", "xhttp"}, HotUserReload: true, Fallbacks: true, ProxyProtocol: true, VLESSReverse: true}},
		{"mita", CoreCapabilities{Protocols: []Protocol{Mieru}, HotUserReload: true}},
		{"hysteria", CoreCapabilities{Protocols: []Protocol{Hysteria2}, HotUserReload: true}},
		{"snell", CoreCapabilities{Protocols: []Protocol{Snell}, SnellObfsTLS: true}},
		{"singbox-extended", CoreCapabilities{CoreOnlyPrivateAccess: true, MieruWildcardOnly: true, PrivateAccess: true, Protocols: []Protocol{VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, SOCKS, HTTP, Naive, Snell, Mieru, SSH}, Transports: []string{"ws", "grpc", "httpupgrade", "http"}, Shadowsocks2022: true, SnellMultiUser: true, ShadowTLS: true}},
	}
}

func CapabilitiesForCore(name string) CoreCapabilities {
	for _, c := range CoreCatalog() {
		if c.Name == name {
			return c.Capabilities
		}
	}
	return CoreCapabilities{}
}

// SelectCore is shared by the runtime registry and the panel preview. The
// supplied candidates must be enabled, in the node's configured priority order.
func SelectCore(ib Inbound, enabled []CoreCandidate) (string, error) {
	if ib.Core != "" {
		for _, c := range enabled {
			if c.Name != ib.Core {
				continue
			}
			if reason := c.Capabilities.UnsupportedReason(ib); reason != "" {
				return "", fmt.Errorf("inbound %q: core %q does not support %s over %s (%s)", ib.Tag, ib.Core, ib.Protocol, ib.TransportType(), reason)
			}
			return c.Name, nil
		}
		return "", fmt.Errorf("inbound %q wants core %q which is not enabled", ib.Tag, ib.Core)
	}
	// Xray's REALITY fallback rate limit protects discovered nodes from abuse.
	if ib.TLS != nil && ib.TLS.Mode == TLSReality {
		for _, c := range enabled {
			if c.Name == "xray" && c.Capabilities.Supports(ib) {
				return c.Name, nil
			}
		}
	}
	for _, c := range enabled {
		// Extended Mieru uses distinct login names for per-inbound billing.
		// Moving to it must be an explicit choice followed by a sub refresh.
		if ib.Protocol == Mieru && c.Name == "singbox-extended" {
			continue
		}
		if c.Capabilities.Supports(ib) {
			return c.Name, nil
		}
	}
	return "", fmt.Errorf("inbound %q: no enabled core supports %s over %s", ib.Tag, ib.Protocol, ib.TransportType())
}

type CoreOption struct {
	PrivateAccessPolicy *PrivateAccessPolicyCapabilities `json:"private_access_policy,omitempty"`
	Name                string                           `json:"name"`
	Compatible          bool                             `json:"compatible"`
	Reason              string                           `json:"reason,omitempty"`
	Available           *bool                            `json:"available"` // nil means the node has not advertised capabilities
}
type CoreOptions struct {
	Options                []CoreOption            `json:"options"`
	InventoryKnown         bool                    `json:"inventory_known"`
	AutoCore               string                  `json:"auto_core"`
	PrivateAccessReadiness *PrivateAccessReadiness `json:"private_access_readiness,omitempty"`
}

// PreviewCores keeps unsupported choices in the API for explaining an existing
// pin. The UI filters those choices unless one is currently selected. nil
// inventory means an older/unreported node, not a node with no enabled cores.
func PreviewCores(ib Inbound, inventory []CoreCandidate) CoreOptions {
	out := CoreOptions{Options: []CoreOption{}, InventoryKnown: inventory != nil}
	catalog := CoreCatalog()
	for _, c := range inventory {
		if c.Capabilities.PrivateAccessReadiness != nil {
			out.PrivateAccessReadiness = c.Capabilities.PrivateAccessReadiness
		}
		i := slices.IndexFunc(catalog, func(x CoreCandidate) bool { return x.Name == c.Name })
		if i >= 0 {
			catalog[i] = c
		} else {
			catalog = append(catalog, c)
		}
	}
	for _, c := range catalog {
		reason := c.Capabilities.UnsupportedReason(ib)
		opt := CoreOption{PrivateAccessPolicy: c.Capabilities.PrivateAccessPolicy, Name: c.Name, Compatible: reason == "", Reason: reason}
		if inventory != nil {
			enabled := slices.ContainsFunc(inventory, func(x CoreCandidate) bool { return x.Name == c.Name })
			opt.Available = &enabled
		}
		out.Options = append(out.Options, opt)
	}
	if inventory != nil {
		ib.Core = ""
		out.AutoCore, _ = SelectCore(ib, inventory)
	}
	return out
}

// CoreProbe reads only capability-relevant, non-secret fields. Credentials
// must never be placed in URLs, browser query caches or HTTP access logs.
func CoreProbe(q url.Values) Inbound {
	ib := Inbound{Protocol: Protocol(q.Get("protocol")), Cipher: q.Get("cipher"), Transport: &Transport{Type: q.Get("transport")}, AcceptProxyProtocol: q.Get("proxy_protocol") == "true", SnellMultiUser: q.Get("snell_multi_user") == "true", SnellObfs: q.Get("snell_obfs")}
	if q.Get("reality") == "true" {
		ib.TLS = &TLS{Mode: TLSReality}
	}
	if q.Get("bound_listen") == "true" {
		ib.Listen = "192.0.2.10"
	}
	if q.Get("private_access") == "true" {
		ib.PrivateAccess = &PrivateAccess{Mode: "internal"}
		if e := q.Get("private_enforcement"); e == "core_only" || e == "auto" {
			ib.PrivateAccess.Enforcement = e
		}
		ib.PrivateAccess.AllowCoreOnly = q.Get("allow_core_only") == "true"
	}
	if q.Get("reverse") == "true" {
		ib.Reverse = &ReverseInbound{ID: "preview"}
	}
	if q.Get("shadow_tls") == "true" {
		ib.ShadowTLS = &ShadowTLS{}
	}
	if q.Get("fallbacks") == "true" {
		ib.Fallbacks = []Fallback{{}}
	}
	return ib
}

// CheckCoreListen also applies when an ingress supplies an otherwise omitted
// listen address. An embedded Mieru listener must not silently bind all NICs.
func (ib Inbound) CheckCoreListen(bindIP string) error {
	if ib.Listen == "" {
		ib.Listen = bindIP
	}
	if ib.Core == "singbox-extended" && CapabilitiesForCore(ib.Core).UnsupportedReason(ib) == "listenAddress" {
		return fmt.Errorf("extended Mieru cannot bind a specific IP; select mita instead")
	}
	return nil
}
