package spec

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
)

// WireGuardLink describes one endpoint of a managed reverse transport.
// Availability requires explicit runtime capability gating on both nodes.
type WireGuardLink struct {
	Slot          int            `json:"slot"`
	Exit          bool           `json:"exit"`
	PrivateKey    string         `json:"private_key"`
	PeerKey       string         `json:"peer_key"`
	Endpoint      string         `json:"endpoint"` // literal public A address:port; empty on A
	ListenPort    int            `json:"listen_port"`
	MTU           int            `json:"mtu"`
	PrivateAccess *PrivateAccess `json:"private_access"`
	// DomainPreference selects the first address family for domains with both
	// A and AAAA records. Empty preserves the original IPv6-first behavior;
	// literal addresses and single-family domains retain their address family.
	DomainPreference string `json:"domain_preference,omitempty"`
	// AutoForwarding lets the exit manage its scoped host forwarding allowance.
	// False preserves externally managed rules; transit endpoints ignore it.
	AutoForwarding bool `json:"auto_forwarding,omitempty"`
}

func (c WireGuardLink) Validate() error {
	if c.Slot < 1 || c.Slot > 16383 {
		return fmt.Errorf("reverse WireGuard slot must be 1-16383")
	}
	for _, k := range []string{c.PrivateKey, c.PeerKey} {
		b, err := base64.StdEncoding.Strict().DecodeString(k)
		if err != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != k {
			return fmt.Errorf("invalid reverse WireGuard key")
		}
		var nonzero byte
		for _, v := range b {
			nonzero |= v
		}
		if nonzero == 0 {
			return fmt.Errorf("zero reverse WireGuard key")
		}
	}
	if c.ListenPort < 0 || c.ListenPort > 65535 || (!c.Exit && c.ListenPort == 0) {
		return fmt.Errorf("invalid reverse WireGuard listen port")
	}
	if c.MTU < 1280 || c.MTU > 1420 {
		return fmt.Errorf("reverse WireGuard MTU must be 1280-1420")
	}
	if c.DomainPreference != "" && c.DomainPreference != "ipv4" && c.DomainPreference != "ipv6" {
		return fmt.Errorf("reverse WireGuard domain preference must be ipv4 or ipv6")
	}
	if c.Exit {
		ep, err := netip.ParseAddrPort(c.Endpoint)
		if err != nil || ep.Port() == 0 || ep.Addr().Zone() != "" || ep.Addr().Is4In6() || !ep.Addr().IsGlobalUnicast() {
			return fmt.Errorf("reverse WireGuard exit requires a literal unicast endpoint")
		}
	} else if c.Endpoint != "" {
		return fmt.Errorf("reverse WireGuard transit learns its peer endpoint")
	}
	if err := c.PrivateAccess.Validate(); err != nil {
		return err
	}
	if c.PrivateAccess.Enabled() && (c.PrivateAccess.CoreOnly() || c.PrivateAccess.Enforcement == "auto") {
		return fmt.Errorf("reverse WireGuard requires explicit OS-enforced private access")
	}
	if c.PrivateAccess != nil && c.PrivateAccess.Mode == "internal" {
		return fmt.Errorf("reverse WireGuard requires explicit private destination rules")
	}
	return nil
}

func (c WireGuardLink) Interface() string { return "bwg" + strconv.Itoa(c.Slot) }
func (c WireGuardLink) Table() int        { return 42000 + c.Slot }
func (c WireGuardLink) Address(exit bool, ipv6 bool) string {
	n := c.Slot*4 + 1
	if exit {
		n++
	}
	if ipv6 {
		return fmt.Sprintf("fd42:626f:7375::%x", n)
	}
	return fmt.Sprintf("10.10.%d.%d", n/256, n%256)
}

func (n *Node) ValidateWireGuardLinks() error {
	if len(n.WireGuardLinks) > 64 {
		return fmt.Errorf("at most 64 WireGuard links per node")
	}
	links := map[int]WireGuardLink{}
	ports := map[int]bool{}
	for _, c := range n.WireGuardLinks {
		if err := c.Validate(); err != nil {
			return err
		}
		if _, ok := links[c.Slot]; ok {
			return fmt.Errorf("duplicate WireGuard slot")
		}
		links[c.Slot] = c
		if c.ListenPort > 0 {
			if ports[c.ListenPort] {
				return fmt.Errorf("duplicate WireGuard listen port")
			}
			ports[c.ListenPort] = true
		}
	}
	for _, ib := range n.Inbounds {
		if len(links) > 0 && ib.Tag == "bosun-private-dns" {
			return fmt.Errorf("bosun-private-dns is reserved for managed DNS")
		}
		if ports[ib.Port] {
			return fmt.Errorf("WireGuard port overlaps an inbound")
		}
		if ib.WireGuardSlot == 0 {
			continue
		}
		if err := ib.Validate(); err != nil {
			return err
		}
		c, ok := links[ib.WireGuardSlot]
		if !ok || c.Exit {
			return fmt.Errorf("WireGuard inbound has no managed transit link")
		}
		if ib.Protocol == WireGuard {
			if ib.WGMTU > c.MTU {
				return fmt.Errorf("WireGuard user MTU must not exceed transport MTU")
			}
			if ib.WGAddress != "" {
				prefix, err := netip.ParsePrefix(ib.WGAddress)
				if err != nil {
					return err
				}
				for _, link := range links {
					for _, exit := range []bool{false, true} {
						for _, v6 := range []bool{false, true} {
							if prefix.Contains(netip.MustParseAddr(link.Address(exit, v6))) {
								return fmt.Errorf("WireGuard user network overlaps transport network")
							}
						}
					}
				}
			}
		}
		if !reflect.DeepEqual(ib.PrivateAccess.EffectiveRules(), c.PrivateAccess.EffectiveRules()) {
			return fmt.Errorf("WireGuard inbound and link private grants must match")
		}
	}
	for _, f := range n.Forwards {
		if ports[f.Port] {
			return fmt.Errorf("WireGuard port overlaps a forward")
		}
	}
	if len(links) == 0 {
		return nil
	}
	// Shared shaping currently combines the primary physical interface and
	// managed tunnels. Source-specific ordinary egress could bypass that set.
	if n.EgressByIngress {
		return fmt.Errorf("managed WireGuard cannot combine with per-ingress source egress")
	}
	if n.Mode.Effective() == NodeMonitor {
		return ErrMonitorOnly
	}
	if n.AllowPrivateDest || len(n.PrivateDestAllow) > 0 {
		return fmt.Errorf("managed WireGuard cannot use global private access exceptions")
	}
	for _, o := range n.Outbounds {
		if strings.HasPrefix(o.Tag, "wireguard-") {
			return fmt.Errorf("wireguard- outbound tags are reserved")
		}
	}
	return CheckWireGuardOverrides(n.Overrides)
}

// CheckWireGuardOverrides prevents an opaque patch from bypassing managed routing.
func CheckWireGuardOverrides(overrides map[string]json.RawMessage) error {
	for _, family := range []string{"xray", "singbox", "singbox-extended"} {
		var patch map[string]any
		if raw := overrides[family]; len(raw) > 0 {
			if json.Unmarshal(raw, &patch) != nil {
				return fmt.Errorf("invalid managed core override")
			}
			for key := range patch {
				switch strings.ToLower(key) {
				case "routing", "route", "outbounds", "inbounds", "policy", "dns", "endpoints", "experimental":
					return fmt.Errorf("managed WireGuard cannot override %s %s", family, key)
				}
			}
		}
	}
	return nil
}
