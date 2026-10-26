package spec

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// CarrierProbeConfig retains independent target lists while switching the
// selected protocol and family. Empty lists use the NextTrace Beijing targets.
// Its presence supersedes the legacy CarrierPing/Carriers runtime settings.
type CarrierProbeConfig struct {
	Protocol string    `json:"protocol" yaml:"protocol"`
	Family   string    `json:"family" yaml:"family"`
	TCPIPv4  []Carrier `json:"tcp_ipv4,omitempty" yaml:"tcp_ipv4,omitempty"`
	TCPIPv6  []Carrier `json:"tcp_ipv6,omitempty" yaml:"tcp_ipv6,omitempty"`
	ICMPIPv4 []Carrier `json:"icmp_ipv4,omitempty" yaml:"icmp_ipv4,omitempty"`
	ICMPIPv6 []Carrier `json:"icmp_ipv6,omitempty" yaml:"icmp_ipv6,omitempty"`
}

func (c *CarrierProbeConfig) Clone() *CarrierProbeConfig {
	if c == nil {
		return nil
	}
	v := *c
	v.TCPIPv4 = append([]Carrier(nil), c.TCPIPv4...)
	v.TCPIPv6 = append([]Carrier(nil), c.TCPIPv6...)
	v.ICMPIPv4 = append([]Carrier(nil), c.ICMPIPv4...)
	v.ICMPIPv6 = append([]Carrier(nil), c.ICMPIPv6...)
	return &v
}

// Normalize returns an independent copy; unknown values remain invalid.
func (c CarrierProbeConfig) Normalize() CarrierProbeConfig {
	v := *c.Clone()
	v.Protocol = strings.ToLower(strings.TrimSpace(v.Protocol))
	v.Family = strings.ToLower(strings.TrimSpace(v.Family))
	if v.Protocol == "" {
		v.Protocol = "tcp"
	}
	if v.Family == "" {
		v.Family = "ipv4"
	}
	for _, list := range [][]Carrier{v.TCPIPv4, v.TCPIPv6, v.ICMPIPv4, v.ICMPIPv6} {
		for i := range list {
			list[i].Name = strings.TrimSpace(list[i].Name)
			list[i].Addr = strings.TrimSpace(list[i].Addr)
		}
	}
	return v
}

func (c CarrierProbeConfig) Validate() error {
	c = c.Normalize()
	if c.Protocol != "tcp" && c.Protocol != "icmp" {
		return fmt.Errorf("carrier protocol must be tcp or icmp")
	}
	if c.Family != "ipv4" && c.Family != "ipv6" && c.Family != "dual" {
		return fmt.Errorf("carrier family must be ipv4, ipv6 or dual")
	}
	for _, group := range []struct {
		protocol, family string
		list             []Carrier
	}{{"tcp", "ipv4", c.TCPIPv4}, {"tcp", "ipv6", c.TCPIPv6}, {"icmp", "ipv4", c.ICMPIPv4}, {"icmp", "ipv6", c.ICMPIPv6}} {
		if len(group.list) > 16 {
			return fmt.Errorf("at most 16 carrier targets per protocol and family")
		}
		seen := map[string]bool{}
		for _, target := range group.list {
			if target.Name == "" || !PublicLabel(target.Name) || len(target.Name) > 128 || seen[target.Name] {
				return fmt.Errorf("carrier targets require unique public names")
			}
			seen[target.Name] = true
			if group.protocol == "tcp" {
				if host, port, err := net.SplitHostPort(target.Addr); err != nil || host == "" || port == "" {
					return fmt.Errorf("TCP carrier target must be host:port")
				}
			}
			if err := (PingTask{Name: target.Name, Type: group.protocol, Target: target.Addr, Family: group.family}).Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}

// DefaultCarrierTargets does not guess endpoints for unsupported modes.
func DefaultCarrierTargets(protocol, family string) []Carrier {
	if (protocol != "tcp" && protocol != "icmp") || (family != "ipv4" && family != "ipv6") {
		return nil
	}
	out := []Carrier{}
	for _, target := range []struct{ name, asn string }{{"CT", "4134"}, {"CU", "4837"}, {"CM", "9808"}} {
		addr := family + ".pek-" + target.asn + ".endpoint.nxtrace.org"
		if protocol == "tcp" {
			addr = net.JoinHostPort(addr, "80")
		}
		out = append(out, Carrier{Name: target.name, Addr: addr})
	}
	return out
}

// CarrierSeries identifies the full measurement definition without disclosing
// its target to public consumers. The name intentionally remains human readable.
func CarrierSeries(protocol, family, name, target string) string {
	h := sha256.Sum256([]byte(protocol + "\x00" + family + "\x00" + name + "\x00" + target))
	return "carrier:" + hex.EncodeToString(h[:])
}
func ValidCarrierSeries(v string) bool {
	if len(v) != 72 || !strings.HasPrefix(v, "carrier:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(v, "carrier:"))
	return err == nil && strings.ToLower(v) == v
}

// Tasks returns no tasks for an invalid config, rather than falling back to a
// different protocol, address family or target.
func (c CarrierProbeConfig) Tasks() []PingTask {
	c = c.Normalize()
	if c.Validate() != nil {
		return nil
	}
	families := []string{c.Family}
	if c.Family == "dual" {
		families = []string{"ipv4", "ipv6"}
	}
	out := []PingTask{}
	for _, family := range families {
		var targets []Carrier
		switch c.Protocol + "/" + family {
		case "tcp/ipv4":
			targets = c.TCPIPv4
		case "tcp/ipv6":
			targets = c.TCPIPv6
		case "icmp/ipv4":
			targets = c.ICMPIPv4
		case "icmp/ipv6":
			targets = c.ICMPIPv6
		}
		if len(targets) == 0 {
			targets = DefaultCarrierTargets(c.Protocol, family)
		}
		for _, target := range targets {
			out = append(out, PingTask{Name: target.Name, Type: c.Protocol, Target: target.Addr, Family: family, Series: CarrierSeries(c.Protocol, family, target.Name, target.Addr), IntervalSeconds: 10, TCPReachability: c.Protocol == "tcp"})
		}
	}
	return out
}
