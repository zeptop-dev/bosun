package agentproto

import "net/netip"

// PublicAddresses is an observation of outbound public addresses, not a claim
// about inbound reachability. Empty families mean unknown, never deletion.
type PublicAddresses struct {
	SampledAt int64  `json:"sampled_at"`
	IPv4      string `json:"ipv4,omitempty"`
	IPv6      string `json:"ipv6,omitempty"`

	// Single-source fallback observations are advisory only. Older Captains ignore
	// these fields; they must never enter the consensus IPv4/IPv6 slots above.
	FallbackIPv4 *PublicAddressFallback `json:"fallback_ipv4,omitempty"`
	FallbackIPv6 *PublicAddressFallback `json:"fallback_ipv6,omitempty"`
}

const PublicAddressFallbackSource = "captain_cloudflare_trace"

// PublicAddressFallback records one anonymous observation through the configured
// Captain origin, not independent consensus or proof of inbound reachability.
// Error is a bounded code, never remote content or a credential-bearing URL.
type PublicAddressFallback struct {
	Address   string `json:"address,omitempty"`
	Source    string `json:"source"`
	Origin    string `json:"origin"`
	SampledAt int64  `json:"sampled_at"`
	Error     string `json:"error,omitempty"`
}

func ValidPublicAddress(value string, v6 bool) bool {
	a, err := netip.ParseAddr(value)
	return err == nil && a.Zone() == "" && !a.Is4In6() && a.Is6() == v6 && a.IsGlobalUnicast() && !a.IsPrivate() && !netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}
