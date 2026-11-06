package agentproto

import (
	"encoding/json"
	"testing"
)

func TestPublicAddressFallbackIsAdditiveAndNeverLegacyConsensus(t *testing.T) {
	in := PublicAddresses{SampledAt: 100, FallbackIPv4: &PublicAddressFallback{
		Address: "198.51.100.20", Source: PublicAddressFallbackSource,
		Origin: "https://example.com:2096", SampledAt: 100,
		CheckStatus: PublicAddressFallbackCheckNoConflict, RunID: "b0123456789012345678901234567890b",
	}}
	body, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	// This is the previous wire contract consumed by older Captain versions.
	var old struct {
		SampledAt int64  `json:"sampled_at"`
		IPv4      string `json:"ipv4"`
		IPv6      string `json:"ipv6"`
	}
	if err := json.Unmarshal(body, &old); err != nil {
		t.Fatal(err)
	}
	if old.SampledAt != 100 || old.IPv4 != "" || old.IPv6 != "" {
		t.Fatalf("advisory promoted in old reader: %+v", old)
	}
	var out PublicAddresses
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.FallbackIPv4 == nil || *out.FallbackIPv4 != *in.FallbackIPv4 || out.FallbackIPv6 != nil {
		t.Fatalf("round trip: %+v", out)
	}
	out = PublicAddresses{}
	if err := json.Unmarshal([]byte(`{"sampled_at":101,"ipv4":"203.0.113.30"}`), &out); err != nil {
		t.Fatal(err)
	}
	if out.IPv4 != "203.0.113.30" || out.FallbackIPv4 != nil || out.FallbackIPv6 != nil {
		t.Fatal("legacy observation lost")
	}
	if err := json.Unmarshal([]byte(`{"sampled_at":101,"fallback_ipv4":{"address":"198.51.100.20","source":"captain_cloudflare_trace","origin":"https://example.com:2096","sampled_at":101}}`), &out); err != nil {
		t.Fatal(err)
	}
	if out.FallbackIPv4 == nil || out.FallbackIPv4.CheckStatus != "" || out.FallbackIPv4.RunID != "" {
		t.Fatal("old fallback gained invented follow evidence")
	}
}
