package agentproto

import "time"

// PathHealthReport is independent of next-hop TCP health. Samples retain their
// original identity and time across report construction and HTTP retries.
type PathHealthReport struct {
	Supported bool               `json:"supported"`
	Samples   []PathHealthSample `json:"samples,omitempty"`
}

type PathHealthSample struct {
	Tag             string    `json:"tag"`
	RouteID         int64     `json:"route_id"`
	ScopeID         string    `json:"scope_id"`
	CandidateID     string    `json:"candidate_id"`
	ConfigDigest    string    `json:"config_digest"`
	CandidateDigest string    `json:"candidate_digest"`
	Epoch           string    `json:"epoch"`
	Sequence        uint64    `json:"sequence"`
	ObservedAt      time.Time `json:"observed_at"`
	// Health is the hysteresis state, Result is the latest handshake outcome.
	Health    string `json:"health"`
	Result    string `json:"result"`
	RTTMillis int64  `json:"rtt_ms"`
	Error     string `json:"error,omitempty"`
}
