// Package agentproto defines the wire types between Captain and bosun. Both
// sides import this package, so there is one definition of every message.
//
// Endpoints (all JSON, node token as "Authorization: Bearer <token>"):
//
//	POST /api/agent/pair    PairRequest  -> PairResponse   (pairing code, no token yet)
//	GET  /api/agent/state   ?wait=30s, If-None-Match      -> State (200) or 304
//	POST /api/agent/report  Report       -> ReportResponse
package agentproto

import "github.com/zeptop-dev/bosun/pkg/spec"

// PairRequest redeems a one-time pairing code for a node token.
type PairRequest struct {
	Code     string `json:"code"`
	Hostname string `json:"hostname"`
	Version  string `json:"version"`  // bosun version
	Platform string `json:"platform"` // GOOS/GOARCH
}

// PairResponse carries the permanent node token.
type PairResponse struct {
	NodeID string `json:"node_id"`
	Token  string `json:"token"`
}

// State is the complete desired state for one node. Revision changes
// whenever any part changes; it doubles as the ETag.
type State struct {
	Revision string         `json:"revision"`
	Node     spec.Node      `json:"node"`
	Users    []spec.User    `json:"users"`
	Forwards []spec.Forward `json:"forwards"`
	// Intervals the agent should use, in seconds.
	PullSeconds int `json:"pull_seconds,omitempty"`
	PushSeconds int `json:"push_seconds,omitempty"`
}

// Report is what bosun pushes every push interval.
type Report struct {
	Version  string                `json:"version"`
	Revision string                `json:"revision"` // state revision currently applied
	Traffic  []spec.UserTraffic    `json:"traffic,omitempty"`
	Online   map[string][]string   `json:"online,omitempty"` // user name -> client IPs
	Forwards []ForwardStatus       `json:"forwards,omitempty"`
	Cores    map[string]CoreStatus `json:"cores,omitempty"`
	Host     spec.SystemStatus     `json:"host"`
}

// ForwardStatus is one relay rule's health and counters.
type ForwardStatus struct {
	Tag        string `json:"tag"`
	Up         bool   `json:"up"`
	RTTMillis  int64  `json:"rtt_ms"`
	LastError  string `json:"last_error,omitempty"`
	ActiveConn int64  `json:"active_conn"`
	TotalConn  int64  `json:"total_conn"`
	BytesIn    int64  `json:"bytes_in"`
	BytesOut   int64  `json:"bytes_out"`
}

// CoreStatus is one core's state.
type CoreStatus struct {
	Running bool   `json:"running"`
	Version string `json:"version,omitempty"`
}

// ReportResponse lets Captain nudge the agent to fetch state immediately
// and, when an operator asked for it, upgrade itself.
type ReportResponse struct {
	StateChanged bool `json:"state_changed"`
	// UpgradeTo is a bosun release tag (e.g. "v0.6.0") the agent should
	// install and restart into. Empty means nothing to do.
	UpgradeTo string `json:"upgrade_to,omitempty"`
}
