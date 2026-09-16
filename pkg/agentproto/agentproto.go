// Package agentproto defines the wire types between Captain and bosun. Both
// sides import this package, so there is one definition of every message.
//
// Endpoints (all JSON, node token as "Authorization: Bearer <token>"):
//
//	POST /api/agent/pair    PairRequest  -> PairResponse   (pairing code, no token yet)
//	GET  /api/agent/state   ?wait=30s, If-None-Match      -> State (200) or 304
//	POST /api/agent/report  Report       -> ReportResponse
package agentproto

import (
	"encoding/json"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

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
	// Probe configures host monitoring beats; nil/disabled = only the
	// coarse host snapshot inside Report.
	Probe *spec.Probe `json:"probe,omitempty"`
	// Komari asks the node to also report to a Komari server.
	Komari *spec.Komari `json:"komari,omitempty"`
	// Jobs are one-off tasks the node should run once; results ride on a
	// later Report and the panel then drops the job from the state.
	Jobs []Job `json:"jobs,omitempty"`
}

// Job is a one-off task. Kinds: "reality_scan" with params
// {"hosts": ["www.example.com"], "port": 443} (empty hosts = default pool).
type Job struct {
	ID     string          `json:"id"`
	Kind   string          `json:"kind"`
	Params json.RawMessage `json:"params,omitempty"`
}

// JobResult is the outcome of a Job.
type JobResult struct {
	ID     string          `json:"id"`
	Kind   string          `json:"kind"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// Beat is the light, frequent host sample sent while probing is enabled.
type Beat struct {
	Version string            `json:"version"`
	Host    spec.SystemStatus `json:"host"`
}

// Report is what bosun pushes every push interval.
type Report struct {
	Version  string                `json:"version"`
	Revision string                `json:"revision"` // state revision currently applied
	Traffic  []spec.UserTraffic    `json:"traffic,omitempty"`
	Online   map[string][]string   `json:"online,omitempty"` // user name -> client IPs
	Forwards []ForwardStatus       `json:"forwards,omitempty"`
	Cores    map[string]CoreStatus `json:"cores,omitempty"`
	Certs    []CertStatus          `json:"certs,omitempty"`
	Host     spec.SystemStatus     `json:"host"`
	// Doctor is the node's latest self-check, sent when it changed and at
	// least every 30 minutes.
	Doctor *DoctorReport `json:"doctor,omitempty"`
	// Jobs are results of State.Jobs finished since the last report.
	Jobs []JobResult `json:"jobs,omitempty"`
	// Inbounds is traffic per inbound tag since the last report (cores
	// that count it: xray, sing-box).
	Inbounds map[string]spec.Traffic `json:"inbounds,omitempty"`
	// Outbounds is traffic per outbound tag since the last report.
	Outbounds map[string]spec.Traffic `json:"outbounds,omitempty"`
	// Connections are the accepted connections since the last report when
	// the node spec asks for them (Node.ConnLog); ConnDropped counts the
	// ones the bounded buffer had to discard.
	Connections []ConnEvent `json:"connections,omitempty"`
	ConnDropped int         `json:"conn_dropped,omitempty"`
}

// ConnEvent is one accepted connection.
type ConnEvent struct {
	At       int64  `json:"at"` // unix seconds
	User     string `json:"user"`
	Inbound  string `json:"inbound,omitempty"`
	ClientIP string `json:"client_ip"`
	Host     string `json:"host"` // destination host name or address
	Port     int    `json:"port"`
	Network  string `json:"net,omitempty"` // tcp or udp
}

// DoctorCheck is one verdict of the node's self-check.
type DoctorCheck struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"` // ok | warn | fail | skip
	Detail string `json:"detail,omitempty"`
}

// DoctorSummary counts checks by status.
type DoctorSummary struct {
	OK   int `json:"ok"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
	Skip int `json:"skip"`
}

// DoctorReport is one self-check run.
type DoctorReport struct {
	At      time.Time     `json:"at"`
	Checks  []DoctorCheck `json:"checks"`
	Summary DoctorSummary `json:"summary"`
}

// Failed reports whether any check failed.
func (r DoctorReport) Failed() bool { return r.Summary.Fail > 0 }

// Same reports whether two reports carry the same verdicts (time aside).
func (r DoctorReport) Same(o *DoctorReport) bool {
	if o == nil || len(r.Checks) != len(o.Checks) {
		return false
	}
	for i := range r.Checks {
		if r.Checks[i] != o.Checks[i] {
			return false
		}
	}
	return true
}

// CertStatus is one automatically managed certificate.
type CertStatus struct {
	Domain   string    `json:"domain"`
	Method   string    `json:"method"`
	NotAfter time.Time `json:"not_after"`
	Error    string    `json:"error,omitempty"`
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
