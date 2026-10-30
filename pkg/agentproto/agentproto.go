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
	NodeModes bool   `json:"node_modes,omitempty"`
	Code      string `json:"code"`
	Hostname  string `json:"hostname"`
	Version   string `json:"version"`  // bosun version
	Platform  string `json:"platform"` // GOOS/GOARCH
}

// PairResponse carries the permanent node token.
type PairResponse struct {
	NodeID string `json:"node_id"`
	Token  string `json:"token"`
}

// State is the complete desired state for one node. Revision changes
// whenever any part changes; it doubles as the ETag.
type State struct {
	Diagnostics    *DiagnosticsControl `json:"diagnostics,omitempty"`
	ConfigRevision string              `json:"config_revision,omitempty"`
	ConfigDelivery *ConfigDelivery     `json:"config_delivery,omitempty"`
	Revision       string              `json:"revision"`
	Node           spec.Node           `json:"node"`
	Users          []spec.User         `json:"users"`
	Forwards       []spec.Forward      `json:"forwards"`
	// Intervals the agent should use, in seconds.
	PullSeconds int `json:"pull_seconds,omitempty"`
	PushSeconds int `json:"push_seconds,omitempty"`
	// Probe configures host monitoring beats; nil/disabled = only the
	// coarse host snapshot inside Report.
	Probe *spec.Probe `json:"probe,omitempty"`
	// Komari is a retired field, retained for wire compatibility and ignored.
	Komari *spec.Komari `json:"komari,omitempty"`
	// DStatus is a retired field, retained for wire compatibility and ignored.
	DStatus *spec.DStatus `json:"dstatus,omitempty"`
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
	PathHealth     *PathHealthReport     `json:"path_health,omitempty"`
	ConfigReceipt  *ConfigReceipt        `json:"config_receipt,omitempty"`
	ServiceControl *ServiceControlReport `json:"service_control,omitempty"`
	// Hostname is freshly read for each report; omitted on lookup failure.
	Hostname         string           `json:"hostname,omitempty"`
	PublicAddresses  *PublicAddresses `json:"public_addresses,omitempty"`
	WireGuard        *WireGuardReport `json:"wireguard,omitempty"`
	NodeModeRevision uint64           `json:"node_mode_revision,omitempty"`
	NodeMode         spec.NodeMode    `json:"node_mode,omitempty"`
	NodeModeError    string           `json:"node_mode_error,omitempty"`
	Version          string           `json:"version"`
	Revision         string           `json:"revision"` // latest state revision received (not an apply acknowledgment)
	// AppliedRevision is set only after both proxy configuration and forwards
	// from this exact revision were successfully applied by this process. Empty
	// means no current confirmation; older agents omit the field. Liveness and
	// per-inbound acceptance still require Cores/Forwards/WireGuard observations.
	AppliedRevision string             `json:"applied_revision,omitempty"`
	Traffic         []spec.UserTraffic `json:"traffic,omitempty"`
	// TrafficSeq identifies this delta batch. A batch that could not be
	// acknowledged is re-sent unchanged under the same number, so the
	// panel can apply it exactly once. 0 = an agent that does not number
	// its batches (before bosun 0.45).
	TrafficSeq uint64 `json:"traffic_seq,omitempty"`
	// TrafficEpoch identifies the durable journal. New panels retain a cursor
	// per epoch so reinstalls and delayed old deliveries cannot reset it.
	TrafficEpoch string `json:"traffic_epoch,omitempty"`
	// TrafficWindowSeconds is how long the batch has been accumulating,
	// so a rate can be derived from it (a backlog after an outage covers
	// many minutes, not one).
	TrafficWindowSeconds int                   `json:"traffic_window_seconds,omitempty"`
	Online               map[string][]string   `json:"online,omitempty"` // user name -> client IPs
	Forwards             []ForwardStatus       `json:"forwards,omitempty"`
	Cores                map[string]CoreStatus `json:"cores,omitempty"`
	CoreInventory        *spec.CoreInventory   `json:"core_inventory,omitempty"`
	Certs                []CertStatus          `json:"certs,omitempty"`
	Host                 spec.SystemStatus     `json:"host"`
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
	// Audits are the audit-rule hits since the last report (Node.AuditRules).
	Audits       []AuditHit `json:"audits,omitempty"`
	AuditDropped int        `json:"audit_dropped,omitempty"`
}

// AuditHit is one connection that matched an audit rule.
type AuditHit struct {
	At       int64  `json:"at"`
	User     string `json:"user"`
	Inbound  string `json:"inbound,omitempty"`
	ClientIP string `json:"client_ip"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	RuleID   int64  `json:"rule_id"`
	RuleName string `json:"rule_name,omitempty"`
	Action   string `json:"action"`
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
	// Health describes only ProbeProtocol (tcp, none, or backend on apply failure).
	Health        string `json:"health,omitempty"`
	ProbeProtocol string `json:"probe_protocol,omitempty"`
	Tag           string `json:"tag"`
	Up            bool   `json:"up"`
	RTTMillis     int64  `json:"rtt_ms"`
	LastError     string `json:"last_error,omitempty"`
	ActiveConn    int64  `json:"active_conn"`
	TotalConn     int64  `json:"total_conn"`
	BytesIn       int64  `json:"bytes_in"`
	BytesOut      int64  `json:"bytes_out"`
	// Targets is per-hop health for a rule with several targets, Target
	// first (bosun >= 0.49). Up above is then "some hop is up".
	Targets []ForwardTargetStatus `json:"targets,omitempty"`
}

// ForwardTargetStatus is one hop of a forward with several targets.
type ForwardTargetStatus struct {
	// Health describes only ProbeProtocol (tcp, none, or backend on apply failure).
	Health        string `json:"health,omitempty"`
	ProbeProtocol string `json:"probe_protocol,omitempty"`
	Target        string `json:"target"`
	Up            bool   `json:"up"`
	RTTMillis     int64  `json:"rtt_ms"`
	LastError     string `json:"last_error,omitempty"`
	ActiveConn    int64  `json:"active_conn"`
	TotalConn     int64  `json:"total_conn"`
}

// CoreStatus is one core's state.
type CoreStatus struct {
	// Reverse reports applied link IDs. A receiver has a live connection
	// observation; a client is null (configured, connectivity observed at A).
	Reverse map[string]*bool `json:"reverse,omitempty"`
	Running bool             `json:"running"`
	Version string           `json:"version,omitempty"`
	// Capabilities marks the complete enabled-core inventory (priority order).
	// Missing on old nodes; Running=false alone never means unavailable.
	Capabilities *spec.CoreCapabilities `json:"capabilities,omitempty"`
	Priority     int                    `json:"priority,omitempty"`
	Inbounds     []string               `json:"inbounds,omitempty"` // successfully applied tags, only while running
}

// ReportResponse lets Captain nudge the agent to fetch state immediately
// and, when an operator asked for it, upgrade itself.
type ReportResponse struct {
	StateChanged bool `json:"state_changed"`
	// UpgradeTo is a bosun release tag (e.g. "v0.6.0") the agent should
	// install and restart into. Empty means nothing to do.
	UpgradeTo string `json:"upgrade_to,omitempty"`
}

// WireGuardReport contains transport diagnostics, never subscriber accounting.
// Applied is independent of Connected; neither proves exit Internet health.
type WireGuardReport struct {
	Setup     *spec.WireGuardSetup  `json:"setup,omitempty"`
	Available bool                  `json:"available"`
	Applied   bool                  `json:"applied"`
	Links     []WireGuardLinkStatus `json:"links"`
	// DomainPreferenceSupported describes renderer support, not exit reachability.
	DomainPreferenceSupported bool                       `json:"domain_preference_supported,omitempty"`
	ForwardingSupported       bool                       `json:"forwarding_supported,omitempty"`
	Forwarding                *WireGuardForwardingStatus `json:"forwarding,omitempty"`
}

// WireGuardForwardingStatus records a host forwarding check without disclosing
// firewall rules, host addresses or raw command output.
type WireGuardForwardingStatus struct {
	State     string `json:"state"`
	Backend   string `json:"backend"`
	Reason    string `json:"reason"`
	CheckedAt int64  `json:"checked_at"`
}

type WireGuardLinkStatus struct {
	Slot      int    `json:"slot"`
	Connected bool   `json:"connected"`
	Handshake int64  `json:"handshake,omitempty"`
	Receive   uint64 `json:"receive"`
	Transmit  uint64 `json:"transmit"`
	Error     string `json:"error,omitempty"`
}
