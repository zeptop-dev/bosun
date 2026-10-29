package agentproto

// ServiceControlReport describes an independently checked runtime policy.
// Supported includes Linux/nft permission and isolated core/socket ownership.
// AppliedRevision is empty while apply/cleanup/verification is incomplete;
// Mode and LimitMbps describe the last installed policy, not desired intent.
type ServiceControlReport struct {
	OfflineSupported bool                  `json:"offline_supported,omitempty"`
	Offline          *OfflineControlReport `json:"offline,omitempty"`
	Supported        bool                  `json:"supported"`
	Reason           string                `json:"reason,omitempty"`
	DesiredRevision  string                `json:"desired_revision,omitempty"`
	AppliedRevision  string                `json:"applied_revision,omitempty"`
	Mode             string                `json:"mode,omitempty"`
	LimitMbps        int                   `json:"limit_mbps,omitempty"`
	Error            string                `json:"error,omitempty"`
	CheckedAt        int64                 `json:"checked_at"`
}

// OfflineControlReport is execution evidence, not a customer traffic receipt.
type OfflineControlReport struct {
	PolicyID    string `json:"policy_id"`
	Cycle       int64  `json:"cycle"`
	PeriodStart int64  `json:"period_start"`
	UsedBytes   int64  `json:"used_bytes"`
	Automatic   bool   `json:"automatic"`
	State       string `json:"state"` // ready, active, waiting, error
	Error       string `json:"error,omitempty"`
}
