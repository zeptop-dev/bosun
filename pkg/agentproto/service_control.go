package agentproto

// ServiceControlReport describes an independently checked runtime policy.
// Supported includes Linux/nft permission and isolated core/socket ownership.
// AppliedRevision is empty while apply/cleanup/verification is incomplete;
// Mode and LimitMbps describe the last installed policy, not desired intent.
type ServiceControlReport struct {
	Supported       bool   `json:"supported"`
	Reason          string `json:"reason,omitempty"`
	DesiredRevision string `json:"desired_revision,omitempty"`
	AppliedRevision string `json:"applied_revision,omitempty"`
	Mode            string `json:"mode,omitempty"`
	LimitMbps       int    `json:"limit_mbps,omitempty"`
	Error           string `json:"error,omitempty"`
	CheckedAt       int64  `json:"checked_at"`
}
