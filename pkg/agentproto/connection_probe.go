package agentproto

const ConnectionProbeVersionHeader = "X-Bosun-Migration-Probe"
const ConnectionProbeCursorHeader = "X-Bosun-Migration-Probe-Cursor"
const ConnectionProbeVersion = "1"

// ConnectionProbe carries no authorization to migrate or send credentials to
// its target. Results go only to the currently authenticated source connection.
type ConnectionProbe struct {
	ID        string `json:"id"`
	TargetURL string `json:"target_url"`
	ProofKey  string `json:"proof_key"`
	ExpiresAt int64  `json:"expires_at"`
}
type ConnectionProbeResult struct {
	ID     string `json:"id"`
	Status string `json:"status"` // direct | trusted-proxy | failed
	Error  string `json:"error,omitempty"`
}

func ProbeConnectionBinding(expires int64) string {
	return "probe-v1:" + ProxyConnectionBinding(expires)
}
