package agentproto

import "time"

const (
	DiagnosticsVersionHeader   = "X-Bosun-Diagnostics-Version"
	DiagnosticsNonceHeader     = "X-Bosun-Diagnostics-Nonce"
	DiagnosticsChallengeHeader = "X-Bosun-Diagnostics-Challenge"
	DiagnosticsCursorHeader    = "X-Bosun-Diagnostics-Cursor"
	DiagnosticsVersion         = "1"
	DiagnosticsMaxSampleBytes  = 8192
	DiagnosticsMaxInterfaces   = 16
	DiagnosticsMaxLeaseMS      = 15000
)

// DiagnosticsControl is transient observation metadata. It is not desired
// configuration, must not be persisted for offline recovery, and cannot renew
// a lease without a newer Generation. RemainingMS is measured from the request
// start on the agent's monotonic clock, not from receipt of the response.
type DiagnosticsControl struct {
	Session      string `json:"session"`
	RequestNonce string `json:"request_nonce"`
	Challenge    string `json:"challenge"`
	Epoch        string `json:"epoch"`
	Generation   uint64 `json:"generation"`
	RemainingMS  int64  `json:"remaining_ms"`
	IntervalMS   int    `json:"interval_ms"`
}

// DiagnosticsSample contains passive host observations only. Nil rates mean
// unavailable, first sample, counter reset or a sampling gap; zero is measured.
// SampledAt is the actual observation time; ElapsedMS is the sampling interval.
// This stream never bills traffic.
type DiagnosticsSample struct {
	Session     string                 `json:"session"`
	Epoch       string                 `json:"epoch"`
	Sequence    uint64                 `json:"sequence"`
	SampledAt   time.Time              `json:"sampled_at"`
	ElapsedMS   int64                  `json:"elapsed_ms"`
	CPUPercent  *float64               `json:"cpu_percent"`
	MemoryUsed  *uint64                `json:"memory_used"`
	MemoryTotal *uint64                `json:"memory_total"`
	NetUpBPS    *float64               `json:"net_up_bps"`
	NetDownBPS  *float64               `json:"net_down_bps"`
	Interfaces  []DiagnosticsInterface `json:"interfaces"`
	Truncated   bool                   `json:"truncated"`
}

type DiagnosticsInterface struct {
	Name  string   `json:"name"`
	RXBPS *float64 `json:"rx_bps"`
	TXBPS *float64 `json:"tx_bps"`
}
