package spec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ProbeTimings are durations of completed phases in milliseconds. A nil phase
// was not performed/completed; it is not a measured zero. Response is the wait
// from writing the HTTP request to its first response byte (excluding DNS/TLS).
type ProbeTimings struct {
	DNS      *float64 `json:"dns_ms"`
	Connect  *float64 `json:"connect_ms"`
	TLS      *float64 `json:"tls_ms"`
	Response *float64 `json:"response_ms"`
}

type ProbeWindow struct {
	Attempts int      `json:"attempts"`
	Failed   int      `json:"failed"`
	Min      *float64 `json:"min_ms"`
	Max      *float64 `json:"max_ms"`
	P50      *float64 `json:"p50_ms"`
	P95      *float64 `json:"p95_ms"`
	Jitter   *float64 `json:"jitter_ms"` // mean absolute difference of adjacent successes; failures break adjacency
}

// ProbeMeasurement is one attempt, never a best-of-retries measurement.
type ProbeMeasurement struct {
	Sequence   uint64        `json:"sequence"`
	At         int64         `json:"at"`         // actual completion time, Unix seconds
	LatencyMs  float64       `json:"latency_ms"` // -1 on failure
	Mbps       float64       `json:"mbps,omitempty"`
	Bytes      int64         `json:"bytes,omitempty"` // bytes read during a bounded download
	Outcome    string        `json:"outcome"`         // bounded classification, never a raw error or URL
	DurationMs float64       `json:"duration_ms"`
	HTTPStatus int           `json:"http_status,omitempty"`
	Timings    *ProbeTimings `json:"timings,omitempty"`
}

type PingQuality struct {
	ProbeMeasurement
	Epoch           string      `json:"epoch"`
	Type            string      `json:"type"` // icmp | tcp | tcp_reachability | http | download
	IntervalSeconds int         `json:"interval_seconds"`
	Window          ProbeWindow `json:"window"`
	// Earliest actual completion time included in Window, not a sequence/interval estimate.
	// Zero means unknown; receivers must normalize it with the latest measurement clock.
	WindowStartedAt int64 `json:"window_started_at,omitempty"`
	// Recent contains up to 60 unacknowledged attempts on Captain beats only.
	// Replays are deduplicated by (node, task, name, epoch, sequence).
	Recent []ProbeMeasurement `json:"recent,omitempty"`
}

func ProbeOutcome(s string) bool {
	switch s {
	case "ok", "refused", "timeout", "dns", "tls", "permission", "unreachable", "http_status", "io", "invalid", "canceled", "empty", "interface", "unsupported":
		return true
	}
	return false
}
func (m ProbeMeasurement) Valid() bool {
	if m.Bytes < 0 || m.Bytes > 64<<20 {
		return false
	}
	finite := func(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
	if m.Sequence == 0 || m.Sequence > math.MaxInt64 || m.At <= 0 || !ProbeOutcome(m.Outcome) || !finite(m.LatencyMs) || m.LatencyMs < -1 || m.LatencyMs > 60000 || !finite(m.DurationMs) || m.DurationMs < 0 || m.DurationMs > 60000 || !finite(m.Mbps) || m.Mbps < 0 || m.HTTPStatus < 0 || m.HTTPStatus > 599 {
		return false
	}
	if m.Timings != nil {
		for _, v := range []*float64{m.Timings.DNS, m.Timings.Connect, m.Timings.TLS, m.Timings.Response} {
			if v != nil && (!finite(*v) || *v < 0 || *v > 60000) {
				return false
			}
		}
	}
	return true
}

// Validate is shared by both panels and the runner. Targets are admin-chosen;
// private addresses are allowed for explicitly configured line/service checks.
func (t PingTask) Validate() error {
	if len(t.Name) > 128 || len(t.Target) > 2048 || !PublicLabel(t.Name) || !Plain(t.Target) || strings.ContainsAny(t.Target, " \t\"'") || t.Target == "" {
		return fmt.Errorf("invalid probe name or target")
	}
	if t.Family != "" && t.Family != "ipv4" && t.Family != "ipv6" {
		return fmt.Errorf("probe family must be ipv4 or ipv6")
	}
	if t.Series != "" {
		if t.SourceInterface != "" {
			if !ValidProbeTaskSeries(t.Series) || t.Series != ProbeTaskSeries(t) {
				return fmt.Errorf("invalid interface probe series")
			}
		} else if t.ID != 0 || !ValidCarrierSeries(t.Series) {
			return fmt.Errorf("invalid carrier series")
		}
	}
	if t.SourceInterface != "" {
		if err := ValidateProbeInterface(t.SourceInterface); err != nil {
			return err
		}
		if t.Type != "tcp" && t.Type != "icmp" {
			return fmt.Errorf("interface binding requires TCP or ICMP")
		}
		host := t.Target
		if t.Type == "tcp" {
			h, port, err := net.SplitHostPort(host)
			if err != nil {
				return fmt.Errorf("interface-bound TCP target must be IP:port")
			}
			n, err := strconv.Atoi(port)
			if err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("interface-bound TCP target requires a numeric port")
			}
			host = h
		}
		if net.ParseIP(host) == nil {
			return fmt.Errorf("interface-bound target must be a literal IP address")
		}
	}
	if t.Family != "" {
		if t.Type != "tcp" && t.Type != "icmp" {
			return fmt.Errorf("explicit family requires TCP or ICMP")
		}
		host := t.Target
		if t.Type == "tcp" {
			if v, _, err := net.SplitHostPort(host); err == nil {
				host = v
			}
		}
		for _, address := range []string{host, t.SourceIP} {
			if ip := net.ParseIP(address); ip != nil && (ip.To4() != nil) != (t.Family == "ipv4") {
				return fmt.Errorf("probe address does not match requested family")
			}
		}
	}
	if t.SourceIP != "" && net.ParseIP(t.SourceIP) == nil {
		return fmt.Errorf("source must be an IP")
	}
	if t.TCPReachability && !strings.EqualFold(t.Type, "tcp") {
		return fmt.Errorf("TCP reachability requires a TCP task")
	}
	switch strings.ToLower(t.Type) {
	case "icmp":
		if strings.ContainsAny(t.Target, "/?#@") || (net.ParseIP(t.Target) == nil && strings.Contains(t.Target, ":")) {
			return fmt.Errorf("ICMP target must be a host or IP")
		}
	case "tcp":
		target := t.Target
		if _, _, err := net.SplitHostPort(target); err != nil {
			target = net.JoinHostPort(target, "80")
		}
		host, port, err := net.SplitHostPort(target)
		if err != nil || host == "" || port == "" || strings.ContainsAny(host, "/?#@") || (strings.Contains(host, ":") && net.ParseIP(host) == nil) {
			return fmt.Errorf("TCP target must be host:port")
		}
		if _, err := net.LookupPort("tcp", port); err != nil {
			return fmt.Errorf("invalid TCP port")
		}
	case "http", "download":
		target := t.Target
		if !strings.Contains(target, "://") {
			target = "https://" + target
		}
		u, err := url.Parse(target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
			return fmt.Errorf("HTTP target must be an HTTP(S) URL without user credentials")
		}
	default:
		return fmt.Errorf("type must be icmp, tcp, http or download")
	}
	return nil
}

// ValidateProbeInterface permits actual device names without shell or UCI syntax.
func ValidateProbeInterface(name string) error {
	if name == "" {
		return nil
	}
	if len(name) > 15 || name == "." || name == ".." {
		return fmt.Errorf("invalid probe interface name")
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return fmt.Errorf("invalid probe interface name")
		}
	}
	return nil
}

// ProbeTaskSeries separates interface/path changes from earlier observations.
// Empty-interface tasks retain their legacy identity and wire representation.
func ProbeTaskSeries(t PingTask) string {
	if t.SourceInterface == "" {
		return ""
	}
	data, _ := json.Marshal([]any{t.ID, t.Name, strings.ToLower(t.Type), t.Target, t.Family, t.SourceIP, t.SourceInterface, t.TCPReachability})
	sum := sha256.Sum256(data)
	return "task:" + hex.EncodeToString(sum[:])
}
func ValidProbeTaskSeries(s string) bool {
	if len(s) != 69 || !strings.HasPrefix(s, "task:") || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s[5:])
	return err == nil
}
