package spec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

const (
	PathHealthTLS         = "tls"
	PathHealthHTTP        = "http_proxy"
	PathHealthSOCKS5      = "socks5"
	PathHealthUnsupported = "unsupported"
)

// PathHealthPolicy is operator intent. Omission is distinct from explicitly
// disabling an existing policy; callers merging old editors must preserve nil.
type PathHealthPolicy struct {
	Enabled           bool   `json:"enabled"`
	AutoFailover      bool   `json:"auto_failover"`
	ServerName        string `json:"server_name,omitempty"`
	IntervalSeconds   int    `json:"interval_seconds"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
	FailureThreshold  int    `json:"failure_threshold"`
	RecoveryThreshold int    `json:"recovery_threshold"`
}

var pathHealthLabel = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,95}$`)
var pathHealthHash = regexp.MustCompile(`^[a-f0-9]{64}$`)

// ValidPathHealthServerName accepts only an ASCII DNS name, never a URL, IP,
// wildcard or dial override. TLS verification still uses the host root store.
func ValidPathHealthServerName(name string) bool {
	if name == "" || len(name) > 253 || net.ParseIP(name) != nil || strings.HasSuffix(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func (p PathHealthPolicy) Normalized() (PathHealthPolicy, error) {
	p.ServerName = strings.ToLower(strings.TrimSpace(p.ServerName))
	if p.ServerName != "" && !ValidPathHealthServerName(p.ServerName) {
		return p, fmt.Errorf("path health server name must be a DNS name")
	}
	if p.IntervalSeconds == 0 {
		p.IntervalSeconds = 15
	}
	if p.TimeoutSeconds == 0 {
		p.TimeoutSeconds = 3
	}
	if p.FailureThreshold == 0 {
		p.FailureThreshold = 3
	}
	if p.RecoveryThreshold == 0 {
		p.RecoveryThreshold = 2
	}
	if p.IntervalSeconds < 10 || p.IntervalSeconds > 300 || p.TimeoutSeconds < 1 || p.TimeoutSeconds > 10 || p.TimeoutSeconds > p.IntervalSeconds || p.FailureThreshold < 1 || p.FailureThreshold > 10 || p.RecoveryThreshold < 1 || p.RecoveryThreshold > 10 {
		return p, fmt.Errorf("path health timing or threshold is out of range")
	}
	return p, nil
}

// PathHealth contains no arbitrary probe address, request, credentials or
// certificate bypass. Every target must be one of this rule's existing hops.
// Only the compiler that owns the complete route should create this object.
type PathHealth struct {
	RouteID           int64                 `json:"route_id"`
	ScopeID           string                `json:"scope_id"`
	Protocol          string                `json:"protocol"`
	ServerName        string                `json:"server_name,omitempty"`
	ALPN              []string              `json:"alpn,omitempty"`
	AutoFailover      bool                  `json:"auto_failover"`
	IntervalSeconds   int                   `json:"interval_seconds"`
	TimeoutSeconds    int                   `json:"timeout_seconds"`
	FailureThreshold  int                   `json:"failure_threshold"`
	RecoveryThreshold int                   `json:"recovery_threshold"`
	Candidates        []PathHealthCandidate `json:"candidates"`
}

type PathHealthCandidate struct {
	ID     string `json:"id"`
	Target string `json:"target"`
	Digest string `json:"digest"`
}

func ClonePathHealth(p *PathHealth) *PathHealth {
	if p == nil {
		return nil
	}
	out := *p
	out.ALPN = append([]string(nil), p.ALPN...)
	out.Candidates = append([]PathHealthCandidate(nil), p.Candidates...)
	return &out
}

func (p *PathHealth) Digest() string {
	if p == nil {
		return ""
	}
	b, _ := json.Marshal(p)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Freshness spans the normal report interval without letting copied reports
// renew a sample. Local selection and the panel use the original sample time.
func (p *PathHealth) Freshness() time.Duration {
	return time.Duration(max(90, 2*p.IntervalSeconds+p.TimeoutSeconds)) * time.Second
}

func (f Forward) ValidatePathHealth() error {
	p := f.PathHealth
	if p == nil {
		return nil
	}
	if f.Protocol != "tcp" || f.Backend != "" || f.ProxyProtocol || f.PreserveSource {
		return fmt.Errorf("path health requires native TCP relay without PROXY protocol")
	}
	if p.RouteID == 0 || !pathHealthLabel.MatchString(p.ScopeID) {
		return fmt.Errorf("path health requires a route identity")
	}
	policy := PathHealthPolicy{Enabled: true, AutoFailover: p.AutoFailover, ServerName: p.ServerName, IntervalSeconds: p.IntervalSeconds, TimeoutSeconds: p.TimeoutSeconds, FailureThreshold: p.FailureThreshold, RecoveryThreshold: p.RecoveryThreshold}
	normal, err := policy.Normalized()
	if err != nil || normal != policy {
		return fmt.Errorf("invalid compiled path health policy")
	}
	switch p.Protocol {
	case PathHealthTLS:
		if !ValidPathHealthServerName(p.ServerName) {
			return fmt.Errorf("TLS path health requires a verifiable server name")
		}
	case PathHealthHTTP, PathHealthSOCKS5, PathHealthUnsupported:
		if p.ServerName != "" || len(p.ALPN) != 0 {
			return fmt.Errorf("non-TLS path health cannot use TLS options")
		}
	default:
		return fmt.Errorf("unsupported path health protocol")
	}
	if len(p.ALPN) > 8 {
		return fmt.Errorf("too many path health ALPN values")
	}
	for _, value := range p.ALPN {
		if len(value) == 0 || len(value) > 64 || !Plain(value) || strings.ContainsAny(value, " \"'") {
			return fmt.Errorf("invalid path health ALPN")
		}
	}
	if p.AutoFailover && (f.BalanceMode() != BalanceFailover || p.Protocol == PathHealthUnsupported) {
		return fmt.Errorf("automatic path failover needs a supported handshake and failover strategy")
	}
	hops := f.Hops()
	if len(p.Candidates) != len(hops) || len(hops) > MaxForwardHops {
		return fmt.Errorf("path health candidates must match all forwarding targets")
	}
	seen := map[string]bool{}
	for i, c := range p.Candidates {
		if !pathHealthLabel.MatchString(c.ID) || !pathHealthHash.MatchString(c.Digest) || c.Target != hops[i].Target || seen[c.ID] {
			return fmt.Errorf("invalid path health candidate identity or target")
		}
		seen[c.ID] = true
	}
	return nil
}
