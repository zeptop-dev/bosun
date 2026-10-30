package spec

import (
	"strings"
	"testing"
)

func TestPathHealthValidation(t *testing.T) {
	base := Forward{Tag: "line-1-a-probe", Protocol: "tcp", Target: "198.51.100.20:443", PathHealth: &PathHealth{RouteID: 1, ScopeID: "scope1", Protocol: PathHealthTLS, ServerName: "example.com", IntervalSeconds: 15, TimeoutSeconds: 3, FailureThreshold: 3, RecoveryThreshold: 2, Candidates: []PathHealthCandidate{{ID: "branch1", Target: "198.51.100.20:443", Digest: strings.Repeat("a", 64)}}}}
	if err := base.ValidateTargets(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Forward){
		"arbitrary target": func(f *Forward) { f.PathHealth.Candidates[0].Target = "169.254.169.254:80" },
		"realm":            func(f *Forward) { f.Backend = "realm" },
		"udp":              func(f *Forward) { f.Protocol = "udp" },
		"proxy prefix":     func(f *Forward) { f.ProxyProtocol = true },
		"missing sni":      func(f *Forward) { f.PathHealth.ServerName = "" },
		"url as sni":       func(f *Forward) { f.PathHealth.ServerName = "https://example.com" },
		"IP as sni":        func(f *Forward) { f.PathHealth.ServerName = "192.0.2.10" },
		"wildcard sni":     func(f *Forward) { f.PathHealth.ServerName = "*.example.com" },
		"fast loop":        func(f *Forward) { f.PathHealth.IntervalSeconds = 1 },
		"zero threshold":   func(f *Forward) { f.PathHealth.RecoveryThreshold = 0 },
		"unknown protocol": func(f *Forward) { f.PathHealth.Protocol = "GET" },
		"auto roundrobin":  func(f *Forward) { f.Balance = BalanceRoundRobin; f.PathHealth.AutoFailover = true },
		"auto unsupported": func(f *Forward) {
			f.PathHealth.AutoFailover = true
			f.PathHealth.Protocol = PathHealthUnsupported
			f.PathHealth.ServerName = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := base
			f.PathHealth = ClonePathHealth(base.PathHealth)
			change(&f)
			if f.ValidateTargets() == nil {
				t.Fatal("accepted unsafe policy")
			}
		})
	}
	copy := ClonePathHealth(base.PathHealth)
	copy.Candidates[0].ID = "other"
	if base.PathHealth.Candidates[0].ID != "branch1" || base.PathHealth.Digest() == copy.Digest() {
		t.Fatal("health identity alias or digest omission")
	}
}

func TestPathHealthPolicyDefaults(t *testing.T) {
	p, err := (PathHealthPolicy{}).Normalized()
	if err != nil || p.Enabled || p.AutoFailover || p.IntervalSeconds != 15 || p.TimeoutSeconds != 3 || p.FailureThreshold != 3 || p.RecoveryThreshold != 2 {
		t.Fatal(p, err)
	}
	p, err = (PathHealthPolicy{ServerName: " Example.COM "}).Normalized()
	if err != nil || p.ServerName != "example.com" {
		t.Fatal(p, err)
	}
}
