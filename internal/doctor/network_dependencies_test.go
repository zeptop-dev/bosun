package doctor

import (
	"context"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/internal/egressguard"
	"github.com/zeptop-dev/bosun/internal/shaper"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestShapingDiagnosticsSeparateIntentPrerequisitesAndApplication(t *testing.T) {
	for _, tc := range []struct {
		name     string
		deps     Deps
		status   string
		contains string
	}{
		{"unused missing tools", Deps{Node: &spec.Node{}, Shaper: &shaper.Status{MissingTools: []string{"nft", "tc"}, Error: "missing tools"}}, Skip, "no user speed limits configured"},
		{"unused ready tools", Deps{Node: &spec.Node{}, Shaper: &shaper.Status{Supported: true}}, Skip, "has not been verified"},
		{"requested missing tools", Deps{Node: &spec.Node{}, Users: []spec.User{{ID: 7, SpeedLimitMbps: 2}}, Shaper: &shaper.Status{MissingTools: []string{"tc"}}}, Warn, "service PATH: tc"},
		{"requested result absent", Deps{Node: &spec.Node{UserSpeedLimitMbps: 2}, Users: []spec.User{{ID: 7}}}, Warn, "no applied shaping result"},
		{"configured default without users", Deps{Node: &spec.Node{UserSpeedLimitMbps: 2}}, Skip, "no user speed limits configured"},
		{"empty reported result", Deps{Node: &spec.Node{}, Users: []spec.User{{ID: 7, SpeedLimitMbps: 2}}, Shaper: &shaper.Status{Supported: true}}, Warn, "no users have an applied"},
		{"permission failure", Deps{Shaper: &shaper.Status{Supported: true, Users: 1, Error: "tc: Operation not permitted"}}, Fail, "Operation not permitted"},
		{"cleanup failed without users", Deps{Node: &spec.Node{}, Shaper: &shaper.Status{Supported: true, Error: "nft: Operation not permitted"}}, Fail, "remove speed-limit rules"},
		{"old shaping after revocation", Deps{Node: &spec.Node{}, Shaper: &shaper.Status{Supported: true, Users: 1}}, Warn, "awaiting reconciliation"},
		{"success", Deps{Shaper: &shaper.Status{Supported: true, Users: 1, Interface: "eth0"}}, OK, "1 users shaped"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := checkShaper(context.Background(), &tc.deps)[0]
			if c.Status != tc.status || !strings.Contains(c.Detail, tc.contains) {
				t.Fatalf("got %+v, want %s containing %q", c, tc.status, tc.contains)
			}
		})
	}
}

func TestIsolationDiagnosticsSeparateAccountAndFirewall(t *testing.T) {
	for _, tc := range []struct {
		name             string
		state            *egressguard.Status
		status, contains string
	}{
		{"no result", nil, Warn, "no applied egress-guard result"},
		{"missing tool", &egressguard.Status{MissingTools: []string{"nft"}}, Warn, "service PATH: nft"},
		{"kernel denied", &egressguard.Status{Supported: true, Error: "nft: Operation not permitted"}, Fail, "rule application failed"},
		{"applied", &egressguard.Status{Supported: true, Enabled: true, UID: 900}, OK, "rules applied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := Deps{CoreUser: "proxy-test", Egress: tc.state, Exec: func(context.Context, string, ...string) ([]byte, error) {
				t.Fatal("diagnostics must not apply firewall rules")
				return nil, nil
			}}
			c := checkIsolation(context.Background(), &d)[0]
			if c.Status != tc.status || !strings.Contains(c.Detail, tc.contains) || !strings.Contains(c.Detail, "core account proxy-test") {
				t.Fatalf("unexpected diagnostic: %+v", c)
			}
		})
	}
}
