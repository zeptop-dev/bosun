package servicecontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

type fakeNFT struct {
	script    string
	installs  int
	fail      bool
	corrupt   bool
	flowtable bool
	commands  []string
}

func (f *fakeNFT) run(_ context.Context, args []string, stdin string) ([]byte, error) {
	f.commands = append(f.commands, strings.Join(args, " "))
	if f.fail {
		return nil, errors.New("netlink permission denied")
	}
	if strings.Join(args, " ") == "-j list ruleset" {
		if f.flowtable {
			return []byte(`{"nftables":[{"flowtable":{"name":"foreign"}}]}`), nil
		}
		return []byte(`{"nftables":[]}`), nil
	}
	if len(args) > 0 && args[0] == "-c" {
		return nil, nil
	}
	if strings.Join(args, " ") == "-f -" {
		f.installs++
		f.script = stdin
		f.corrupt = false
		return nil, nil
	}
	if strings.Join(args, " ") == "-j list table inet "+table {
		script := f.script
		if f.corrupt {
			script += "modified"
		}
		return json.Marshal(map[string]any{"nftables": []any{map[string]any{"table": map[string]any{"name": table, "family": "inet"}}, map[string]any{"rule": map[string]any{"handle": f.installs, "expr": script, "counter": map[string]any{"packets": f.installs * 10, "bytes": f.installs * 100}}}}})
	}
	return nil, fmt.Errorf("unexpected nft command: %v", args)
}
func testScope() Scope {
	return Scope{Forwards: []spec.Forward{{Listen: "192.0.2.1", Port: 443, Protocol: "both", Backend: "nft"}}, Interfaces: []string{"bwg7"}}
}
func TestPolicyApplyRetryRefreshAndResume(t *testing.T) {
	ctx := context.Background()
	nft := &fakeNFT{}
	m := Manager{Dir: t.TempDir(), Run: nft.run}
	policy := &spec.ServiceControl{Revision: "r1", Mode: spec.ServiceControlLimit, LimitMbps: 8}
	if err := m.Apply(ctx, policy, 998, false, testScope()); err != nil {
		t.Fatal(err)
	}
	if got := m.Status(); !got.Supported || got.AppliedRevision != "r1" || got.Mode != "limit" || got.LimitMbps != 8 || got.CheckedAt == 0 {
		t.Fatal(got)
	}
	first := nft.installs
	if err := m.Apply(ctx, policy, 998, false, testScope()); err != nil {
		t.Fatal(err)
	}
	if nft.installs != first {
		t.Fatal("unchanged policy reset its aggregate bucket")
	}
	nft.corrupt = true
	if err := m.Apply(ctx, policy, 998, false, testScope()); err != nil {
		t.Fatal(err)
	}
	if nft.installs != first+1 {
		t.Fatal("modified rules were not repaired")
	}
	nft.fail = true
	policy = &spec.ServiceControl{Revision: "r2", Mode: spec.ServiceControlPause}
	if err := m.Apply(ctx, policy, 998, false, testScope()); err == nil {
		t.Fatal("failure hidden")
	}
	if got := m.Status(); got.AppliedRevision != "" || got.Error == "" || got.Mode != "limit" {
		t.Fatal(got)
	}
	nft.fail = false
	if err := m.Apply(ctx, policy, 998, false, testScope()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(nft.script, "counter drop") || strings.Contains(nft.script, "limit aggregate") {
		t.Fatal(nft.script)
	}
	// Restart must restore ownership, not silently lose old established NAT.
	restarted := Manager{Dir: m.Dir, Run: nft.run}
	if err := restarted.Apply(ctx, policy, 998, false, Scope{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(nft.script, "ct original proto-dst 443") {
		t.Fatal("restart lost old NAT scope")
	}
	if err := restarted.Apply(ctx, &spec.ServiceControl{Revision: "r3", Mode: spec.ServiceControlNormal}, 998, false, Scope{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(nft.script, "chain") {
		t.Fatal("resume left guard installed")
	}
	if got := restarted.Status(); got.Mode != "normal" || got.AppliedRevision != "r3" {
		t.Fatal(got)
	}
	scope, err := readScope(m.Dir)
	if err != nil || len(scope.Forwards) > 0 || len(scope.Interfaces) > 0 {
		t.Fatal(scope, err)
	}
}
func TestUnsupportedLegacyNormalDoesNotBreakServices(t *testing.T) {
	for _, desired := range []*spec.ServiceControl{nil, {Revision: "normal", Mode: "normal"}} {
		nft := &fakeNFT{fail: true}
		m := Manager{Dir: t.TempDir(), Run: nft.run}
		if err := m.Apply(context.Background(), desired, 998, false, Scope{}); err != nil {
			t.Fatal(err)
		}
		if m.Status().Supported {
			t.Fatal("missing permission advertised")
		}
		for _, cmd := range nft.commands {
			if cmd == "-f -" {
				t.Fatal("legacy normal attempted a firewall mutation")
			}
		}
	}
}
func TestExistingGuardCleanupFailureIsNotNormal(t *testing.T) {
	nft := &fakeNFT{}
	m := Manager{Dir: t.TempDir(), Run: nft.run}
	ctx := context.Background()
	if err := m.Apply(ctx, &spec.ServiceControl{Revision: "pause", Mode: "pause"}, 998, false, Scope{}); err != nil {
		t.Fatal(err)
	}
	nft.fail = true
	if err := m.Apply(ctx, nil, 998, false, Scope{}); err == nil {
		t.Fatal("failed resume hidden")
	}
	if m.Status().Mode != "pause" || m.Status().AppliedRevision != "" {
		t.Fatal(m.Status())
	}
}
func TestPrerequisitesAndNoHostWideSelectors(t *testing.T) {
	for _, tc := range []struct {
		uid           int
		monitor, flow bool
	}{{0, false, false}, {-1, false, false}, {998, true, false}, {998, false, true}} {
		nft := &fakeNFT{flowtable: tc.flow}
		m := Manager{Run: nft.run}
		if err := m.Apply(context.Background(), &spec.ServiceControl{Revision: "x", Mode: "pause"}, tc.uid, tc.monitor, Scope{}); err == nil {
			t.Fatal("unsafe capability accepted", tc)
		}
	}
	script := render(998, testScope(), &spec.ServiceControl{Mode: "limit", LimitMbps: 8}, "")
	for _, want := range []string{"rate over 1000000 bytes/second", "oifname \"lo\" return", "meta skuid 998 goto controlled", fmt.Sprint("meta mark ", spec.ServiceControlSocketMark, " goto controlled"), "ct original proto-dst 443 ct original ip daddr 192.0.2.1", "iifname \"bwg7\" goto controlled"} {
		if !strings.Contains(script, want) {
			t.Fatal(want, script)
		}
	}
	for _, bad := range []string{"hook input", "hook prerouting", "ct state established accept", "iifname \"bwg*\"", "meta skuid 0", "flush ruleset", "tc ", "iptables"} {
		if strings.Contains(script, bad) {
			t.Fatal("unsafe/double-count selector", bad)
		}
	}
	if strings.Count(script, "limit name aggregate") != 1 {
		t.Fatal("limits must share exactly one bucket")
	}
}
func TestRuleFingerprintRejectsFlushedChains(t *testing.T) {
	first := []byte(`{"nftables":[{"metainfo":{"version":"a"}},{"rule":{"handle":1,"expr":[{"counter":{"bytes":5,"packets":1}},{"drop":null}]}}]}`)
	counters := []byte(`{"nftables":[{"metainfo":{"version":"b"}},{"rule":{"handle":20,"expr":[{"counter":{"bytes":99,"packets":9}},{"drop":null}]}}]}`)
	changed := []byte(`{"nftables":[{"rule":{"handle":1,"expr":[{"counter":{"bytes":5,"packets":1}},{"accept":null}]}}]}`)
	if rulesFingerprint(first) != rulesFingerprint(counters) || rulesFingerprint(first) == rulesFingerprint(changed) {
		t.Fatal("rule fingerprint ignored substantive change or included runtime counters")
	}
}
func TestScopeRejectsInjectionAndSymlink(t *testing.T) {
	for _, s := range []Scope{{Interfaces: []string{"bwg7\" accept"}}, {Interfaces: []string{"bwg007"}}, {Forwards: []spec.Forward{{Listen: "192.0.2.1; accept", Port: 443, Protocol: "tcp", Backend: "nft"}}}} {
		if validateScope(s) == nil {
			t.Fatal("invalid scope accepted", s)
		}
	}
	dir := t.TempDir()
	other := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(other, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(dir, "service-control-owned.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := readScope(dir); err == nil {
		t.Fatal("read followed symlink")
	}
	if saveScope(dir, Scope{}) == nil {
		t.Fatal("write accepted symlink")
	}
}

func TestExistingOwnershipCannotResumeWithoutRuntime(t *testing.T) {
	// The unit runner deliberately uses the actual unsupported local platform
	// rather than a fake nft runner, which implies kernel support to Manager.
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		if _, err := exec.LookPath("nft"); err == nil {
			t.Skip("requires an unsupported runtime")
		}
	}
	dir := t.TempDir()
	if err := saveScope(dir, testScope()); err != nil {
		t.Fatal(err)
	}
	m := Manager{Dir: dir}
	if err := m.Apply(context.Background(), &spec.ServiceControl{Revision: "resume", Mode: "normal"}, 998, false, Scope{}); err == nil {
		t.Fatal("unremovable old guard accepted as normal")
	}
	if got := m.Status(); got.Mode == "normal" || got.AppliedRevision != "" || got.Error == "" {
		t.Fatal(got)
	}
}

func TestNamedLimitRateAndBurstAreOneNFTExpression(t *testing.T) {
	script := render(65534, Scope{}, &spec.ServiceControl{Mode: "limit", LimitMbps: 1}, "")
	if !strings.Contains(script, "limit aggregate { rate over 125000 bytes/second burst 65536 bytes; }") {
		t.Fatal(script)
	}
}

func TestNormalReleasesOwnershipAfterMalformedJournal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "service-control-owned.json")
	if err := os.WriteFile(path, []byte("truncated journal"), 0600); err != nil {
		t.Fatal(err)
	}
	nft := &fakeNFT{}
	m := Manager{Dir: dir, Run: nft.run}
	if err := m.Apply(context.Background(), &spec.ServiceControl{Revision: "normal", Mode: "normal"}, 998, false, Scope{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("normal retained ownership evidence", err)
	}
	if !strings.Contains(nft.script, "delete table inet "+table) {
		t.Fatal("normal failed to remove own guard")
	}
	// No historical evidence remains: losing nft after a completed release
	// must not prevent normal proxies from starting after restart.
	restarted := Manager{Dir: dir, Run: (&fakeNFT{fail: true}).run}
	if err := restarted.Apply(context.Background(), nil, 998, false, Scope{}); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyActiveScopeStillPersistsOwnership(t *testing.T) {
	dir := t.TempDir()
	nft := &fakeNFT{}
	m := Manager{Dir: dir, Run: nft.run}
	if err := m.Apply(context.Background(), &spec.ServiceControl{Revision: "pause", Mode: "pause"}, 998, false, Scope{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "service-control-owned.json")); err != nil {
		t.Fatal("UID-only protection lost restart evidence", err)
	}
}
