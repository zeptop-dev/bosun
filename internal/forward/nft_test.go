package forward

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestRenderNFT(t *testing.T) {
	targets := map[string]nftTarget{"web": {IP: "203.0.113.30", Port: 443}, "game": {IP: "198.51.100.20", Port: 27015}}
	cases := []struct {
		name  string
		rules []spec.Forward
		want  []string
		not   []string
	}{
		{
			name:  "empty deletes the table",
			rules: nil,
			want:  []string{"table inet bosun_fwd\n", "delete table inet bosun_fwd\n"},
			not:   []string{"chain prerouting"},
		},
		{
			name:  "tcp with masquerade",
			rules: []spec.Forward{{Tag: "web", Port: 24443, Protocol: "tcp", Target: "203.0.113.30:443", Backend: "nft"}},
			want: []string{
				"type nat hook prerouting priority dstnat; policy accept;",
				"\t\ttcp dport 24443 dnat ip to 203.0.113.30:443 comment \"web\"",
				"\t\tip daddr 203.0.113.30 tcp dport 443 masquerade comment \"web\"",
				"ct status dnat accept",
			},
		},
		{
			name:  "both, preserve source, bound listen address",
			rules: []spec.Forward{{Tag: "game", Listen: "10.10.0.2", Port: 27015, Protocol: "both", Target: "198.51.100.20:27015", Backend: "nft", PreserveSource: true}},
			want: []string{
				"\t\tip daddr 10.10.0.2 tcp dport 27015 dnat ip to 198.51.100.20:27015 comment \"game\"",
				"\t\tip daddr 10.10.0.2 udp dport 27015 dnat ip to 198.51.100.20:27015 comment \"game\"",
			},
			not: []string{"masquerade"},
		},
		{
			name:  "unresolved rule is skipped, stable tag order",
			rules: []spec.Forward{{Tag: "web", Port: 1, Protocol: "tcp", Target: "203.0.113.30:443", Backend: "nft"}, {Tag: "game", Port: 2, Protocol: "udp", Target: "198.51.100.20:27015", Backend: "nft"}, {Tag: "nope", Port: 3, Protocol: "tcp", Target: "x", Backend: "nft"}},
			want:  []string{"comment \"game\"\n\t\ttcp dport 1"},
			not:   []string{"nope"},
		},
	}
	for _, c := range cases {
		out := renderNFT(c.rules, targets)
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("%s: missing %q in\n%s", c.name, w, out)
			}
		}
		for _, n := range c.not {
			if strings.Contains(out, n) {
				t.Errorf("%s: unexpected %q in\n%s", c.name, n, out)
			}
		}
	}
}

func TestResolveNFT(t *testing.T) {
	if _, err := resolveNFT(context.Background(), "2001:db8::1:443"); err == nil {
		t.Fatal("ipv6 accepted")
	}
	if target, err := resolveNFT(context.Background(), "[2001:db8::1]:443"); err != nil || target.IP != "2001:db8::1" {
		t.Fatalf("IPv6 target: %+v %v", target, err)
	}
	tg, err := resolveNFT(context.Background(), "203.0.113.30:443")
	if err != nil || tg.IP != "203.0.113.30" || tg.Port != 443 {
		t.Fatalf("%+v %v", tg, err)
	}
}

func TestNFTApplyAndStatus(t *testing.T) {
	var scripts []string
	oldRun, oldFwd := nftRun, enableForwarding
	nftRun = func(_ context.Context, s string) error { scripts = append(scripts, s); return nil }
	enableForwarding = func(context.Context) error { return nil }
	defer func() { nftRun, enableForwarding = oldRun, oldFwd }()
	m := NewManager(slog.Default())
	defer m.Stop()
	f := spec.Forward{Tag: "web", Port: 24443, Protocol: "tcp", Target: "203.0.113.30:443", Backend: "nft"}
	if err := m.Apply([]spec.Forward{f}); err != nil {
		t.Fatal(err)
	}
	if len(scripts) != 1 || !strings.Contains(scripts[0], "dnat ip to 203.0.113.30:443") {
		t.Fatalf("scripts: %v", scripts)
	}
	// Same rules again: nothing re-applied.
	_ = m.Apply([]spec.Forward{f})
	if len(scripts) != 1 {
		t.Fatalf("re-applied unchanged ruleset: %d", len(scripts))
	}
	// Removing the last nft rule deletes the table.
	_ = m.Apply(nil)
	if len(scripts) != 2 || strings.Contains(scripts[1], "chain prerouting") {
		t.Fatalf("delete script: %v", scripts)
	}
	// nft missing: the rule stays listed, down, with the error.
	nftRun = func(context.Context, string) error { return errors.New("nftables not installed") }
	if err := m.Apply([]spec.Forward{f}); err == nil {
		t.Fatal("failed nft install was acknowledged")
	}
	snap := m.Snapshot()
	if len(snap) != 1 || snap[0].Up || snap[0].LastError != "nftables not installed" {
		t.Fatalf("snapshot: %+v", snap)
	}
	// Validation.
	if err := m.Apply([]spec.Forward{{Tag: "x", Port: 1, Protocol: "tcp", Target: "203.0.113.30:443", Backend: "realm"}}); err == nil {
		t.Fatal("unknown backend accepted")
	}
	if err := m.Apply([]spec.Forward{{Tag: "x", Port: 1, Protocol: "tcp", Target: "203.0.113.30:443", PreserveSource: true}}); err == nil {
		t.Fatal("preserve_source on the relay accepted")
	}
}

func TestNFTFailedReplacementAndCleanupRemainRetryable(t *testing.T) {
	oldRun, oldForward := nftRun, enableForwarding
	t.Cleanup(func() { nftRun, enableForwarding = oldRun, oldForward })
	failure := errors.New("nft operation failed")
	fail, calls := false, 0
	nftRun = func(context.Context, string) error {
		calls++
		if fail {
			return failure
		}
		return nil
	}
	enableForwarding = func(context.Context) error { return nil }
	m := NewManager(slog.Default())
	t.Cleanup(m.Stop)
	f := spec.Forward{Tag: "one", Port: 18443, Protocol: "udp", Target: "192.0.2.10:443", Backend: "nft"}
	if err := m.Apply([]spec.Forward{f}); err != nil {
		t.Fatal(err)
	}
	first := m.nftApplied
	f.Target = "198.51.100.20:443"
	fail = true
	for i := 0; i < 2; i++ {
		before := calls
		if err := m.Apply([]spec.Forward{f}); !errors.Is(err, failure) || calls != before+1 {
			t.Fatalf("replacement failure/retry lost: calls=%d error=%v", calls, err)
		}
		if m.nftApplied != first {
			t.Fatal("failed replacement changed the applied script")
		}
	}
	fail = false
	if err := m.Apply([]spec.Forward{f}); err != nil || m.nftApplied == first {
		t.Fatalf("replacement did not recover: %v", err)
	}
	before := calls
	if err := m.Apply([]spec.Forward{f}); err != nil || calls != before {
		t.Fatal("successful unchanged script was reinstalled", err)
	}
	fail = true
	for i := 0; i < 2; i++ {
		before := calls
		if err := m.Apply(nil); !errors.Is(err, failure) || calls != before+1 || m.nftApplied == "" {
			t.Fatalf("cleanup failure/retry lost: calls=%d error=%v", calls, err)
		}
		if len(m.Snapshot()) != 0 {
			t.Fatal("expected removed rules: the apply error must survive without a per-rule report")
		}
	}
	fail = false
	if err := m.Apply(nil); err != nil || m.nftApplied != "" {
		t.Fatal("cleanup did not recover", err)
	}
}

func TestNFTUnresolvedRuleFailsApplyEvenWhenRenderedScriptIsUnchanged(t *testing.T) {
	oldRun, oldForward := nftRun, enableForwarding
	t.Cleanup(func() { nftRun, enableForwarding = oldRun, oldForward })
	nftRun = func(context.Context, string) error { return nil }
	enableForwarding = func(context.Context) error { return nil }
	m := NewManager(slog.Default())
	// Exercise resolution failure without a network-dependent DNS lookup.
	f := spec.Forward{Tag: "unresolved", Port: 18443, Protocol: "udp", Target: "missing-port", Backend: "nft"}
	for i := 0; i < 2; i++ {
		if err := m.applyNFT(context.Background(), []spec.Forward{f}); err == nil {
			t.Fatal("omitted unresolved rule was acknowledged as a complete apply")
		}
	}
}

func TestNFTIPv6AndFamilyMismatch(t *testing.T) {
	f := spec.Forward{Tag: "v6", Listen: "2001:db8::10", Protocol: "both", Port: 10000, Target: "[2001:db8::20]:443", Backend: "nft"}
	target, err := resolveNFTFamily(context.Background(), f.Target, f.Listen)
	if err != nil {
		t.Fatal(err)
	}
	script := renderNFT([]spec.Forward{f}, map[string]nftTarget{f.Tag: target})
	for _, want := range []string{"ip6 daddr 2001:db8::10 tcp dport 10000 dnat ip6 to [2001:db8::20]:443", "ip6 daddr 2001:db8::10 udp dport 10000 dnat ip6 to [2001:db8::20]:443", "ip6 daddr 2001:db8::20 udp dport 443 masquerade"} {
		if !strings.Contains(script, want) {
			t.Fatal("wrong IPv6 rule", script)
		}
	}
	f.PreserveSource = true
	if strings.Contains(renderNFT([]spec.Forward{f}, map[string]nftTarget{f.Tag: target}), "masquerade") {
		t.Fatal("source not preserved")
	}
	for _, listen := range []string{"0.0.0.0", "192.0.2.10"} {
		if _, err := resolveNFTFamily(context.Background(), f.Target, listen); err == nil {
			t.Fatal("cross-family nft accepted")
		}
	}
	if _, err := resolveNFTFamily(context.Background(), "198.51.100.20:443", "::"); err == nil {
		t.Fatal("v6 listen with v4 target accepted")
	}
}
