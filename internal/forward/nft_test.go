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
	if _, err := resolveNFT(context.Background(), "[2001:db8::1]:443"); err == nil {
		t.Fatal("ipv6 literal accepted")
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
	_ = m.Apply([]spec.Forward{f})
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
