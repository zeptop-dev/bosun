package egressguard

import (
	"context"
	"strings"
	"testing"
)

func TestScriptAndApply(t *testing.T) {
	s := Script(998, Options{Allow: []string{"10.10.0.0/24", "fd00:1::/64", "192.0.2.10", "not an address"}, LoopbackPorts: []int{53, 9103}})
	for _, want := range []string{
		"meta skuid 998 ip daddr { 10.10.0.0/24, 192.0.2.10/32 } accept",
		"meta skuid 998 ip6 daddr { fd00:1::/64 } accept",
		"meta skuid 998 ct state new ip daddr { 127.0.0.0/8, 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16 } drop",
		"meta skuid 998 ct state new ip6 daddr { ::1/128, fc00::/7, fe80::/10 } drop",
		"meta skuid 998 ip daddr 127.0.0.0/8 tcp dport { 53, 9103 } accept",
		"meta skuid 998 ip6 daddr ::1/128 udp dport { 53, 9103 } accept",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("script lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "not an address") {
		t.Fatalf("script interpolated junk:\n%s", s)
	}
	if Script(-1, Options{}) != "" {
		t.Fatal("no uid must render nothing")
	}
	var runs []string
	g := &Guard{Run: func(_ context.Context, stdin, name string, args ...string) ([]byte, error) {
		runs = append(runs, stdin)
		return nil, nil
	}}
	if err := g.Apply(context.Background(), 998, Options{LoopbackPorts: []int{53}}); err != nil {
		t.Fatal(err)
	}
	if err := g.Apply(context.Background(), 998, Options{LoopbackPorts: []int{53}}); err != nil || len(runs) != 1 {
		t.Fatalf("unchanged input re-applied: %d runs, %v", len(runs), err)
	}
	if st := g.Status(); !st.Supported || st.UID != 998 || st.Error != "" {
		t.Fatalf("status %+v", st)
	}
	if err := g.Apply(context.Background(), -1, Options{}); err != nil || !strings.HasPrefix(runs[len(runs)-1], "delete table") {
		t.Fatalf("removal: %v %q", err, runs[len(runs)-1])
	}
}

// The cores' control APIs (unauthenticated gRPC on loopback) are closed to
// every local account except root, which is bosun itself — the third layer
// behind the cores' own routing rules and the egress drops.
func TestScriptProtectsControlPorts(t *testing.T) {
	s := Script(998, Options{Allow: []string{"10.10.0.2"}, LoopbackPorts: []int{53, 4443}, ProtectedPorts: []int{9102, 9101, 9101}})
	want := []string{
		"meta skuid != 0 ip daddr 127.0.0.0/8 tcp dport { 9101, 9102 } drop",
		"meta skuid != 0 ip6 daddr ::1/128 tcp dport { 9101, 9102 } drop",
	}
	for _, w := range want {
		if !strings.Contains(s, w) {
			t.Fatalf("missing %q in:\n%s", w, s)
		}
	}
	// The drop has to come before the accepts, or an allowed loopback port
	// or CIDR would open the API again.
	if i, j := strings.Index(s, "skuid != 0"), strings.Index(s, "accept\n"); i < 0 || (j >= 0 && i > j) {
		t.Fatalf("the protected-port drop is not first:\n%s", s)
	}
	// Without a core account the table exists for this rule alone.
	only := Script(-1, Options{ProtectedPorts: []int{9101}})
	if !strings.Contains(only, "skuid != 0") || strings.Contains(only, "skuid 998") {
		t.Fatalf("no-account script = %q", only)
	}
	// With neither, nothing is installed.
	if got := Script(-1, Options{}); got != "" {
		t.Fatalf("empty options produced %q", got)
	}
}
