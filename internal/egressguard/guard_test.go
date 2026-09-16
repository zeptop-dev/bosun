package egressguard

import (
	"context"
	"strings"
	"testing"
)

func TestScriptAndApply(t *testing.T) {
	s := Script(998, []string{"10.10.0.0/24", "fd00:1::/64", "192.0.2.10", "not an address"})
	for _, want := range []string{
		"meta skuid 998 ip daddr { 10.10.0.0/24, 192.0.2.10/32 } accept",
		"meta skuid 998 ip6 daddr { fd00:1::/64 } accept",
		"meta skuid 998 ct state new ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16 } drop",
		"meta skuid 998 ct state new ip6 daddr { fc00::/7, fe80::/10 } drop",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("script lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "not an address") || strings.Contains(s, "127.") {
		t.Fatalf("script interpolated junk or blocks loopback:\n%s", s)
	}
	if Script(-1, nil) != "" {
		t.Fatal("no uid must render nothing")
	}
	var runs []string
	g := &Guard{Run: func(_ context.Context, stdin, name string, args ...string) ([]byte, error) {
		runs = append(runs, stdin)
		return nil, nil
	}}
	if err := g.Apply(context.Background(), 998, nil); err != nil {
		t.Fatal(err)
	}
	if err := g.Apply(context.Background(), 998, nil); err != nil || len(runs) != 1 {
		t.Fatalf("unchanged input re-applied: %d runs, %v", len(runs), err)
	}
	if st := g.Status(); !st.Supported || st.UID != 998 || st.Error != "" {
		t.Fatalf("status %+v", st)
	}
	if err := g.Apply(context.Background(), -1, nil); err != nil || !strings.HasPrefix(runs[len(runs)-1], "delete table") {
		t.Fatalf("removal: %v %q", err, runs[len(runs)-1])
	}
}
