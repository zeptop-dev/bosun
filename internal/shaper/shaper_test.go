package shaper

import (
	"context"
	"strings"
	"testing"
)

func TestApplyInstallsAndClears(t *testing.T) {
	var cmds []string
	s := &Shaper{Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		if name == "ip" && len(args) > 2 && args[2] == "get" {
			return []byte("1.1.1.1 via 203.0.113.1 dev eth0 src 203.0.113.30 uid 0"), nil
		}
		return nil, nil
	}}
	if err := s.Apply(context.Background(), []Limit{{UserID: 7, Mbps: 50}}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{"tc qdisc replace dev eth0 root handle 1: htb default 0", "classid 1:8 htb rate 50mbit ceil 50mbit", "handle 0x10007 fw flowid 1:8", "dev ifb-bosun root", "action connmark action mirred egress redirect dev ifb-bosun", "ct mark set meta mark"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in\n%s", want, joined)
		}
	}
	if st := s.Status(); !st.Supported || st.Users != 1 || st.Interface != "eth0" {
		t.Fatalf("status %+v", st)
	}
	n := len(cmds)
	if err := s.Apply(context.Background(), []Limit{{UserID: 7, Mbps: 50}}); err != nil || len(cmds) != n {
		t.Fatal("unchanged limits must be a no-op")
	}
	if err := s.Apply(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if tail := strings.Join(cmds[n:], "\n"); !strings.Contains(tail, "qdisc del dev eth0 root") || !strings.Contains(tail, "link del ifb-bosun") {
		t.Fatalf("clear: %s", tail)
	}
}
