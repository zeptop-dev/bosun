package ingressguard

import (
	"context"
	"strings"
	"testing"
)

func TestScriptAndApply(t *testing.T) {
	s := Script([]Rule{{IP: "10.10.0.2", Proto: "udp", Port: 17702}, {IP: "10.10.0.2", Proto: "tcp", Port: 17701}})
	if !strings.Contains(s, "ip daddr != 10.10.0.2 tcp dport 17701 drop\n    ip daddr != 10.10.0.2 udp dport 17702 drop") {
		t.Fatalf("script:\n%s", s)
	}
	var calls []string
	g := &Guard{Run: func(_ context.Context, stdin, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " ")+" <<"+stdin)
		return nil, nil
	}}
	rules := []Rule{{IP: "10.10.0.2", Proto: "tcp", Port: 17701}}
	if err := g.Apply(context.Background(), rules); err != nil {
		t.Fatal(err)
	}
	if err := g.Apply(context.Background(), rules); err != nil || len(calls) != 1 {
		t.Fatalf("unchanged rules should be a no-op: %v %v", err, calls)
	}
	if !strings.Contains(calls[0], "delete table inet bosun_ingress") || !strings.Contains(calls[0], "dport 17701 drop") {
		t.Fatalf("nft call: %s", calls[0])
	}
	if st := g.Status(); !st.Supported || st.Rules != 1 || st.Error != "" {
		t.Fatalf("status %+v", st)
	}
	if err := g.Apply(context.Background(), nil); err != nil || len(calls) != 2 || !strings.Contains(calls[1], "delete table") {
		t.Fatalf("clear: %v %v", err, calls)
	}
}
