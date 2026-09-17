package audit

import (
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestMatcher(t *testing.T) {
	c := &Collector{}
	at := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return at }
	c.SetRules([]spec.AuditRule{
		{ID: 1, Name: "bt", Match: []string{"protocol:bittorrent"}, Action: "block"},
		{ID: 2, Name: "spam", Match: []string{"domain:evil.example", "port:443,8443"}, Action: "block"},
		{ID: 3, Name: "kw", Match: []string{"keyword:casino", "regexp:^bet[0-9]+\\."}, Action: "log"},
		{ID: 4, Name: "net", Match: []string{"ip:198.51.100.0/24", "inbound:in"}, Action: "log"},
		{ID: 5, Name: "bare", Match: []string{"plain.example"}, Action: "log"},
	})
	hits := func(host string, port int, user string) int64 {
		at = at.Add(61 * time.Second) // past the per-user, per-rule dedupe window
		c.Check(user, "203.0.113.9", host, port, "tcp")
		out, _ := c.Drain()
		if len(out) == 0 {
			return 0
		}
		return out[0].RuleID
	}
	cases := []struct {
		host string
		port int
		user string
		want int64
	}{
		{"www.evil.example", 443, "a|in", 2},
		{"www.evil.example", 80, "a|in", 0}, // port kind must hold too
		{"evil.example", 8443, "a|in", 2},
		{"my-casino.test", 80, "b|in", 3},
		{"bet99.test", 80, "b|in", 3},
		{"198.51.100.7", 80, "b|in", 4},
		{"198.51.100.7", 80, "b|other", 0}, // inbound kind
		{"sub.plain.example", 80, "c|in", 5},
		{"nothing.test", 80, "c|in", 0},
	}
	for _, cs := range cases {
		if got := hits(cs.host, cs.port, cs.user); got != cs.want {
			t.Errorf("%s:%d %s: rule %d, want %d", cs.host, cs.port, cs.user, got, cs.want)
		}
	}
	// Dedupe: the same user and rule within a minute is recorded once.
	c.Check("d|in", "203.0.113.9", "bet1.test", 80, "tcp")
	at = at.Add(30 * time.Second)
	c.Check("d|in", "203.0.113.9", "bet2.test", 80, "tcp")
	at = at.Add(31 * time.Second)
	c.Check("d|in", "203.0.113.9", "bet3.test", 80, "tcp")
	out, _ := c.Drain()
	if len(out) != 2 || out[0].User != "d" || out[0].Inbound != "in" || out[0].RuleName != "kw" || out[0].Action != "log" {
		t.Fatalf("dedupe: %+v", out)
	}
	br := BlockRules([]spec.AuditRule{{ID: 1, Match: []string{"domain:x"}, Action: "block"}, {ID: 2, Match: []string{"domain:y"}, Action: "log"}})
	if len(br) != 1 || br[0].Action != "block" || br[0].Match[0] != "domain:x" {
		t.Fatalf("block rules: %+v", br)
	}
}
