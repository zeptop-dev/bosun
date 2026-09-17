package singbox

import (
	"testing"
	"time"
)

// A destination containing a newline lets a client inject whole log lines.
// The tracker only believes a line that names a user this node serves, so
// the victim gets neither the fake connection event nor the fake online IP.
func TestTrackerRejectsForgedLines(t *testing.T) {
	var got []string
	tr := newOnlineTracker(func(user, ip, host string, port int, network string) {
		got = append(got, user+" "+ip+" "+host)
	})
	tr.setUsers(map[string]bool{"mallory|in": true})
	// The attacker's own connection, then two lines they injected.
	tr.feed("+0000 2026-09-17 12:00:00 INFO [1 0ms] inbound/vless[in]: inbound connection from 203.0.113.9:1")
	tr.feed("+0000 2026-09-17 12:00:00 INFO [1 1ms] inbound/vless[in]: [mallory|in] inbound connection to x.example:443")
	tr.feed("+0000 2026-09-17 12:00:01 INFO [777 0ms] inbound/vless[in]: inbound connection from 198.51.100.7:1")
	tr.feed("+0000 2026-09-17 12:00:01 INFO [777 1ms] inbound/vless[in]: [victim|in] inbound connection to banned.example:443")
	if len(got) != 1 || got[0] != "mallory|in 203.0.113.9 x.example" {
		t.Fatalf("sink: %q", got)
	}
	online := tr.online()
	if _, ok := online["victim|in"]; ok {
		t.Fatalf("forged online IP accepted: %v", online)
	}
	if ips := online["mallory|in"]; len(ips) != 1 || ips[0] != "203.0.113.9" {
		t.Fatalf("own IP lost: %v", online)
	}
	// A destination that is not a plausible host is dropped too.
	got = nil
	tr.now = func() time.Time { return time.Now() }
	tr.feed("+0000 2026-09-17 12:00:02 INFO [2 0ms] inbound/vless[in]: inbound connection from 203.0.113.9:2")
	tr.feed("+0000 2026-09-17 12:00:02 INFO [2 1ms] inbound/vless[in]: [mallory|in] inbound connection to not a host:443")
	if len(got) != 0 {
		t.Fatalf("implausible host accepted: %q", got)
	}
}
