package xray

import (
	"testing"
	"time"
)

func TestOnlineWindowRemembersRecentIPs(t *testing.T) {
	now := time.Unix(1000, 0)
	w := newOnlineWindow()
	w.now = func() time.Time { return now }
	w.add(map[string][]string{"u": {"203.0.113.9"}})
	now = now.Add(2 * time.Minute)
	w.add(map[string][]string{"u": {"203.0.113.10"}})
	got := w.online()
	if len(got["u"]) != 2 {
		t.Fatalf("both IPs inside the window: %v", got)
	}
	now = now.Add(90 * time.Second) // first IP is 3.5 min old, second 1.5 min
	got = w.online()
	if len(got["u"]) != 1 || got["u"][0] != "203.0.113.10" {
		t.Fatalf("old IP should be forgotten: %v", got)
	}
	now = now.Add(5 * time.Minute)
	if got = w.online(); len(got) != 0 {
		t.Fatalf("everything expired: %v", got)
	}
}
