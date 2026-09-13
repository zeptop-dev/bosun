package singbox

import (
	"sort"
	"testing"
	"time"
)

func TestOnlineTrackerJoinsLines(t *testing.T) {
	tr := newOnlineTracker()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base
	tr.now = func() time.Time { return now }
	feed := func(lines ...string) {
		for _, l := range lines {
			tr.feed(l)
		}
	}
	feed(
		"+0000 2026-01-01 00:00:00 INFO [1745031466 0ms] inbound/vless[in]: inbound connection from 203.0.113.9:51234",
		"+0000 2026-01-01 00:00:00 INFO [1745031466 0ms] inbound/vless[in]: [alice] inbound connection to example.com:443",
		"+0000 2026-01-01 00:00:00 INFO [99 0ms] inbound/shadowsocks[ss]: [bob] inbound packet connection from [2001:db8::1]:4000",
		"+0000 2026-01-01 00:00:00 INFO [77 0ms] inbound/trojan[tj]: [carol] inbound connection to x.y:1", // no source line: ignored
		"+0000 2026-01-01 00:00:00 INFO [1745031466 3ms] outbound/direct[direct]: outbound connection to example.com:443",
		"+0000 2026-01-01 00:00:00 INFO [1745031466 0ms] inbound/vless[in]: inbound connection from 198.51.100.7:2",
		"+0000 2026-01-01 00:00:00 INFO [1745031466 0ms] inbound/vless[in]: [alice] inbound connection to example.com:443",
	)
	got := tr.online()
	sort.Strings(got["alice"])
	if len(got) != 2 || len(got["alice"]) != 2 || got["alice"][0] != "198.51.100.7" || got["alice"][1] != "203.0.113.9" || got["bob"][0] != "2001:db8::1" {
		t.Fatalf("online: %v", got)
	}
	if _, ok := got["carol"]; ok {
		t.Fatal("user without a source line must not appear")
	}
	// Entries expire after the window.
	now = base.Add(onlineWindow + time.Second)
	if got := tr.online(); len(got) != 0 {
		t.Fatalf("expected expiry, got %v", got)
	}
}

func TestOnlineLogLevel(t *testing.T) {
	if got := effectiveLogLevel("warn", true); got != "info" {
		t.Fatalf("device limits need info, got %s", got)
	}
	if got := effectiveLogLevel("warn", false); got != "warn" {
		t.Fatalf("unchanged without limits, got %s", got)
	}
	if got := effectiveLogLevel("debug", true); got != "debug" {
		t.Fatalf("debug stays, got %s", got)
	}
}
