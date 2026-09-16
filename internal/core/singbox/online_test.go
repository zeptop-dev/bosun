package singbox

import (
	"fmt"
	"sort"
	"testing"
	"time"
)

func TestOnlineTrackerJoinsLines(t *testing.T) {
	tr := newOnlineTracker(nil)
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

func TestKeepLineFiltersByConfiguredLevel(t *testing.T) {
	c := &Core{opt: Options{LogLevel: "warn"}}
	if c.keepLine("+0000 2026-09-16 02:12:50 INFO [1 0ms] inbound/vless[in]: inbound connection from 203.0.113.9:1") {
		t.Fatal("info line should not reach the journal at warn")
	}
	if !c.keepLine("+0000 2026-09-16 02:12:50 ERROR [1 0ms] inbound/vless[in]: unknown UUID") {
		t.Fatal("error line must be kept")
	}
	if !c.keepLine("panic: something without a level") {
		t.Fatal("untagged lines must be kept")
	}
	c.opt.LogLevel = "info"
	if !c.keepLine("+0000 2026-09-16 02:12:50 INFO [1 0ms] x") {
		t.Fatal("info kept at info")
	}
}

// The tracker also hands each joined connection (user, client, destination)
// to the connection-log sink, for TCP and UDP lines alike.
func TestTrackerConnSink(t *testing.T) {
	var got []string
	tr := newOnlineTracker(func(user, ip, host string, port int, network string) {
		got = append(got, user+" "+ip+" "+host+" "+network+" "+itoa(port))
	})
	tr.feed("+0000 2026-09-16 12:00:00 INFO [1001 0ms] inbound/vless[in]: inbound connection from 203.0.113.9:51234")
	tr.feed("+0000 2026-09-16 12:00:00 INFO [1001 1ms] inbound/vless[in]: [alice|in] inbound connection to example.com:443")
	tr.feed("+0000 2026-09-16 12:00:01 INFO [1002 0ms] inbound/hysteria2[hy]: [bob|hy] inbound packet connection from 203.0.113.10:4000")
	tr.feed("+0000 2026-09-16 12:00:01 INFO [1002 1ms] inbound/hysteria2[hy]: [bob|hy] inbound packet connection to 1.1.1.1:53")
	if len(got) != 2 || got[0] != "alice|in 203.0.113.9 example.com tcp 443" || got[1] != "bob|hy 203.0.113.10 1.1.1.1 udp 53" {
		t.Fatalf("sink got %q", got)
	}
}

func itoa(n int) string { return fmt.Sprint(n) }
