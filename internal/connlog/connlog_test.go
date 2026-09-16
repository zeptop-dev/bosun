package connlog

import "testing"

func TestParsers(t *testing.T) {
	u, ip, host, port, net, ok := ParseXray(`2026/09/16 12:00:00.123456 from 203.0.113.9:51234 accepted tcp:example.com:443 [vless-in -> direct] email: alice|vless-in`)
	if !ok || u != "alice|vless-in" || ip != "203.0.113.9" || host != "example.com" || port != 443 || net != "tcp" {
		t.Fatalf("xray: %v %q %q %q %d %q", ok, u, ip, host, port, net)
	}
	u, ip, host, port, net, ok = ParseXray(`from [2001:db8::9]:51234 accepted udp:[2001:db8::1]:53 email: bob`)
	if !ok || u != "bob" || ip != "2001:db8::9" || host != "2001:db8::1" || port != 53 || net != "udp" {
		t.Fatalf("xray v6: %v %q %q %q %d %q", ok, u, ip, host, port, net)
	}
	if _, _, _, _, _, ok = ParseXray(`from 203.0.113.9:1 rejected tcp:x:1 email: a`); ok {
		t.Fatal("rejected must not count")
	}
	u, ip, host, port, net, ok = ParseHysteria(`2026-09-16T12:00:00Z DEBUG TCP request {"addr": "203.0.113.9:51234", "id": "alice|hy", "reqAddr": "example.com:443"}`)
	if !ok || u != "alice|hy" || ip != "203.0.113.9" || host != "example.com" || port != 443 || net != "tcp" {
		t.Fatalf("hysteria: %v %q %q %q %d %q", ok, u, ip, host, port, net)
	}
	c := &Collector{Cap: 2}
	c.Add("alice|in", "203.0.113.9", "example.com", 443, "tcp")
	if evs, _ := c.Drain(); len(evs) != 0 {
		t.Fatal("disabled collector must drop")
	}
	c.SetEnabled(true)
	for i := 0; i < 3; i++ {
		c.Add("alice|in", "203.0.113.9", "example.com", 443+i, "tcp")
	}
	evs, dropped := c.Drain()
	if len(evs) != 2 || dropped != 1 || evs[0].Port != 444 || evs[0].User != "alice" || evs[0].Inbound != "in" {
		t.Fatalf("ring: %+v dropped=%d", evs, dropped)
	}
}
