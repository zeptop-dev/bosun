package ui

import (
	"net/url"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestMieruShareLinkKnobs(t *testing.T) {
	u := spec.User{UUID: "alice", Password: "pw"}
	ib := spec.Inbound{Tag: "m", Protocol: spec.Mieru, Port: 17701, MieruTransport: "BOTH", MieruMTU: 1400, MieruMultiplexing: "MULTIPLEXING_HIGH", MieruHandshake: "HANDSHAKE_NO_WAIT"}
	link := shareURI(ib, "203.0.113.30", 17701, "jp", u)
	if !strings.HasPrefix(link, "mierus://alice:pw@203.0.113.30?") {
		t.Fatalf("link: %s", link)
	}
	q, err := url.ParseQuery(strings.SplitN(link, "?", 2)[1])
	if err != nil {
		t.Fatal(err)
	}
	if got := q["port"]; len(got) != 2 || got[0] != "17701" || got[1] != "17702" {
		t.Fatalf("ports: %v", got)
	}
	if got := q["protocol"]; len(got) != 2 || got[0] != "TCP" || got[1] != "UDP" {
		t.Fatalf("protocols: %v", got)
	}
	if q.Get("mtu") != "1400" || q.Get("multiplexing") != "MULTIPLEXING_HIGH" || q.Get("handshake-mode") != "HANDSHAKE_NO_WAIT" || q.Get("profile") != "jp" {
		t.Fatalf("params: %v", q)
	}
	// Defaults stay out of the link.
	plain := shareURI(spec.Inbound{Tag: "m", Protocol: spec.Mieru, Port: 2012}, "203.0.113.30", 2012, "jp", u)
	if strings.Contains(plain, "mtu=") || strings.Contains(plain, "multiplexing=") || strings.Contains(plain, "handshake") || !strings.Contains(plain, "protocol=TCP") {
		t.Fatalf("plain: %s", plain)
	}
}

func TestSnellShareLine(t *testing.T) {
	u := spec.User{UUID: "alice", Password: "pw"}
	line := shareURI(spec.Inbound{Tag: "s", Protocol: spec.Snell, Port: 6160, SnellPSK: "secret", SnellObfs: "http", SnellObfsHost: "www.bing.com"}, "203.0.113.30", 6160, "jp", u)
	if line != "jp = snell, 203.0.113.30, 6160, psk=secret, version=5, obfs=http, obfs-host=www.bing.com" {
		t.Fatalf("line: %s", line)
	}
	line = shareURI(spec.Inbound{Tag: "s", Protocol: spec.Snell, Port: 6160, SnellPSK: "secret", SnellVersion: 4}, "203.0.113.30", 6160, "jp", u)
	if line != "jp = snell, 203.0.113.30, 6160, psk=secret, version=4" {
		t.Fatalf("line: %s", line)
	}
}
