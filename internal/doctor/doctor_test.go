package doctor

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/dstatus"
	"github.com/zeptop-dev/bosun/internal/shaper"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func find(r Report, id string) Check {
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	return Check{}
}

func TestListenersAndConflicts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadPort := dead.Addr().(*net.TCPAddr).Port
	dead.Close()
	node := &spec.Node{Inbounds: []spec.Inbound{
		{Tag: "ok", Protocol: spec.VLESS, Port: port},
		{Tag: "dead", Protocol: spec.Trojan, Port: deadPort, TLS: &spec.TLS{Mode: spec.TLSStandard, ServerName: "jp1.example.com"}},
		{Tag: "hy2", Protocol: spec.Hysteria2, Port: port},
		{Tag: "dup", Protocol: spec.Shadowsocks, Port: port},
	}}
	exec := func(_ context.Context, name string, _ ...string) ([]byte, error) {
		return nil, errors.New(name + " missing")
	}
	rep := Run(context.Background(), Deps{Node: node, Cores: []CoreState{{Name: "xray", Running: true, Inbounds: 2}}, CoresKnown: true,
		Certs: []CertState{{Domain: "*.example.com", NotAfter: time.Now().Add(5 * 24 * time.Hour)}},
		Host:  spec.SystemStatus{DiskTotal: 100, DiskUsed: 95, MemTotal: 100, MemUsed: 50}, Exec: exec})
	if c := find(rep, "inbound:ok"); c.Status != OK {
		t.Fatalf("ok listener: %+v", c)
	}
	if c := find(rep, "inbound:dead"); c.Status != Fail || !strings.Contains(c.Detail, strconv.Itoa(deadPort)) {
		t.Fatalf("dead listener: %+v", c)
	}
	if c := find(rep, "inbound:hy2"); c.Status != Skip || c.Detail != "udp" {
		t.Fatalf("udp inbound: %+v", c)
	}
	if c := find(rep, "ports"); c.Status != Fail || !strings.Contains(c.Detail, "tcp/"+strconv.Itoa(port)) {
		t.Fatalf("port conflict: %+v", c)
	}
	if c := find(rep, "cert:jp1.example.com"); c.Status != Warn || !strings.Contains(c.Detail, "expires in") {
		t.Fatalf("cert via wildcard, expiring soon: %+v", c)
	}
	if c := find(rep, "disk"); c.Status != Warn {
		t.Fatalf("disk: %+v", c)
	}
	if c := find(rep, "firewall"); c.Status != Skip {
		t.Fatalf("firewall without tools: %+v", c)
	}
	if c := find(rep, "cores"); c.Status != OK {
		t.Fatalf("cores: %+v", c)
	}
	if rep.Summary.Fail != 2 || !rep.Failed() {
		t.Fatalf("summary: %+v", rep.Summary)
	}
	if !rep.Same(&rep) || rep.Same(&Report{}) {
		t.Fatal("Same")
	}
}

func TestBindFirewallPanel(t *testing.T) {
	node := &spec.Node{Inbounds: []spec.Inbound{{Tag: "line", Protocol: spec.Mieru, Listen: "10.10.0.2", Port: 17710, MieruTransport: "TCP"}}}
	exec := func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch name {
		case "nft":
			return []byte("table inet filter {\n chain input {\n type filter hook input priority 0; policy drop;\n tcp dport 22 accept\n }\n}"), nil
		case "timedatectl":
			return []byte("NTPSynchronized=no\n"), nil
		}
		return nil, errors.New("missing")
	}
	now := time.Now()
	rep := Run(context.Background(), Deps{Node: node, CoresKnown: true, Cores: []CoreState{{Name: "mita", Running: false, Inbounds: 1}},
		Dial: func(context.Context, string) error { return nil }, Exec: exec,
		Interfaces: func() []net.IP { return []net.IP{net.ParseIP("192.0.2.10")} },
		Managed:    true, LastReport: now.Add(-10 * time.Minute), PushInterval: time.Minute, KomariEnabled: true, KomariError: "token rejected",
		Now: func() time.Time { return now }})
	if c := find(rep, "bind"); c.Status != Fail || !strings.Contains(c.Detail, "10.10.0.2") {
		t.Fatalf("bind: %+v", c)
	}
	if c := find(rep, "firewall"); c.Status != Warn || !strings.Contains(c.Detail, "line:17710") {
		t.Fatalf("firewall: %+v", c)
	}
	if c := find(rep, "cores"); c.Status != Fail {
		t.Fatalf("cores: %+v", c)
	}
	if c := find(rep, "panel"); c.Status != Warn {
		t.Fatalf("panel: %+v", c)
	}
	if c := find(rep, "komari"); c.Status != Warn {
		t.Fatalf("komari: %+v", c)
	}
	if c := find(rep, "time"); c.Status != Warn {
		t.Fatalf("time: %+v", c)
	}
	if c := find(rep, "inbound:line"); c.Status != OK || c.Detail != "10.10.0.2:17710" {
		t.Fatalf("bound inbound dial address: %+v", c)
	}
}

func TestRealityTargets(t *testing.T) {
	node := &spec.Node{Inbounds: []spec.Inbound{
		{Tag: "cf", Protocol: spec.VLESS, Port: 443, TLS: &spec.TLS{Mode: spec.TLSReality, ServerName: "www.example.com", Reality: &spec.Reality{PrivateKey: "k", HandshakeServer: "www.example.com", HandshakePort: 443}}},
		{Tag: "sb", Protocol: spec.VLESS, Port: 8443, TLS: &spec.TLS{Mode: spec.TLSReality, ServerName: "www.apple.com", Reality: &spec.Reality{PrivateKey: "k", HandshakeServer: "www.apple.com", HandshakePort: 443}}},
		{Tag: "off", Protocol: spec.VLESS, Port: 9443, TLS: &spec.TLS{Mode: spec.TLSReality, ServerName: "www.apple.com", Reality: &spec.Reality{PrivateKey: "k", HandshakeServer: "www.apple.com", HandshakePort: 443, FallbackLimit: &spec.FallbackLimit{Off: true}}}},
	}}
	lookup := func(_ context.Context, host string) ([]net.IP, error) {
		if host == "www.example.com" {
			return []net.IP{net.ParseIP("104.16.124.96")}, nil
		}
		return []net.IP{net.ParseIP("198.51.100.20")}, nil
	}
	rep := Run(context.Background(), Deps{Node: node, Lookup: lookup, Assign: map[string]string{"cf": "xray", "sb": "singbox", "off": "xray"},
		Dial: func(context.Context, string) error { return nil }, Exec: func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("missing") }})
	if c := find(rep, "reality:cf"); c.Status != Fail || !strings.Contains(c.Detail, "cloudflare") {
		t.Fatalf("cdn target: %+v", c)
	}
	if c := find(rep, "reality:sb"); c.Status != Warn || !strings.Contains(c.Detail, "singbox") {
		t.Fatalf("sing-box warning: %+v", c)
	}
	if c := find(rep, "reality:off"); c.Status != Warn || !strings.Contains(c.Detail, "off") {
		t.Fatalf("limit off warning: %+v", c)
	}
}

// A node that just came up has not had a report accepted yet, and that is
// not a fault: warning about it would put a red mark on the panel after
// every restart, until the next doctor run cleared it by itself.
func TestPanelContactIsQuietRightAfterAStart(t *testing.T) {
	now := time.Now()
	base := Deps{Managed: true, PushInterval: time.Minute, Now: func() time.Time { return now }}
	base.Started = now.Add(-5 * time.Second)
	if c := find(Run(context.Background(), base), "panel"); c.Status != Skip {
		t.Fatalf("just started: %+v", c)
	}
	base.Started = now.Add(-30 * time.Minute)
	if c := find(Run(context.Background(), base), "panel"); c.Status != Warn {
		t.Fatalf("up for half an hour with nothing accepted: %+v", c)
	}
}

// Shaping only the upload direction is a warning that names the missing
// half, not a green light and not a failure.
func TestShaperUploadOnlyWarns(t *testing.T) {
	d := Deps{Shaper: &shaper.Status{Supported: true, Users: 3, Interface: "eth0",
		DownloadError: "the kernel will not mirror ingress onto ifb-bosun, so only the upload direction is limited: exit status 1"}}
	c := find(Run(context.Background(), d), "shaper")
	if c.Status != Warn || !strings.Contains(c.Detail, "upload only") {
		t.Fatalf("upload-only: %+v", c)
	}
	d.Shaper = &shaper.Status{Supported: true, Users: 3, Interface: "eth0"}
	if c := find(Run(context.Background(), d), "shaper"); c.Status != OK {
		t.Fatalf("both directions: %+v", c)
	}
}

// The DStatus endpoint is scraped, not pushed, so "up but nobody has ever
// read it" is the interesting state — that is a firewall or a wrong
// address in the panel, and a refused-key count says which.
func TestDStatusCheck(t *testing.T) {
	now := time.Now()
	at := func(d Deps) Check {
		d.Now = func() time.Time { return now }
		return find(Run(context.Background(), d), "dstatus")
	}

	if c := at(Deps{}); c.Status != Skip {
		t.Fatalf("off: %+v", c)
	}
	if c := at(Deps{DStatus: &dstatus.Status{Enabled: true, Listen: ":9999", LastError: "bind: address already in use"}}); c.Status != Fail {
		t.Fatalf("cannot listen: %+v", c)
	}
	c := at(Deps{DStatus: &dstatus.Status{Enabled: true, Listen: ":9999", Denied: 3}})
	if c.Status != Warn || !strings.Contains(c.Detail, "never scraped") || !strings.Contains(c.Detail, "wrong key") {
		t.Fatalf("never scraped with refusals: %+v", c)
	}
	if c := at(Deps{DStatus: &dstatus.Status{Enabled: true, Listen: ":9999", LastScrape: now.Add(-30 * time.Minute)}}); c.Status != Warn {
		t.Fatalf("stale: %+v", c)
	}
	if c := at(Deps{DStatus: &dstatus.Status{Enabled: true, Listen: ":9999", LastScrape: now.Add(-5 * time.Second)}}); c.Status != OK {
		t.Fatalf("healthy: %+v", c)
	}
}

// Active mode is judged by whether the panel accepts the reports, and a
// refusal after earlier acceptance is a warning that carries the reason.
func TestDStatusActiveCheck(t *testing.T) {
	now := time.Now()
	at := func(st dstatus.Status) Check {
		return find(Run(context.Background(), Deps{DStatus: &st, Now: func() time.Time { return now }}), "dstatus")
	}
	if c := at(dstatus.Status{Enabled: true, Mode: "active", Server: "https://p.example.com", Interval: 3}); c.Status != Warn || !strings.Contains(c.Detail, "no report accepted") {
		t.Fatalf("nothing accepted yet: %+v", c)
	}
	if c := at(dstatus.Status{Enabled: true, Mode: "active", Server: "https://p.example.com", Interval: 3, LastError: "the panel URL must start with http:// or https://"}); c.Status != Fail {
		t.Fatalf("cannot start: %+v", c)
	}
	if c := at(dstatus.Status{Enabled: true, Mode: "active", Server: "https://p.example.com", Interval: 3, Reports: 9, LastReport: now.Add(-2 * time.Second)}); c.Status != OK {
		t.Fatalf("healthy: %+v", c)
	}
	c := at(dstatus.Status{Enabled: true, Mode: "active", Server: "https://p.example.com", Interval: 3, Reports: 9, LastReport: now.Add(-5 * time.Minute), LastError: "panel refused the report: API 密钥无效"})
	if c.Status != Warn || !strings.Contains(c.Detail, "密钥") {
		t.Fatalf("stale with a reason: %+v", c)
	}
}
