package agent

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

type fakeCore struct {
	name    string
	protos  []spec.Protocol
	running bool
	applied []string
	fail    error
}

func (f *fakeCore) Name() string { return f.name }
func (f *fakeCore) Capabilities() core.Capabilities {
	return core.Capabilities{Protocols: f.protos}
}
func (f *fakeCore) Render(_ *spec.Node, ibs []spec.Inbound, _ []spec.User) (*core.Bundle, error) {
	f.applied = f.applied[:0]
	for _, ib := range ibs {
		f.applied = append(f.applied, ib.Tag)
	}
	return &core.Bundle{}, nil
}
func (f *fakeCore) Start(context.Context, *core.Bundle) error {
	if f.fail != nil {
		return f.fail
	}
	f.running = true
	return nil
}
func (f *fakeCore) Apply(context.Context, *core.Bundle) error                    { return f.fail }
func (f *fakeCore) Stop(context.Context) error                                   { f.running = false; return nil }
func (f *fakeCore) Running() bool                                                { return f.running }
func (f *fakeCore) Stats(context.Context, bool) (map[string]spec.Traffic, error) { return nil, nil }

type nopDriver struct{}

func (nopDriver) Name() string                                          { return "test" }
func (nopDriver) Node(context.Context) (*spec.Node, bool, error)        { return nil, false, nil }
func (nopDriver) Users(context.Context) ([]spec.User, bool, error)      { return nil, false, nil }
func (nopDriver) PushTraffic(context.Context, []spec.UserTraffic) error { return nil }
func (nopDriver) PushStatus(context.Context, spec.SystemStatus) error   { return nil }
func (nopDriver) Intervals() spec.Intervals                             { return spec.Intervals{} }

// One unsupported inbound and one mita inbound without users must not stop
// the other cores from being applied; both show up as skipped with a reason.
func TestApplySkipsUnsupportedAndUserlessMita(t *testing.T) {
	reg := core.NewRegistry()
	sb := &fakeCore{name: "singbox", protos: []spec.Protocol{spec.VLESS}}
	mita := &fakeCore{name: "mita", protos: []spec.Protocol{spec.Mieru}}
	reg.Register(sb)
	reg.Register(mita)
	a := New(&config.Config{DataDir: t.TempDir()}, nopDriver{}, reg, nil, slog.Default())
	a.node = &spec.Node{Inbounds: []spec.Inbound{
		{Tag: "vless", Protocol: spec.VLESS, Port: 1},
		{Tag: "snell", Protocol: spec.Snell, Port: 2, SnellPSK: "psk"},
		{Tag: "mieru", Protocol: spec.Mieru, Port: 3},
	}}
	if err := a.applyInner(context.Background()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(sb.applied) != 1 || sb.applied[0] != "vless" || !sb.running {
		t.Fatalf("singbox should serve vless: %v running=%v", sb.applied, sb.running)
	}
	if mita.running {
		t.Fatal("mita must not start without users")
	}
	st := a.Status()
	if st.Skipped["snell"] == "" || st.Skipped["mieru"] == "" {
		t.Fatalf("expected skip reasons for snell and mieru: %v", st.Skipped)
	}
	// Users arrive: mita starts on the next apply and its skip clears.
	a.users = []spec.User{{ID: 1, Name: "u", UUID: "x"}}
	if err := a.applyInner(context.Background()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !mita.running || len(mita.applied) != 1 {
		t.Fatalf("mita should run once users exist: %v", mita.applied)
	}
	if _, ok := a.Status().Skipped["mieru"]; ok {
		t.Fatal("mieru skip should clear once users exist")
	}
}

// A failing core reports its error but the others are still applied.
func TestApplyContinuesPastFailingCore(t *testing.T) {
	reg := core.NewRegistry()
	bad := &fakeCore{name: "hysteria", protos: []spec.Protocol{spec.Hysteria2}, fail: errors.New("boom")}
	sb := &fakeCore{name: "singbox", protos: []spec.Protocol{spec.VLESS}}
	reg.Register(bad)
	reg.Register(sb)
	a := New(&config.Config{DataDir: t.TempDir()}, nopDriver{}, reg, nil, slog.Default())
	a.node = &spec.Node{Inbounds: []spec.Inbound{
		{Tag: "hy2", Protocol: spec.Hysteria2, Port: 1, TLS: &spec.TLS{Mode: spec.TLSStandard, ServerName: "x", CertPath: "/c", KeyPath: "/k"}},
		{Tag: "vless", Protocol: spec.VLESS, Port: 2},
	}}
	err := a.applyInner(context.Background())
	if err == nil || !errors.Is(err, bad.fail) {
		t.Fatalf("expected the hysteria error, got %v", err)
	}
	if !sb.running {
		t.Fatal("singbox should still have been applied")
	}
}

// A managed node has no local store: the WARP account lands in a file
// under the data dir and is picked up when outbounds resolve.
func TestWARPAccountFileFallback(t *testing.T) {
	a := New(&config.Config{DataDir: t.TempDir()}, nopDriver{}, core.NewRegistry(), nil, slog.Default())
	if a.warpAccount() != nil {
		t.Fatal("no account yet")
	}
	if err := a.saveWARP(&spec.WARPAccount{ID: "x", PrivateKey: "k", PeerPublicKey: "p"}); err != nil {
		t.Fatal(err)
	}
	if got := a.warpAccount(); got == nil || got.PrivateKey != "k" {
		t.Fatalf("account should load from the file: %+v", got)
	}
}

// A rule the cores cannot render is dropped here and reported, instead of
// being written into a config no core will load: the panel is trusted to
// mean well, not to be correct, and one bad rule must not take a node's
// whole configuration down.
func TestValidateNodeDropsUnrenderableRules(t *testing.T) {
	node := &spec.Node{
		Routes: []spec.RouteRule{
			{Match: []string{"domain:example.com"}, Action: "direct"},
			{Match: []string{"ip:not-an-address"}, Action: "direct"},
		},
		AuditRules: []spec.AuditRule{
			{ID: 1, Name: "bt", Match: []string{"protocol:bittorrent"}, Action: "block"},
			{ID: 2, Name: "empty", Match: []string{"keyword:"}, Action: "block"},
			{ID: 3, Name: "bad port", Match: []string{"port:not-a-port"}, Action: "log"},
		},
	}
	var reported []string
	got := validateNode(node, slog.Default(), func(msgs []string) { reported = msgs })
	if len(got.Routes) != 1 || got.Routes[0].Match[0] != "domain:example.com" {
		t.Fatalf("routes = %v", got.Routes)
	}
	if len(got.AuditRules) != 1 || got.AuditRules[0].ID != 1 {
		t.Fatalf("audit rules = %v", got.AuditRules)
	}
	if len(reported) != 3 {
		t.Fatalf("the doctor was told about %d of 3 dropped rules: %v", len(reported), reported)
	}
	// The caller's node is left alone, so nothing else sees the trimmed copy.
	if len(node.AuditRules) != 3 {
		t.Fatalf("the incoming node was modified in place")
	}
	// A node whose rules are all fine is passed through untouched.
	clean := &spec.Node{AuditRules: []spec.AuditRule{{ID: 1, Name: "bt", Match: []string{"protocol:bittorrent"}, Action: "block"}}}
	if validateNode(clean, slog.Default(), nil) != clean {
		t.Fatal("a valid node was copied for no reason")
	}
}

// The node opens port 80 for itself exactly when something on it asks for
// a certificate over HTTP-01: a firewall that blocks it lets the first
// issuance work from a machine with no firewall yet and then fails a
// renewal two months later.
func TestNeedsHTTP01(t *testing.T) {
	served := map[string]string{"in": "singbox", "decoyless": "xray"}
	auto := func(method string) *spec.Inbound {
		return &spec.Inbound{Tag: "in", TLS: &spec.TLS{Mode: spec.TLSStandard, ServerName: "node.example.com", AutoCert: true, ACME: method}}
	}
	cases := []struct {
		name string
		node spec.Node
		want bool
	}{
		{"no tls at all", spec.Node{Inbounds: []spec.Inbound{{Tag: "in"}}}, false},
		{"auto_cert, method unset (http by default)", spec.Node{Inbounds: []spec.Inbound{*auto("")}}, true},
		{"auto_cert over http", spec.Node{Inbounds: []spec.Inbound{*auto("http")}}, true},
		{"auto_cert over dns", spec.Node{Inbounds: []spec.Inbound{*auto("dns")}}, false},
		{"certificate from the panel, not ACME", spec.Node{Inbounds: []spec.Inbound{{Tag: "in", TLS: &spec.TLS{Mode: spec.TLSStandard, ServerName: "node.example.com"}}}}, false},
		{"inbound no core serves", spec.Node{Inbounds: []spec.Inbound{{Tag: "unserved", TLS: &spec.TLS{Mode: spec.TLSStandard, AutoCert: true}}}}, false},
		{"decoy site over http", spec.Node{Decoy: &spec.Decoy{Domain: "decoy.example.com"}}, true},
		{"decoy site over dns", spec.Node{Decoy: &spec.Decoy{Domain: "decoy.example.com", ACME: "dns"}}, false},
	}
	for _, c := range cases {
		if got := needsHTTP01(&c.node, served); got != c.want {
			t.Errorf("%s: needsHTTP01 = %v, want %v", c.name, got, c.want)
		}
	}
}

// The endpoint is scraped from outside, so its port has to be opened —
// but not when it is off, bound to loopback, or nonsense. The firewall is
// synced from the desired config, not the running exporter, because the
// two are set up on different paths and the exporter is still off when
// the setting first arrives.
func TestDStatusPortIsOpenedOnlyWhenReachable(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *spec.DStatus
		want int
	}{
		{"off", nil, 0},
		{"disabled", &spec.DStatus{Listen: ":9999"}, 0},
		{"default listen", &spec.DStatus{Enabled: true}, 9999},
		{"any address", &spec.DStatus{Enabled: true, Listen: "[::]:9999"}, 9999},
		{"one address", &spec.DStatus{Enabled: true, Listen: "198.51.100.20:9100"}, 9100},
		{"loopback", &spec.DStatus{Enabled: true, Listen: "127.0.0.1:9999"}, 0},
		{"no colon", &spec.DStatus{Enabled: true, Listen: "9999"}, 0},
		{"active mode dials out", &spec.DStatus{Enabled: true, Mode: spec.DStatusActive, Listen: ":9999"}, 0},
	} {
		if got := dstatusPortFor(tc.cfg); got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, got, tc.want)
		}
	}
}
