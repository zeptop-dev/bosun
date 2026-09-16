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
		{Tag: "snell", Protocol: spec.Snell, Port: 2},
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
		{Tag: "hy2", Protocol: spec.Hysteria2, Port: 1},
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
