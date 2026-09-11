package core

import (
	"context"
	"testing"

	"gitlab.com/zeptop-group/bosun/internal/spec"
)

type fakeCore struct {
	name   string
	protos []spec.Protocol
}

func (f fakeCore) Name() string                                                    { return f.name }
func (f fakeCore) Capabilities() Capabilities                                      { return Capabilities{Protocols: f.protos} }
func (f fakeCore) Render(*spec.Node, []spec.Inbound, []spec.User) (*Bundle, error) { return nil, nil }
func (f fakeCore) Start(context.Context, *Bundle) error                            { return nil }
func (f fakeCore) Apply(context.Context, *Bundle) error                            { return nil }
func (f fakeCore) Stop(context.Context) error                                      { return nil }
func (f fakeCore) Running() bool                                                   { return false }
func (f fakeCore) Stats(context.Context, bool) (map[string]spec.Traffic, error)    { return nil, nil }

func TestAssign(t *testing.T) {
	r := NewRegistry()
	r.Register(fakeCore{"singbox", []spec.Protocol{spec.VLESS, spec.Hysteria2}})
	r.Register(fakeCore{"xray", []spec.Protocol{spec.VLESS}})

	got, err := r.Assign([]spec.Inbound{
		{Tag: "a", Protocol: spec.VLESS},
		{Tag: "b", Protocol: spec.VLESS, Core: "xray"},
		{Tag: "c", Protocol: spec.Hysteria2},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got["singbox"]) != 2 || len(got["xray"]) != 1 {
		t.Fatalf("unexpected assignment: %+v", got)
	}

	if _, err := r.Assign([]spec.Inbound{{Tag: "d", Protocol: spec.Mieru}}); err == nil {
		t.Fatal("expected error for unsupported protocol")
	}
	if _, err := r.Assign([]spec.Inbound{{Tag: "e", Protocol: spec.Hysteria2, Core: "xray"}}); err == nil {
		t.Fatal("expected error for explicit core lacking protocol")
	}
}
