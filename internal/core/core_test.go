package core

import (
	"context"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

type fakeCore struct {
	name   string
	protos []spec.Protocol
	trans  []string
}

func (f fakeCore) Name() string { return f.name }
func (f fakeCore) Capabilities() Capabilities {
	return Capabilities{Protocols: f.protos, Transports: f.trans}
}
func (f fakeCore) Render(*spec.Node, []spec.Inbound, []spec.User) (*Bundle, error) { return nil, nil }
func (f fakeCore) Start(context.Context, *Bundle) error                            { return nil }
func (f fakeCore) Apply(context.Context, *Bundle) error                            { return nil }
func (f fakeCore) Stop(context.Context) error                                      { return nil }
func (f fakeCore) Running() bool                                                   { return false }
func (f fakeCore) Stats(context.Context, bool) (map[string]spec.Traffic, error)    { return nil, nil }

func TestAssign(t *testing.T) {
	r := NewRegistry()
	r.Register(fakeCore{"singbox", []spec.Protocol{spec.VLESS, spec.Hysteria2}, []string{"ws"}})
	r.Register(fakeCore{"xray", []spec.Protocol{spec.VLESS}, []string{"ws", "xhttp"}})

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
	got, err = r.Assign([]spec.Inbound{{Tag: "f", Protocol: spec.VLESS, Transport: &spec.Transport{Type: "xhttp"}}})
	if err != nil || len(got["xray"]) != 1 {
		t.Fatalf("xhttp should land on xray: %v %v", got, err)
	}
	if _, err := r.Assign([]spec.Inbound{{Tag: "g", Protocol: spec.VLESS, Transport: &spec.Transport{Type: "grpc"}}}); err == nil {
		t.Fatal("expected error for unsupported transport")
	}
}

func TestSplit(t *testing.T) {
	r := NewRegistry()
	r.Register(fakeCore{"singbox", []spec.Protocol{spec.VLESS}, nil})
	byCore, unsupported := r.Split([]spec.Inbound{
		{Tag: "a", Protocol: spec.VLESS},
		{Tag: "b", Protocol: spec.Snell},
		{Tag: "c", Protocol: spec.VLESS, Core: "xray"},
	})
	if len(byCore["singbox"]) != 1 || byCore["singbox"][0].Tag != "a" {
		t.Fatalf("unexpected assignment: %+v", byCore)
	}
	if len(unsupported) != 2 || unsupported["b"] == "" || unsupported["c"] == "" {
		t.Fatalf("expected b and c unsupported with reasons: %v", unsupported)
	}
}

func TestSupportsProxyProtocol(t *testing.T) {
	plain := Capabilities{Protocols: []spec.Protocol{spec.VLESS}}
	pp := Capabilities{Protocols: []spec.Protocol{spec.VLESS}, ProxyProtocol: true}
	ib := spec.Inbound{Tag: "a", Protocol: spec.VLESS, AcceptProxyProtocol: true}
	if plain.Supports(ib) || !pp.Supports(ib) {
		t.Fatal("accept_proxy_protocol must route to a core that reads the header")
	}
}
