package doctor

import (
	"context"
	"errors"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"testing"
)

func TestServiceControlDoctorSeparatesIntentionalPauseFromFailedApply(t *testing.T) {
	node := &spec.Node{ServiceControl: &spec.ServiceControl{Revision: "paused", Mode: "pause"}, Inbounds: []spec.Inbound{{Tag: "managed", Protocol: spec.VLESS, Listen: "127.0.0.1", Port: 443}}}
	control := &agentproto.ServiceControlReport{Supported: true, DesiredRevision: "paused", AppliedRevision: "paused", Mode: "pause"}
	d := Deps{Node: node, ServiceControl: control, CoresKnown: true, Cores: []CoreState{{Name: "xray", Inbounds: 1}}, Dial: func(context.Context, string) error { return errors.New("intentionally closed") }, Exec: func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("unavailable") }}
	got := Run(context.Background(), d)
	if c := find(got, "service_control"); c.Status != OK {
		t.Fatal(c)
	}
	if find(got, "cores").ID != "" || find(got, "inbound:managed").ID != "" {
		t.Fatal("intentional paused listeners were reported failed", got)
	}
	control.AppliedRevision = ""
	control.Error = "nft unavailable"
	got = Run(context.Background(), d)
	if c := find(got, "service_control"); c.Status != Fail || c.Detail != "nft unavailable" {
		t.Fatal(c)
	}
	if find(got, "cores").ID == "" {
		t.Fatal("unconfirmed pause hid actual core failure")
	}
}
