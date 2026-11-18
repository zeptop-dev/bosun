package ui

import (
	"github.com/zeptop-dev/bosun/pkg/spec"
	"github.com/zeptop-dev/bosun/pkg/subscription"
	"testing"
)

func TestNaiveLocalSharePreservesLoginName(t *testing.T) {
	ib := spec.Inbound{Protocol: spec.Naive, TLS: &spec.TLS{Mode: spec.TLSStandard, ServerName: "node.example.com"}}
	u := spec.User{Name: "local-alice", UUID: "11111111-1111-1111-1111-111111111111", Password: "test-password"}
	uri := shareURI(ib, "2001:db8::1", 8445, "Naive", u)
	line, err := subscription.ParseURI(uri)
	if err != nil || line.UUID != u.Name || line.Password != u.Password || line.Host != "2001:db8::1" {
		t.Fatalf("local login changed: %v %#v", err, line)
	}
}
