package xray

import (
	"github.com/zeptop-dev/bosun/pkg/spec"
	"strings"
	"testing"
)

func TestStandaloneSOCKSRestartKeyAndNoSubscribers(t *testing.T) {
	ib := spec.Inbound{Tag: "independent", Protocol: spec.SOCKS, Port: 1080, Standalone: &spec.StandaloneAuth{Username: "operator", Password: "first-secret"}}
	raw, first, err := render(&spec.Node{}, []spec.Inbound{ib}, users, renderOptions{APIListen: "127.0.0.1:9101"})
	if err != nil {
		t.Fatal(err)
	}
	in := decode(t, raw)["inbounds"].([]any)[0].(map[string]any)
	accounts := in["settings"].(map[string]any)["accounts"].([]any)
	if len(accounts) != 1 || accounts[0].(map[string]any)["user"] != "operator" || strings.Contains(string(raw), users[0].UUID) || len(first.users[ib.Tag]) != 0 {
		t.Fatal("standalone auth mixed with subscriber accounts")
	}
	ib.Standalone = &spec.StandaloneAuth{Username: "operator", Password: "second-secret"}
	_, second, err := render(&spec.Node{}, []spec.Inbound{ib}, users, renderOptions{APIListen: "127.0.0.1:9101"})
	if err != nil {
		t.Fatal(err)
	}
	if first.inboundsKey == second.inboundsKey {
		t.Fatal("credential rotation could incorrectly take the hot-user path")
	}
}
