package forward

import (
	"context"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"log/slog"
	"testing"
)

func TestServiceControlScopePreservesResolvedFamilyAndReleasesCache(t *testing.T) {
	m := NewManager(slog.Default())
	m.SetServiceControl(true)
	rules := []spec.Forward{
		{Tag: "v4", Backend: "nft", Protocol: "both", Port: 10443, Target: "198.51.100.20:443"},
		{Tag: "v6", Backend: "nft", Protocol: "tcp", Port: 10444, Target: "[2001:db8::20]:443"},
		{Tag: "relay", Backend: "relay", Protocol: "tcp", Port: 10445, Target: "198.51.100.20:443"},
	}
	scope, err := m.ServiceControlScope(context.Background(), rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(scope) != 2 || scope[0].Listen != "0.0.0.0" || scope[1].Listen != "::" {
		t.Fatal(scope)
	}
	for _, f := range scope {
		if f.Target != "" {
			t.Fatal("guard journal must not copy remote destinations")
		}
	}
	if len(m.preparedNFT) != 2 {
		t.Fatal("missing pinned targets")
	}
	m.SetServiceControl(false)
	if len(m.preparedNFT) != 0 || len(m.preparedNFTKeys) != 0 {
		t.Fatal("normal mode retained controlled DNS snapshots")
	}
}
