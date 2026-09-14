package snell

import (
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestRender(t *testing.T) {
	out, err := render(spec.Inbound{Tag: "s", Protocol: spec.Snell, Port: 6160, SnellPSK: "secret", SnellObfs: "http", SnellObfsHost: "www.bing.com"})
	if err != nil {
		t.Fatal(err)
	}
	want := "[snell-server]\nlisten = 0.0.0.0:6160\npsk = secret\nipv6 = false\nobfs = http\nobfs-host = www.bing.com\n"
	if string(out) != want {
		t.Fatalf("got\n%s", out)
	}
	out, _ = render(spec.Inbound{Tag: "s", Protocol: spec.Snell, Port: 6160, Listen: "10.10.0.2", SnellPSK: "secret"})
	if !strings.Contains(string(out), "listen = 10.10.0.2:6160\n") || !strings.Contains(string(out), "obfs = off\n") || strings.Contains(string(out), "obfs-host") {
		t.Fatalf("got\n%s", out)
	}
	for _, bad := range []spec.Inbound{
		{Tag: "s", Protocol: spec.Snell, Port: 6160},
		{Tag: "s", Protocol: spec.Snell, Port: 6160, SnellPSK: "x", SnellObfs: "quic"},
		{Tag: "s", Protocol: spec.Mieru, Port: 6160, SnellPSK: "x"},
	} {
		if _, err := render(bad); err == nil {
			t.Fatalf("expected error for %+v", bad)
		}
	}
}
