package forward

import (
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestRealmConfig(t *testing.T) {
	cfg := realmConfig([]spec.Forward{
		{Tag: "web", Port: 24443, Protocol: "tcp", Target: "203.0.113.30:443", Backend: "realm"},
		{Tag: "game", Listen: "10.10.0.2", Port: 27015, Protocol: "both", Target: "198.51.100.20:27015", Backend: "realm"},
		{Tag: "dns", Port: 5353, Protocol: "udp", Target: "192.0.2.10:53", Backend: "realm"},
	})
	for _, want := range []string{
		"listen = \"0.0.0.0:24443\"\nremote = \"203.0.113.30:443\"\n",
		"listen = \"10.10.0.2:27015\"\nremote = \"198.51.100.20:27015\"\nnetwork = { use_udp = true }\n",
		"listen = \"0.0.0.0:5353\"\nremote = \"192.0.2.10:53\"\nnetwork = { no_tcp = true, use_udp = true }\n",
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("missing %q in:\n%s", want, cfg)
		}
	}
	if strings.Index(cfg, "# dns") > strings.Index(cfg, "# game") || strings.Index(cfg, "# game") > strings.Index(cfg, "# web") {
		t.Fatalf("not sorted by tag:\n%s", cfg)
	}
	if err := validate([]spec.Forward{{Tag: "x", Port: 1, Protocol: "tcp", Target: "192.0.2.10:1", Backend: "realm", PreserveSource: true}}); err == nil {
		t.Fatal("preserve_source with realm should be rejected")
	}
}

func TestRealmConfigSendProxy(t *testing.T) {
	cfg := realmConfig([]spec.Forward{{Tag: "pp", Port: 27016, Protocol: "tcp", Target: "198.51.100.20:443", Backend: "realm", ProxyProtocol: true}})
	if !strings.Contains(cfg, "network = { send_proxy = true, send_proxy_version = 2 }") {
		t.Fatalf("send_proxy missing:\n%s", cfg)
	}
}
