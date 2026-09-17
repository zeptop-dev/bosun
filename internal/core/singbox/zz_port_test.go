package singbox

import (
	"encoding/json"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// A port match renders in sing-box's own syntax: single ports in "port",
// ranges as "a:b". An empty value is dropped instead of matching all.
func TestRenderPortMatch(t *testing.T) {
	node := &spec.Node{AllowPrivateDest: true, Routes: []spec.RouteRule{
		{Match: []string{"port:25", "port:6881-6889,443"}, Action: "block"},
		{Match: []string{"keyword:"}, Action: "block"},
	}}
	ins := []spec.Inbound{{Tag: "a", Protocol: spec.Shadowsocks, Port: 8388, Cipher: "aes-128-gcm"}}
	out, err := render(node, ins, []spec.User{{ID: 1, Name: "u", Password: "p"}}, renderOptions{StatsListen: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = json.Unmarshal(out, &cfg)
	rules := cfg["route"].(map[string]any)["rules"].([]any)
	var portRule, emptyRule map[string]any
	for _, r := range rules {
		rm := r.(map[string]any)
		if rm["port"] != nil || rm["port_range"] != nil {
			portRule = rm
		} else if rm["action"] == "reject" && rm["port"] == nil && rm["domain_keyword"] == nil && rm["ip_cidr"] == nil {
			emptyRule = rm
		}
	}
	if portRule == nil {
		t.Fatalf("no port rule:\n%s", out)
	}
	ports := portRule["port"].([]any)
	ranges := portRule["port_range"].([]any)
	if len(ports) != 2 || ports[0] != float64(25) || ports[1] != float64(443) || len(ranges) != 1 || ranges[0] != "6881:6889" {
		t.Fatalf("port rule: %v", portRule)
	}
	if emptyRule == nil {
		t.Fatalf("the empty keyword rule should render as an empty reject, not a match-all: %v", rules)
	}
	if emptyRule["domain_keyword"] != nil {
		t.Fatalf("empty keyword value reached the config: %v", emptyRule)
	}
}
