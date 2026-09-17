package xray

import (
	"encoding/json"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestRenderPortMatch(t *testing.T) {
	node := &spec.Node{AllowPrivateDest: true, Routes: []spec.RouteRule{{Match: []string{"port:25", "port:6881-6889,443"}, Action: "block"}}}
	ins := []spec.Inbound{{Tag: "a", Protocol: spec.VLESS, Port: 443}}
	out, _, err := render(node, ins, []spec.User{{ID: 1, Name: "u", UUID: "00000000-0000-0000-0000-000000000001"}}, renderOptions{LogLevel: "warning", APIListen: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = json.Unmarshal(out, &cfg)
	for _, r := range cfg["routing"].(map[string]any)["rules"].([]any) {
		if rm := r.(map[string]any); rm["port"] != nil {
			if rm["port"] != "25,6881-6889,443" {
				t.Fatalf("port rule: %v", rm)
			}
			return
		}
	}
	t.Fatalf("no port rule:\n%s", out)
}
