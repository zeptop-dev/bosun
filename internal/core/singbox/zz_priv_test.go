package singbox

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// User traffic to the node's own loopback and private neighbourhood is
// rejected before any other rule, with the node's exceptions kept.
func TestRenderPrivateDestBlocked(t *testing.T) {
	node := &spec.Node{PrivateDestAllow: []string{"10.10.0.0/24", "junk"}}
	ins := []spec.Inbound{{Tag: "a", Protocol: spec.Shadowsocks, Port: 8388, Cipher: "aes-128-gcm"}}
	users := []spec.User{{ID: 1, Name: "u", Password: "p"}}
	out, err := render(node, ins, users, renderOptions{StatsListen: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = json.Unmarshal(out, &cfg)
	rules := cfg["route"].(map[string]any)["rules"].([]any)
	// sniff first, then the allow rule, then the reject
	allow := rules[1].(map[string]any)
	reject := rules[2].(map[string]any)
	if allow["outbound"] != "direct" || allow["ip_cidr"].([]any)[0] != "10.10.0.0/24" || len(allow["ip_cidr"].([]any)) != 1 {
		t.Fatalf("allow rule: %v", allow)
	}
	if reject["action"] != "reject" || !strings.Contains(string(out), "127.0.0.0/8") {
		t.Fatalf("reject rule: %v", reject)
	}
	node.AllowPrivateDest = true
	out, _ = render(node, ins, users, renderOptions{StatsListen: "127.0.0.1:1"})
	if strings.Contains(string(out), "127.0.0.0/8") {
		t.Fatal("allow_private_dest must drop the reject rule")
	}
}
