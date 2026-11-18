package singbox

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func wgFixture(protocol spec.Protocol, distribution string) (*spec.Node, spec.Inbound) {
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	link := spec.WireGuardLink{Slot: 7, PrivateKey: key, PeerKey: key, ListenPort: 51820, MTU: 1380, DomainPreference: "ipv4"}
	ib := spec.Inbound{Tag: "wg-entry", Core: distribution, Protocol: protocol, Port: 18443, WireGuardSlot: 7, Cipher: "2022-blake3-aes-128-gcm", SnellMultiUser: true}
	spec.FillInboundSecrets(&ib)
	return &spec.Node{WireGuardLinks: []spec.WireGuardLink{link}, Inbounds: []spec.Inbound{ib}}, ib
}
func TestWireGuardRoutesStayAheadOfOrdinaryExits(t *testing.T) {
	node, ib := wgFixture(spec.VLESS, "singbox")
	node.DefaultOutbound = "operator"
	node.Outbounds = []spec.Outbound{{Tag: "operator"}}
	node.Routes = []spec.RouteRule{{Action: "outbound", Value: "operator", Match: []string{"domain:example.com"}}}
	scoped := append([]spec.User(nil), users...)
	scoped[0].SpeedLimitMbps = 2
	raw, e := render(node, []spec.Inbound{ib}, scoped, renderOptions{})
	if e != nil {
		t.Fatal(e)
	}
	cfg := decode(t, raw)
	rules := cfg["route"].(map[string]any)["rules"].([]any)
	seenWG, seenOperator := false, false
	for _, r := range rules {
		rule := r.(map[string]any)
		out, _ := rule["outbound"].(string)
		if strings.HasPrefix(out, "wireguard-") {
			if seenOperator {
				t.Fatal("ordinary exit can capture WG traffic")
			}
			seenWG = true
		}
		if out == "operator" {
			seenOperator = true
		}
	}
	if !seenWG {
		t.Fatal("WG route missing")
	}
	for _, r := range cfg["outbounds"].([]any) {
		o := r.(map[string]any)
		tag, _ := o["tag"].(string)
		if !strings.HasPrefix(tag, "wireguard-") {
			continue
		}
		if o["inet4_bind_address"] == nil && o["inet6_bind_address"] == nil {
			t.Fatal("unbound WG exit")
		}
		if strings.Contains(tag, "-u1") && o["routing_mark"] != float64(spec.SpeedMark(scoped[0].ID)) {
			t.Fatal("user mark lost")
		}
	}
	// Patches that could erase WG routing must fail before rendering an artifact.
	node.Overrides = map[string]json.RawMessage{"singbox": json.RawMessage(`{"route":{"final":"direct"}}`)}
	if _, e = render(node, []spec.Inbound{ib}, scoped, renderOptions{}); e == nil {
		t.Fatal("routing override bypassed WG ownership")
	}
}
func TestRealSingboxWireGuardEntryConfigs(t *testing.T) {
	cp, kp := compatibilityCert(t)
	for _, distribution := range []string{"singbox", "singbox-extended"} {
		t.Run(distribution, func(t *testing.T) {
			bin := os.Getenv("BOSUN_SINGBOX_TEST_BINARY")
			if distribution == "singbox-extended" {
				bin = os.Getenv("BOSUN_EXTENDED_TEST_BINARY")
			}
			if bin == "" {
				t.Skip("set matching reviewed core binary")
			}
			protocols := []spec.Protocol{spec.VLESS, spec.VMess, spec.Trojan, spec.Shadowsocks, spec.Hysteria2, spec.TUIC, spec.AnyTLS, spec.Naive, spec.Snell, spec.SOCKS, spec.HTTP}
			if distribution == "singbox-extended" {
				protocols = append(protocols, spec.SSH, spec.Mieru)
			}
			for _, protocol := range protocols {
				t.Run(string(protocol), func(t *testing.T) {
					node, ib := wgFixture(protocol, distribution)
					if requiresTLS(protocol) {
						ib.TLS = &spec.TLS{Mode: spec.TLSStandard, ServerName: "example.com", CertPath: cp, KeyPath: kp}
					}
					if protocol == spec.Mieru {
						ib.MieruTransport = "TCP"
					}
					node.Inbounds = []spec.Inbound{ib}
					raw, e := render(node, node.Inbounds, users, renderOptions{Distribution: distribution, StatsListen: "127.0.0.1:19102"})
					if e != nil {
						t.Fatal(e)
					}
					path := filepath.Join(t.TempDir(), "config.json")
					if e = os.WriteFile(path, raw, 0600); e != nil {
						t.Fatal(e)
					}
					out, e := exec.Command(bin, "check", "-c", path).CombinedOutput()
					if e != nil {
						t.Fatalf("real parser: %v: %s", e, out)
					}
				})
			}
		})
	}
}

func TestWireGuardStandaloneCannotEnterSubscriberCounter(t *testing.T) {
	node, paid := wgFixture(spec.SOCKS, "singbox")
	separate := spec.Inbound{Tag: "independent", Core: "singbox", Protocol: spec.SOCKS, Port: 18445, Standalone: &spec.StandaloneAuth{Username: users[0].Name, Password: "fixture-password"}}
	node.Inbounds = []spec.Inbound{paid, separate}
	if _, err := render(node, node.Inbounds, users, renderOptions{}); err == nil {
		t.Fatal("standalone traffic could enter the subscriber's global username counter")
	}
	separate.Standalone.Username = "distinct-independent-account"
	node.Inbounds = []spec.Inbound{paid, separate}
	if _, err := render(node, node.Inbounds, users, renderOptions{}); err != nil {
		t.Fatal(err)
	}
}
