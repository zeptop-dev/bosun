package xray

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
	"github.com/zeptop-dev/bosun/pkg/wg"
)

func deviceTestInbound(t *testing.T) spec.Inbound {
	t.Helper()
	private, _, err := wg.Keypair()
	if err != nil {
		t.Fatal(err)
	}
	return spec.Inbound{Tag: "wg", Protocol: spec.WireGuard, Port: 51820, WGPrivateKey: private}
}

func TestWireGuardDevicePeersShareAccount(t *testing.T) {
	ib := deviceTestInbound(t)
	u := spec.User{ID: 1, Name: "account", UUID: "account-uuid", SpeedLimitMbps: 2, WireGuardPeers: []spec.WireGuardPeer{
		{UUID: "phone", Address: "10.67.0.1/32"},
		{UUID: "laptop", Address: "10.67.0.2/32"},
	}}
	peers, err := wireGuardPeers(ib, []spec.User{u})
	if err != nil || len(peers) != 3 {
		t.Fatalf("expected legacy and two device peers: %v", err)
	}
	_, legacyPublic, _ := wg.DerivePeer(ib.WGPrivateKey, u.UUID)
	if peers[0]["publicKey"] != legacyPublic {
		t.Fatal("legacy key changed")
	}
	for index, device := range u.WireGuardPeers {
		_, public, _ := wg.DeriveDevicePeer(ib.WGPrivateKey, u.UUID, device.UUID)
		peer := peers[index+1]
		if peer["publicKey"] != public || peer["email"] != "account|wg" || !reflect.DeepEqual(peer["allowedIPs"], []string{device.Address}) {
			t.Fatal("device peer does not retain account attribution and unique address")
		}
	}
	node := &spec.Node{Inbounds: []spec.Inbound{ib}}
	config, state, err := render(node, node.Inbounds, []spec.User{u}, renderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if (&Core{}).hotCapable(state) {
		t.Fatal("WireGuard must use full replacement, not ambiguous email hot removal")
	}
	var decoded map[string]any
	if err := json.Unmarshal(config, &decoded); err != nil {
		t.Fatal(err)
	}
	var foundLimit bool
	for _, raw := range decoded["routing"].(map[string]any)["rules"].([]any) {
		rule := raw.(map[string]any)
		if rule["outboundTag"] == spec.SpeedTag(u.ID) {
			foundLimit = reflect.DeepEqual(rule["user"], []any{"account|wg"})
		}
	}
	if !foundLimit {
		t.Fatal("all device identities must share the account's marking outbound")
	}
	u.WireGuardLegacyDisabled = true
	u.WireGuardPeers = u.WireGuardPeers[:1]
	remaining, err := wireGuardPeers(ib, []spec.User{u})
	if err != nil || len(remaining) != 1 || remaining[0]["publicKey"] != peers[1]["publicKey"] {
		t.Fatal("revocation did not leave exactly the retained device")
	}
}

func TestWireGuardDeviceDuplicatesRejected(t *testing.T) {
	ib := deviceTestInbound(t)
	u := spec.User{ID: 1, UUID: "account", WireGuardPeers: []spec.WireGuardPeer{{UUID: "phone", Address: "10.67.0.1/32"}}}
	v := spec.User{ID: 2, UUID: "other", WireGuardPeers: []spec.WireGuardPeer{{UUID: "tablet", Address: "10.67.0.1/32"}}}
	if _, err := wireGuardPeers(ib, []spec.User{u, v}); err == nil {
		t.Fatal("shared device addresses accepted")
	}
	u.WireGuardPeers = append(u.WireGuardPeers, spec.WireGuardPeer{UUID: "phone", Address: "10.67.0.2/32"})
	if _, err := wireGuardPeers(ib, []spec.User{u}); err == nil {
		t.Fatal("shared device keys accepted")
	}
}

func TestWireGuardDeviceBinaryGate(t *testing.T) {
	for output, want := range map[string]bool{
		"Xray 26.3.27 (Xray)":                     false,
		"Xray 26.6.26 (Xray)":                     false,
		"Xray 26.6.27 (Xray)":                     true,
		"Xray 26.7.28 (Xray)\nA unified platform": true,
		"unknown":             false,
		"Xray 26.6.27-custom": false,
	} {
		if got := supportsWireGuardDevices([]byte(output)); got != want {
			t.Fatalf("version gate %q = %v, want %v", output, got, want)
		}
	}
	ib := deviceTestInbound(t)
	device := spec.User{UUID: "account", WireGuardLegacyDisabled: true}
	old := &Core{}
	if _, err := old.Render(&spec.Node{}, []spec.Inbound{ib}, []spec.User{device}); err == nil {
		t.Fatal("old core accepted a device-only account")
	}
	if old.Capabilities().WireGuardDevices {
		t.Fatal("unknown binary advertised device accounting")
	}
	current := &Core{wireGuardDevices: true}
	if !current.Capabilities().WireGuardDevices {
		t.Fatal("capability detection not reported")
	}
	if _, err := current.Render(&spec.Node{}, []spec.Inbound{ib}, []spec.User{device}); err != nil {
		t.Fatal(err)
	}
	ib.ScopedUsers, ib.Users = true, []spec.User{device}
	if _, err := old.Render(&spec.Node{}, []spec.Inbound{ib}, nil); err == nil {
		t.Fatal("scoped users bypassed binary gate")
	}
	ib.Protocol, ib.Users = spec.VLESS, nil
	if _, err := old.Render(&spec.Node{}, []spec.Inbound{ib}, []spec.User{device}); err != nil {
		t.Fatal("device choice must not disable unrelated VLESS", err)
	}
}
