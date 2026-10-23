package subscription

import (
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
	"github.com/zeptop-dev/bosun/pkg/wg"
)

func TestWireGuardDeviceSelection(t *testing.T) {
	private, public, err := wg.Keypair()
	if err != nil {
		t.Fatal(err)
	}
	line := Line{UUID: "account", UserID: 1, Inbound: spec.Inbound{Protocol: spec.WireGuard, WGPrivateKey: private, WGPublicKey: public}}
	legacy, ok := WGClient(line)
	if !ok || legacy.Address != wg.ClientAddress(1) {
		t.Fatal("legacy WireGuard configuration changed")
	}
	line.WireGuardPeer = &spec.WireGuardPeer{UUID: "phone", Address: "10.67.0.1/32"}
	phone, ok := WGClient(line)
	if !ok || phone.Address != line.WireGuardPeer.Address || phone.PrivateKey == legacy.PrivateKey || phone.ServerPublicKey != legacy.ServerPublicKey {
		t.Fatal("device selection did not produce an independent identity")
	}
	expectedPrivate, expectedPublic, _ := wg.DeriveDevicePeer(private, line.UUID, line.WireGuardPeer.UUID)
	if phone.PrivateKey != expectedPrivate || phone.PublicKey != expectedPublic {
		t.Fatal("subscription and server identity derivation disagree")
	}
	line.WireGuardPeer.Address = "10.66.0.3/32"
	if _, ok := WGClient(line); ok {
		t.Fatal("invalid device selection fell back to legacy")
	}
	line.Inbound.Protocol = spec.VLESS
	if _, ok := WGClient(line); ok || line.UUID != "account" {
		t.Fatal("device choice changed a non-WireGuard credential")
	}
}
