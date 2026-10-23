package spec

import "testing"

func TestWireGuardDeviceValidation(t *testing.T) {
	for _, address := range []string{"10.67.0.1/32", "10.67.1.0/32", "10.67.255.254/32"} {
		if err := (WireGuardPeer{UUID: "device", Address: address}).Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, peer := range []WireGuardPeer{
		{UUID: "", Address: "10.67.0.1/32"},
		{UUID: "device\n", Address: "10.67.0.1/32"},
		{UUID: "device", Address: "10.67.0.0/32"},
		{UUID: "device", Address: "10.67.255.255/32"},
		{UUID: "device", Address: "10.66.0.3/32"},
		{UUID: "device", Address: "10.67.0.1/24"},
		{UUID: "device", Address: "::ffff:10.67.0.1/128"},
	} {
		if peer.Validate() == nil {
			t.Fatal("invalid device peer accepted")
		}
	}
	if !(User{WireGuardLegacyDisabled: true}).HasWireGuardDevices() || (User{}).HasWireGuardDevices() {
		t.Fatal("device capability requirement lost for empty device-only account")
	}
}
