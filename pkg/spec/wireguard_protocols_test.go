package spec

import "testing"

func TestWireGuardProtocolCapabilities(t *testing.T) {
	for _, c := range CoreCatalog() {
		for _, p := range c.Capabilities.Protocols {
			ib := Inbound{Core: c.Name, Protocol: p, WireGuardSlot: 1}
			got := c.Capabilities.SupportsWireGuardProtocol(p) && c.Capabilities.WireGuardReverse
			want := CoreFamily(c.Name) == "singbox" || c.Name == "xray" && (p == VLESS || p == VMess || p == Trojan || p == Shadowsocks || p == WireGuard)
			if got != want {
				t.Fatalf("%s/%s: WG capability %v", c.Name, p, got)
			}
			if c.Name == "xray" && p == WireGuard {
				old := c.Capabilities
				old.WireGuardDevices = false
				if old.UnsupportedReason(ib) != "wireguardReverse" {
					t.Fatal("old Xray accepted WG transit")
				}
			}
		}
	}
	// Published agents with only the old bool can never advertise new protocols.
	old := CoreCapabilities{WireGuardReverse: true, Protocols: []Protocol{WireGuard, Naive, SOCKS}}
	for _, p := range old.Protocols {
		if old.Supports(Inbound{Protocol: p, WireGuardSlot: 1}) {
			t.Fatal("legacy capability interpreted as new support")
		}
	}
}

func TestWireGuardSnellRequiresIndividualIdentity(t *testing.T) {
	ib := Inbound{Tag: "snell-entry", Protocol: Snell, Core: "singbox", Port: 18443, WireGuardSlot: 1}
	FillInboundSecrets(&ib)
	if CapabilitiesForCore("singbox").Supports(ib) {
		t.Fatal("shared PSK advertised as accounted WireGuard service")
	}
	if err := ib.Validate(); err == nil {
		t.Fatal("shared PSK accepted")
	}
	ib.SnellMultiUser = true
	if err := ib.Validate(); err != nil {
		t.Fatal(err)
	}
	if !CapabilitiesForCore("singbox").Supports(ib) {
		t.Fatal("multi-user Snell rejected")
	}
}
