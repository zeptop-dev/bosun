package spec

import (
	"fmt"
	"net/netip"
	"strings"
	"unicode"
)

const (
	WireGuardDevicesMinBosun = "0.77.0"
	WireGuardDevicesMinXray  = "26.6.27"
	MaxWireGuardPeers        = 64
)

// WireGuardPeer is a registered device belonging to one User. UUID is a
// stable, opaque derivation identity; Address is allocated by the panel from
// a separate pool so devices never collide with legacy per-user addresses.
type WireGuardPeer struct {
	UUID    string `json:"uuid"`
	Address string `json:"address"`
}

func (p WireGuardPeer) Validate() error {
	if p.UUID == "" || len(p.UUID) > 128 || strings.ContainsFunc(p.UUID, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return fmt.Errorf("invalid WireGuard device identity")
	}
	prefix, err := netip.ParsePrefix(p.Address)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 || prefix.String() != p.Address {
		return fmt.Errorf("WireGuard device address must be a canonical IPv4 /32")
	}
	a := prefix.Addr().As4()
	if a[0] != 10 || a[1] != 67 || (a[2] == 0 && a[3] == 0) || (a[2] == 255 && a[3] == 255) {
		return fmt.Errorf("WireGuard device address must be allocated from 10.67.0.1-10.67.255.254")
	}
	return nil
}

// HasWireGuardDevices includes an empty device-only account: old runtimes
// must not silently restore its withdrawn legacy identity.
func (u User) HasWireGuardDevices() bool {
	return len(u.WireGuardPeers) > 0 || u.WireGuardLegacyDisabled
}
