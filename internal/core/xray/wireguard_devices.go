package xray

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
	"github.com/zeptop-dev/bosun/pkg/wg"
)

var xrayVersionPattern = regexp.MustCompile(`(?m)^Xray ([0-9]+)\.([0-9]+)\.([0-9]+)(?:[[:space:]]|$)`)

// v26.6.27 first attached a MemoryUser to WG source addresses. Earlier
// versions silently ignore peers.email, so accepting a device configuration
// there would provide connectivity without its promised accounting/limits.
func supportsWireGuardDevices(versionOutput []byte) bool {
	m := xrayVersionPattern.FindSubmatch(versionOutput)
	if m == nil {
		return false
	}
	minimum := [3]int{26, 6, 27}
	for i := range minimum {
		n, err := strconv.Atoi(string(m[i+1]))
		if err != nil {
			return false
		}
		if n != minimum[i] {
			return n > minimum[i]
		}
	}
	return true
}

func detectWireGuardDevices(binary string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binary, "version").Output()
	return err == nil && supportsWireGuardDevices(out)
}

func needsWireGuardDevices(inbounds []spec.Inbound, users []spec.User) bool {
	for _, ib := range inbounds {
		if ib.Protocol != spec.WireGuard {
			continue
		}
		for _, user := range ib.EffectiveUsers(users) {
			if user.HasWireGuardDevices() {
				return true
			}
		}
	}
	return false
}

func wireGuardPeers(ib spec.Inbound, users []spec.User) ([]m, error) {
	peers := []m{}
	keys, addresses := map[string]bool{}, map[string]bool{}
	add := func(pub, address, name string) error {
		if keys[pub] || addresses[address] {
			return fmt.Errorf("xray: inbound %q: duplicate WireGuard peer key or address", ib.Tag)
		}
		keys[pub], addresses[address] = true, true
		// Multiple keys intentionally share one account's inbound-scoped email.
		// Xray stores users by public key and chooses them by source address;
		// its stats and our marking rules then aggregate every device together.
		peers = append(peers, m{"publicKey": pub, "allowedIPs": []string{address}, "email": spec.InboundUser(name, ib.Tag)})
		return nil
	}
	for _, user := range users {
		if len(user.WireGuardPeers) > spec.MaxWireGuardPeers {
			return nil, fmt.Errorf("xray: inbound %q: too many WireGuard devices for a user", ib.Tag)
		}
		if !user.WireGuardLegacyDisabled {
			_, pub, err := wg.DerivePeer(ib.WGPrivateKey, user.UUID)
			if err != nil {
				return nil, fmt.Errorf("xray: inbound %q: invalid WireGuard server key", ib.Tag)
			}
			if err := add(pub, wg.ClientAddress(user.ID), user.Name); err != nil {
				return nil, err
			}
		}
		for _, device := range user.WireGuardPeers {
			if err := device.Validate(); err != nil {
				return nil, fmt.Errorf("xray: inbound %q: %w", ib.Tag, err)
			}
			_, pub, err := wg.DeriveDevicePeer(ib.WGPrivateKey, user.UUID, device.UUID)
			if err != nil {
				return nil, fmt.Errorf("xray: inbound %q: invalid WireGuard device credentials", ib.Tag)
			}
			if err := add(pub, device.Address, user.Name); err != nil {
				return nil, err
			}
		}
	}
	return peers, nil
}
