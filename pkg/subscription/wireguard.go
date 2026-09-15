package subscription

import (
	"strconv"
	"strings"

	"github.com/zeptop-dev/bosun/pkg/spec"
	"github.com/zeptop-dev/bosun/pkg/wg"
)

// WireGuardConf renders one standard [Interface]/[Peer] config per
// WireGuard inbound (what the official apps import, also as a QR code).
// Several inbounds are concatenated with a comment naming each.
type WireGuardConf struct{}

func (WireGuardConf) Name() string        { return "wireguard" }
func (WireGuardConf) ContentType() string { return "text/plain; charset=utf-8" }

func (r WireGuardConf) RenderWith(lines []Line, acct Account, _ string) ([]byte, error) {
	return r.Render(lines, acct)
}

func (WireGuardConf) Render(lines []Line, _ Account) ([]byte, error) {
	var parts []string
	for _, l := range lines {
		if c := WGConf(l); c != "" {
			parts = append(parts, "# "+l.Name+"\n"+c)
		}
	}
	return []byte(strings.Join(parts, "\n\n")), nil
}

// WGPeer is the client side of a WireGuard line.
type WGPeer struct {
	PrivateKey, PublicKey, ServerPublicKey, Address string
	MTU                                             int
}

// WGClient derives the client credentials for a line; ok is false when the
// line is not a usable WireGuard inbound.
func WGClient(l Line) (WGPeer, bool) {
	ib := l.Inbound
	if ib.Protocol != spec.WireGuard || ib.WGPrivateKey == "" {
		return WGPeer{}, false
	}
	priv, pub, err := wg.DerivePeer(ib.WGPrivateKey, l.UUID)
	if err != nil {
		return WGPeer{}, false
	}
	srvPub := ib.WGPublicKey
	if srvPub == "" {
		srvPub, _ = wg.PublicKey(ib.WGPrivateKey)
	}
	mtu := ib.WGMTU
	if mtu <= 0 {
		mtu = wg.DefaultMTU
	}
	return WGPeer{PrivateKey: priv, PublicKey: pub, ServerPublicKey: srvPub, Address: wg.ClientAddress(l.UserID), MTU: mtu}, true
}

// WGConf is the client .conf text for a WireGuard line ("" otherwise).
func WGConf(l Line) string {
	p, ok := WGClient(l)
	if !ok {
		return ""
	}
	host := l.Host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return "[Interface]\nPrivateKey = " + p.PrivateKey + "\nAddress = " + p.Address + "\nDNS = 1.1.1.1, 2606:4700:4700::1111\nMTU = " + strconv.Itoa(p.MTU) +
		"\n\n[Peer]\nPublicKey = " + p.ServerPublicKey + "\nEndpoint = " + host + ":" + strconv.Itoa(l.Port) + "\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"
}
