package spec

import (
	"fmt"
	"strings"
)

// StandaloneAuth is deliberately separate from User: it has no customer ID,
// quota or subscription. Shadowsocks 2022 uses Inbound.ServerKey instead.
type StandaloneAuth struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

func (i Inbound) validateStandalone() error {
	if i.Standalone == nil {
		return nil
	}
	if i.Reverse != nil || i.WireGuardSlot != 0 || i.ShadowTLS != nil || i.PrivateAccess.Enabled() {
		return fmt.Errorf("standalone listeners cannot use managed reverse, ShadowTLS or per-user private access")
	}
	switch i.Protocol {
	case SOCKS:
		a := i.Standalone
		if len(a.Username) == 0 || len(a.Username) > 255 || len(a.Password) == 0 || len(a.Password) > 255 || !Plain(a.Username) || !Plain(a.Password) || strings.ContainsAny(a.Username+a.Password, " \"'") {
			return fmt.Errorf("standalone SOCKS requires a username and password of 1-255 bytes without whitespace, quotes or control characters")
		}
	case Shadowsocks:
		if SS2022KeyLen(i.Cipher) == 0 {
			return fmt.Errorf("standalone Shadowsocks requires a 2022 cipher")
		}
		if i.Standalone.Username != "" || i.Standalone.Password != "" {
			return fmt.Errorf("standalone Shadowsocks uses only its server key")
		}
	default:
		return fmt.Errorf("standalone credentials support only SOCKS5 and Shadowsocks 2022")
	}
	return nil
}
