package spec

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Validate checks that an inbound is complete enough for some core to
// serve it: the shape every panel and the agent agree on, before any
// core-specific rendering. It says what is missing in operator terms so
// the panel can show it on the form and the agent in the doctor. Fields a
// core fills later (certificate paths for auto_cert) are not required.
func (i Inbound) Validate() error {
	if !ValidTag(i.Tag) {
		return fmt.Errorf("tag may only contain letters, digits, . _ : - (max 64)")
	}
	if !ValidListen(i.Listen) {
		return fmt.Errorf("listen must be an IP address")
	}
	if i.Port <= 0 || i.Port > 65535 {
		return fmt.Errorf("port must be 1-65535")
	}
	switch i.TransportType() {
	case "tcp", "ws", "grpc", "httpupgrade", "http", "xhttp":
	default:
		return fmt.Errorf("transport must be tcp, ws, grpc, httpupgrade, http or xhttp")
	}
	if i.Transport != nil && i.TransportType() != "tcp" && !transportProtocol(i.Protocol) {
		return fmt.Errorf("%s does not take a %s transport", i.Protocol, i.TransportType())
	}
	plain := []string{i.SnellObfsHost, i.Cipher, i.Flow, i.Obfs, i.Core}
	if i.Transport != nil {
		plain = append(plain, i.Transport.Host, i.Transport.Path, i.Transport.ServiceName, i.Transport.Mode)
	}
	if i.TLS != nil {
		plain = append(plain, i.TLS.ServerName)
		if i.TLS.Reality != nil {
			plain = append(plain, i.TLS.Reality.HandshakeServer)
		}
	}
	for _, v := range plain {
		if !Plain(v) {
			return fmt.Errorf("fields may not contain control characters")
		}
	}
	if err := i.validateTLS(); err != nil {
		return err
	}
	if i.AcceptProxyProtocol && i.Core != "" && i.Core != "xray" {
		return fmt.Errorf("accept_proxy_protocol is served by xray only")
	}
	switch i.Protocol {
	case VLESS, VMess, Trojan, HTTP, SOCKS:
	case Shadowsocks:
		if strings.TrimSpace(i.Cipher) == "" {
			return fmt.Errorf("shadowsocks needs a cipher")
		}
		if n := SS2022KeyLen(i.Cipher); n > 0 {
			raw, err := base64.StdEncoding.DecodeString(i.ServerKey)
			if err != nil || len(raw) != n {
				return fmt.Errorf("%s needs a %d-byte base64 server key", i.Cipher, n)
			}
		}
	case Hysteria2, TUIC, AnyTLS, Naive:
		if i.TLS == nil || i.TLS.Mode != TLSStandard {
			return fmt.Errorf("%s needs standard TLS (certificate)", i.Protocol)
		}
		if i.Protocol == Hysteria2 && i.Obfs != "" && i.Obfs != "salamander" {
			return fmt.Errorf("hysteria2 obfs must be empty or salamander")
		}
		if i.Protocol == Hysteria2 && i.Obfs == "salamander" && i.ObfsPassword == "" {
			return fmt.Errorf("hysteria2 salamander obfs needs a password")
		}
	case Mieru:
		switch strings.ToUpper(i.MieruTransport) {
		case "", "TCP", "UDP":
		case "BOTH":
			if i.Port+1 > 65535 {
				return fmt.Errorf("mieru BOTH needs port+1 to be valid")
			}
		default:
			return fmt.Errorf("mieru transport must be TCP, UDP or BOTH")
		}
		if i.MieruMTU != 0 && (i.MieruMTU < 1280 || i.MieruMTU > 1500) {
			return fmt.Errorf("mieru mtu must be 1280-1500")
		}
	case Snell:
		if strings.TrimSpace(i.SnellPSK) == "" {
			return fmt.Errorf("snell needs a psk")
		}
		if strings.ContainsAny(i.SnellPSK, "\r\n") {
			return fmt.Errorf("snell psk may not contain line breaks")
		}
		if i.SnellVersion != 0 && i.SnellVersion != 4 && i.SnellVersion != 5 {
			return fmt.Errorf("snell version must be 4 or 5")
		}
		if i.SnellObfs != "" && i.SnellObfs != "http" && i.SnellObfs != "tls" {
			return fmt.Errorf("snell obfs must be off, http or tls")
		}
	case WireGuard:
		if raw, err := base64.StdEncoding.DecodeString(i.WGPrivateKey); err != nil || len(raw) != 32 {
			return fmt.Errorf("wireguard needs a 32-byte base64 private key")
		}
		if i.WGAddress != "" {
			if _, _, err := net.ParseCIDR(i.WGAddress); err != nil {
				return fmt.Errorf("wireguard address must be a CIDR like 10.66.0.1/16")
			}
		}
		if i.WGMTU != 0 && (i.WGMTU < 1280 || i.WGMTU > 1500) {
			return fmt.Errorf("wireguard mtu must be 1280-1500")
		}
	case "":
		return fmt.Errorf("protocol is required")
	default:
		return fmt.Errorf("unknown protocol %q", i.Protocol)
	}
	for _, f := range i.Fallbacks {
		if i.Protocol != VLESS && i.Protocol != Trojan {
			return fmt.Errorf("fallbacks need VLESS or Trojan")
		}
		if i.TransportType() != "tcp" || i.TLS == nil || i.TLS.Mode != TLSStandard {
			return fmt.Errorf("fallbacks need TCP with standard TLS")
		}
		if strings.TrimSpace(f.Dest) == "" {
			return fmt.Errorf("fallback dest is required")
		}
	}
	return nil
}

func (i Inbound) validateTLS() error {
	t := i.TLS
	if t == nil || t.Mode == TLSNone {
		return nil
	}
	switch t.Mode {
	case TLSStandard:
		if t.AutoCert && strings.TrimSpace(t.ServerName) == "" {
			return fmt.Errorf("auto_cert needs a server name")
		}
		if t.AutoCert && t.ACME != "" && t.ACME != "http" && t.ACME != "dns" {
			return fmt.Errorf("acme must be http or dns")
		}
	case TLSReality:
		if i.Protocol != VLESS && i.Protocol != Trojan {
			return fmt.Errorf("REALITY needs VLESS or Trojan")
		}
		r := t.Reality
		if r == nil {
			return fmt.Errorf("REALITY settings are missing")
		}
		if raw, err := base64.RawURLEncoding.DecodeString(r.PrivateKey); err != nil || len(raw) != 32 {
			return fmt.Errorf("REALITY needs a 32-byte base64url private key")
		}
		if strings.TrimSpace(r.HandshakeServer) == "" {
			return fmt.Errorf("REALITY needs a handshake server (dest)")
		}
		if r.HandshakePort < 0 || r.HandshakePort > 65535 {
			return fmt.Errorf("REALITY handshake port must be 0-65535")
		}
		if len(r.ShortIDs) == 0 {
			return fmt.Errorf("REALITY needs at least one short id")
		}
		for _, s := range r.ShortIDs {
			if len(s) > 16 || len(s)%2 != 0 {
				return fmt.Errorf("REALITY short id must be 2-16 hex characters")
			}
			if _, err := hex.DecodeString(s); err != nil {
				return fmt.Errorf("REALITY short id must be hex")
			}
		}
	default:
		return fmt.Errorf("unknown tls mode %d", t.Mode)
	}
	return nil
}

// transportProtocol reports whether the protocol carries a stream transport.
func transportProtocol(p Protocol) bool {
	switch p {
	case VLESS, VMess, Trojan:
		return true
	}
	return false
}

// SS2022KeyLen is the PSK length a Shadowsocks 2022 cipher needs; 0 for
// the classic AEAD ciphers, which take any password.
func SS2022KeyLen(cipher string) int {
	switch strings.ToLower(strings.TrimSpace(cipher)) {
	case "2022-blake3-aes-128-gcm":
		return 16
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return 32
	}
	return 0
}
