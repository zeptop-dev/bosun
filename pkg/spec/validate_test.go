package spec

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	key16 := "P8D/iYe+7z4GrhKl4KDREw=="
	key32 := "oBeM+TwKAddRJt86siaES4T0I8mAGkJ+oyl6U56kHFI="
	reality := &TLS{Mode: TLSReality, ServerName: "www.example.com", Reality: &Reality{PrivateKey: "eMOxHOtsfcgzZwW4FWawJW5SOOg7nQ3Ygk7DnSkJ92o", ShortIDs: []string{"0123abcd"}, HandshakeServer: "www.example.com", HandshakePort: 443}}
	std := &TLS{Mode: TLSStandard, ServerName: "node.example.com", AutoCert: true, ACME: "dns"}
	cases := []struct {
		name string
		in   Inbound
		want string // "" = valid, else a substring of the error
	}{
		{"vless reality", Inbound{Tag: "a", Protocol: VLESS, Port: 443, Flow: "xtls-rprx-vision", TLS: reality}, ""},
		{"ss2022 ok", Inbound{Tag: "a", Protocol: Shadowsocks, Port: 1, Cipher: "2022-blake3-aes-128-gcm", ServerKey: key16}, ""},
		{"ss2022 wrong length", Inbound{Tag: "a", Protocol: Shadowsocks, Port: 1, Cipher: "2022-blake3-aes-128-gcm", ServerKey: key32}, "16-byte"},
		{"ss2022 no key", Inbound{Tag: "a", Protocol: Shadowsocks, Port: 1, Cipher: "2022-blake3-aes-256-gcm"}, "server key"},
		{"ss classic", Inbound{Tag: "a", Protocol: Shadowsocks, Port: 1, Cipher: "aes-128-gcm"}, ""},
		{"ss no cipher", Inbound{Tag: "a", Protocol: Shadowsocks, Port: 1}, "cipher"},
		{"hy2 no tls", Inbound{Tag: "a", Protocol: Hysteria2, Port: 1}, "standard TLS"},
		{"hy2 ok", Inbound{Tag: "a", Protocol: Hysteria2, Port: 1, TLS: std, Obfs: "salamander", ObfsPassword: "x"}, ""},
		{"hy2 obfs no password", Inbound{Tag: "a", Protocol: Hysteria2, Port: 1, TLS: std, Obfs: "salamander"}, "password"},
		{"tuic reality", Inbound{Tag: "a", Protocol: TUIC, Port: 1, TLS: reality}, "REALITY needs VLESS or Trojan"},
		{"reality no short id", Inbound{Tag: "a", Protocol: VLESS, Port: 1, TLS: &TLS{Mode: TLSReality, Reality: &Reality{PrivateKey: reality.Reality.PrivateKey, HandshakeServer: "x"}}}, "short id"},
		{"reality bad key", Inbound{Tag: "a", Protocol: VLESS, Port: 1, TLS: &TLS{Mode: TLSReality, Reality: &Reality{PrivateKey: "nope", HandshakeServer: "x", ShortIDs: []string{"ab"}}}}, "private key"},
		{"mieru both", Inbound{Tag: "a", Protocol: Mieru, Port: 65535, MieruTransport: "BOTH"}, "port+1"},
		{"mieru bad transport", Inbound{Tag: "a", Protocol: Mieru, Port: 1, MieruTransport: "QUIC"}, "TCP, UDP or BOTH"},
		{"snell no psk", Inbound{Tag: "a", Protocol: Snell, Port: 1}, "psk"},
		{"wg ok", Inbound{Tag: "a", Protocol: WireGuard, Port: 1, WGPrivateKey: key32, WGAddress: "10.66.0.1/16"}, ""},
		{"wg bad address", Inbound{Tag: "a", Protocol: WireGuard, Port: 1, WGPrivateKey: key32, WGAddress: "10.66.0.1"}, "CIDR"},
		{"bad tag", Inbound{Tag: "a b", Protocol: SOCKS, Port: 1}, "tag"},
		{"bad port", Inbound{Tag: "a", Protocol: SOCKS, Port: 0}, "port"},
		{"bad listen", Inbound{Tag: "a", Protocol: SOCKS, Port: 1, Listen: "node"}, "listen"},
		{"ws on ss", Inbound{Tag: "a", Protocol: Shadowsocks, Port: 1, Cipher: "aes-128-gcm", Transport: &Transport{Type: "ws"}}, "does not take"},
		{"unknown transport", Inbound{Tag: "a", Protocol: VLESS, Port: 1, Transport: &Transport{Type: "kcp"}}, "transport must be"},
		{"fallback needs tls", Inbound{Tag: "a", Protocol: Trojan, Port: 1, Fallbacks: []Fallback{{Dest: "80"}}}, "fallbacks need TCP with standard TLS"},
		{"fallback ok", Inbound{Tag: "a", Protocol: Trojan, Port: 1, TLS: std, Fallbacks: []Fallback{{Dest: "80"}}}, ""},
		{"no protocol", Inbound{Tag: "a", Port: 1}, "protocol is required"},
		{"unknown protocol", Inbound{Tag: "a", Protocol: "quic", Port: 1}, "unknown protocol"},
	}
	for _, c := range cases {
		err := c.in.Validate()
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: unexpected error %v", c.name, err)
		case c.want != "" && err == nil:
			t.Errorf("%s: expected error containing %q", c.name, c.want)
		case c.want != "" && !strings.Contains(err.Error(), c.want):
			t.Errorf("%s: error %q does not mention %q", c.name, err, c.want)
		}
	}
}

func TestInboundUser(t *testing.T) {
	if got := InboundUser("u", "in"); got != "u|in" {
		t.Fatalf("got %q", got)
	}
	if got := InboundUser("u", ""); got != "u" {
		t.Fatalf("got %q", got)
	}
	for _, c := range []struct{ in, name, tag string }{{"u|in", "u", "in"}, {"u", "u", ""}, {"a|b|c", "a|b", "c"}} {
		n, tag := SplitInboundUser(c.in)
		if n != c.name || tag != c.tag {
			t.Fatalf("%q -> %q %q", c.in, n, tag)
		}
	}
}
