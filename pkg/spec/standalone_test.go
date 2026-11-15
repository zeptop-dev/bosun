package spec

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestStandaloneValidationAndIsolation(t *testing.T) {
	base := Inbound{Tag: "independent", Protocol: SOCKS, Port: 1080, Standalone: &StandaloneAuth{Username: "operator", Password: "secret"}}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	base.Users = []User{{ID: 7, Name: "subscriber", Password: "subscriber-secret"}}
	base.ScopedUsers = true
	if got := base.EffectiveUsers(base.Users); len(got) != 0 {
		t.Fatal("subscriber credentials escaped into standalone inbound")
	}
	for _, auth := range []StandaloneAuth{{}, {Username: "x"}, {Username: "x", Password: "a\nb"}, {Username: strings.Repeat("x", 256), Password: "x"}, {Username: "x y", Password: "x"}} {
		ib := base
		ib.Standalone = &auth
		if ib.Validate() == nil {
			t.Fatal("invalid standalone credentials accepted")
		}
	}
	for _, protocol := range []Protocol{VLESS, HTTP, WireGuard} {
		ib := base
		ib.Protocol = protocol
		if ib.Validate() == nil {
			t.Fatal("unsupported protocol accepted", protocol)
		}
	}
	for _, cipher := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		ib := base
		ib.Protocol = Shadowsocks
		ib.Standalone = &StandaloneAuth{}
		ib.Cipher = cipher
		ib.ServerKey = base64.StdEncoding.EncodeToString(make([]byte, SS2022KeyLen(cipher)))
		if err := ib.Validate(); err != nil {
			t.Fatal(err)
		}
		ib.ServerKey = "not-a-key"
		if ib.Validate() == nil {
			t.Fatal("invalid SS2022 key accepted")
		}
	}
	caps := CapabilitiesForCore("singbox")
	caps.StandaloneAuth = false
	if caps.Supports(base) || caps.UnsupportedReason(base) != "standaloneAuth" {
		t.Fatal("old adapter accepted new mode")
	}
}
