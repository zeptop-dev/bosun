package subscription

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func shadowTLSLine() Line {
	return Line{
		Name: "HK ShadowTLS", Host: "hk1.example.com", Port: 443,
		UUID: "11111111-2222-3333-4444-555555555555", UserID: 7,
		Inbound: spec.Inbound{
			Tag: "st", Protocol: spec.Shadowsocks, Port: 443,
			Cipher:    "2022-blake3-aes-128-gcm",
			ServerKey: "8JCsPssfgS8tiRwiMlhARg==",
			ShadowTLS: &spec.ShadowTLS{Handshake: "www.apple.com:443", StrictMode: true},
		},
	}
}

// Every client that can express ShadowTLS gets it, in its own dialect, and
// always with the version spelled out: mihomo, Stash and the URI readers
// all default to version 2 when it is missing.
func TestShadowTLSRendersPerClient(t *testing.T) {
	l := shadowTLSLine()
	pw := spec.ShadowTLSUserKey(l.UUID)

	p := clashProxy(l)
	if p["plugin"] != "shadow-tls" {
		t.Fatalf("mihomo: plugin = %v", p["plugin"])
	}
	opts, _ := p["plugin-opts"].(map[string]any)
	if opts["host"] != "www.apple.com" || opts["password"] != pw || opts["version"] != 3 {
		t.Fatalf("mihomo plugin-opts = %v", opts)
	}
	if p["client-fingerprint"] != "chrome" {
		t.Fatalf("mihomo: no client fingerprint: %v", p)
	}

	// Stash keeps the plugin but not mihomo's own keys.
	st := stashProxy(clashProxy(l))
	if st["plugin"] != "shadow-tls" {
		t.Fatalf("stash lost the plugin: %v", st)
	}
	if _, ok := st["client-fingerprint"]; ok {
		t.Fatalf("stash kept a mihomo-only key: %v", st)
	}

	// sing-box: a carrier outbound the protocol outbound dials through.
	doc, err := (SingBox{}).Render([]Line{l}, Account{})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(doc, &cfg); err != nil {
		t.Fatal(err)
	}
	var carrier, proxy map[string]any
	for _, o := range cfg.Outbounds {
		switch o["type"] {
		case "shadowtls":
			carrier = o
		case "shadowsocks":
			proxy = o
		}
	}
	if carrier == nil || proxy == nil {
		t.Fatalf("sing-box: want a shadowtls and a shadowsocks outbound, got %d outbounds", len(cfg.Outbounds))
	}
	if carrier["password"] != pw || carrier["version"].(float64) != 3 {
		t.Fatalf("sing-box carrier = %v", carrier)
	}
	if tls, _ := carrier["tls"].(map[string]any); tls == nil || tls["enabled"] != true || tls["server_name"] != "www.apple.com" {
		t.Fatalf("sing-box carrier tls = %v", carrier["tls"])
	}
	if proxy["detour"] != carrier["tag"] {
		t.Fatalf("the protocol outbound does not dial through the carrier: %v", proxy)
	}
	if _, ok := proxy["server"]; ok {
		t.Fatalf("the protocol outbound must not carry an address of its own: %v", proxy)
	}

	// URI: the plugin form every converter reads.
	uri := ShareURI(l)
	if !strings.Contains(uri, "plugin=") || !strings.Contains(uri, "shadow-tls") || !strings.Contains(uri, "version%3D3") {
		t.Fatalf("uri = %s", uri)
	}
}

// A plain Shadowsocks line is untouched by any of it.
func TestWithoutShadowTLSNothingChanges(t *testing.T) {
	l := shadowTLSLine()
	l.Inbound.ShadowTLS = nil
	if p := clashProxy(l); p["plugin"] != nil {
		t.Fatalf("plain ss grew a plugin: %v", p)
	}
	if uri := ShareURI(l); strings.Contains(uri, "plugin") {
		t.Fatalf("plain ss uri = %s", uri)
	}
	doc, err := (SingBox{}).Render([]Line{l}, Account{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(doc), "shadowtls") {
		t.Fatal("plain ss produced a shadowtls outbound")
	}
}

// The user's ShadowTLS password is derived, stable, and not the same as
// any other credential the line carries.
func TestShadowTLSUserKeyIsStableAndDistinct(t *testing.T) {
	const uuid = "11111111-2222-3333-4444-555555555555"
	a, b := spec.ShadowTLSUserKey(uuid), spec.ShadowTLSUserKey(uuid)
	if a != b || a == "" {
		t.Fatalf("not stable: %q %q", a, b)
	}
	if spec.ShadowTLSUserKey("other") == a {
		t.Fatal("two users share a password")
	}
	l := shadowTLSLine()
	if a == ssPassword(l) || a == l.Password || a == l.UUID {
		t.Fatalf("the ShadowTLS password repeats another credential: %q", a)
	}
}
