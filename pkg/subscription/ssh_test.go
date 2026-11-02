package subscription

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
	"gopkg.in/yaml.v3"
)

func TestSSHSubscriptionPinsHostAndNeverLeaksPrivateKey(t *testing.T) {
	ib := spec.Inbound{Tag: "ssh", Protocol: spec.SSH, Port: 2222}
	spec.FillInboundSecrets(&ib)
	l := Line{Name: "SSH", Host: "example.com", Port: 2222, Inbound: ib, UUID: "identity", Password: "password"}
	o := singboxOutbound(l)
	if o["user"] != spec.ProxyUsername(l.UUID, ib.Tag) || o["type"] != "ssh" {
		t.Fatal(o)
	}
	raw, _ := json.Marshal(o)
	if !strings.Contains(string(raw), ib.SSH.PublicKey) || strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("host key pin missing or private key exposed")
	}
	p := clashProxy(l)
	if p == nil || p["type"] != "ssh" || p["username"] != spec.ProxyUsername(l.UUID, ib.Tag) || p["password"] != l.Password || p["udp"] != false {
		t.Fatal("mihomo SSH credentials or TCP-only transport missing")
	}
	raw, _ = json.Marshal(p)
	if !strings.Contains(string(raw), ib.SSH.PublicKey) || strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("mihomo host key pin missing or private key exposed")
	}
	ib.Protocol = spec.Mieru
	ib.Core = "singbox-extended"
	l.Inbound = ib
	if got := clashProxy(l)["username"]; got != spec.ProxyUsername(l.UUID, ib.Tag) {
		t.Fatal(got)
	}
	ib.Core = "mita"
	l.Inbound = ib
	if got := clashProxy(l)["username"]; got != l.UUID {
		t.Fatal("existing mita credentials changed")
	}
}

func TestSSHSubscriptionClientFormats(t *testing.T) {
	ib := spec.Inbound{Tag: "ssh-proxy", Protocol: spec.SSH, Port: 2222}
	if err := ib.EnsureSSHKey(); err != nil {
		t.Fatal(err)
	}
	line := Line{Name: "SSH proxy", Host: "ssh.example.com", Port: 2222, Inbound: ib, UUID: "identity", Password: "password:with#characters"}
	ordinary := Line{Name: "ordinary", Host: "example.com", Port: 443, Inbound: spec.Inbound{Protocol: spec.Trojan}, Password: "password"}
	for _, renderer := range []Renderer{Clash{}, Stash{}} {
		t.Run(renderer.Name(), func(t *testing.T) {
			body, err := renderer.Render([]Line{line, ordinary}, Account{})
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Proxies []map[string]any `yaml:"proxies"`
				Groups  []struct {
					Proxies []string `yaml:"proxies"`
				} `yaml:"proxy-groups"`
			}
			if err := yaml.Unmarshal(body, &doc); err != nil {
				t.Fatal(err)
			}
			want := renderer.Name() == "clash"
			found := false
			for _, proxy := range doc.Proxies {
				if proxy["name"] != line.Name {
					continue
				}
				found = true
				pins, ok := proxy["host-key"].([]any)
				if !ok || len(pins) != 1 || pins[0] != ib.SSH.PublicKey || proxy["username"] != "identity|ssh-proxy" || proxy["password"] != line.Password || proxy["udp"] != false {
					t.Fatal("SSH subscription lost its credentials, host pin or TCP-only flag")
				}
			}
			if found != want {
				t.Fatalf("SSH presence = %v, want %v", found, want)
			}
			for _, group := range doc.Groups {
				if strings.Contains(strings.Join(group.Proxies, "\n"), line.Name) != want {
					t.Fatal("proxy group has a missing or dangling SSH reference")
				}
			}
			if strings.Contains(string(body), "PRIVATE KEY") {
				t.Fatal("subscription leaked the server private key")
			}
		})
	}
	if ShareURI(line) != "" {
		t.Fatal("generic URI must not silently discard the SSH host pin")
	}
	for _, missing := range []*spec.SSHServer{nil, {}} {
		line.Inbound.SSH = missing
		if clashProxy(line) != nil || singboxOutbound(line) != nil {
			t.Fatal("SSH without a host key must not be published")
		}
	}
}

func TestNekoBoxExplicitSSHFormatPreservesDefaultNegotiation(t *testing.T) {
	android := "NekoBox/Android/1.4.2 (Prefer ClashMeta Format)"
	pc := "NekoBox/PC/4.0.1 (Prefer ClashMeta Format)"
	for _, ua := range []string{android, pc, "clash-verge/v2.5.8"} {
		if got := Pick("", ua).Name(); got != "clash" {
			t.Fatalf("existing default changed for %q: %s", ua, got)
		}
	}
	for _, client := range []string{"nb4a", "nekobox-android", "singbox", "sing-box"} {
		if got := Pick(client, android).Name(); got != "singbox" {
			t.Fatalf("explicit %s did not select sing-box: %s", client, got)
		}
	}
}
