package subscription

import (
	"errors"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func surgeVLESSFixture(transport string, security spec.TLSMode, flow string) Line {
	l := Line{Name: "VLESS", Host: "192.0.2.10", Port: 443, UUID: "2cae91b3-f85c-433b-88ee-a002b9ed6d61", Inbound: spec.Inbound{Protocol: spec.VLESS, Flow: flow, Transport: &spec.Transport{Type: transport, Path: "/vless", Host: "cdn.example.com", ServiceName: "mygrpc"}, TLS: &spec.TLS{Mode: security, ServerName: "example.com"}}}
	if security == spec.TLSReality {
		l.Inbound.TLS.Reality = &spec.Reality{PublicKey: "dwrjY6KiAMPxKdlF7T4AWFXXBtsxeHCXtBQYeCOdZV4", ShortIDs: []string{"0123456789abcdef"}, PrivateKey: "must-not-leak"}
	}
	return l
}
func TestSurgeVLESSCombinations(t *testing.T) {
	for _, transport := range []string{"tcp", "ws", "grpc", "xhttp", "httpupgrade", "http", "mkcp"} {
		for _, security := range []spec.TLSMode{spec.TLSNone, spec.TLSStandard, spec.TLSReality} {
			for _, flow := range []string{"", "xtls-rprx-vision", "xtls-rprx-vision-udp443", "unknown"} {
				l := surgeVLESSFixture(transport, security, flow)
				supported := transport == "tcp" || transport == "ws" && security != spec.TLSReality || transport == "grpc" && security != spec.TLSNone
				supported = supported && (flow == "" || transport == "tcp" && security != spec.TLSNone && flow != "unknown")
				s := surgeVLESSLine(l)
				if (s != "") != supported {
					t.Fatalf("%s/%d/%s: %q", transport, security, flow, s)
				}
				if s == "" {
					continue
				}
				for _, v := range []string{"username=" + l.UUID, "sni=example.com"} {
					if security == spec.TLSNone && strings.HasPrefix(v, "sni=") {
						continue
					}
					if !strings.Contains(s, v) {
						t.Fatalf("missing %s: %s", v, s)
					}
				}
				if strings.Contains(s, "must-not-leak") {
					t.Fatal("private key leaked")
				}
				if transport == "ws" && !strings.Contains(s, "ws-headers=Host:cdn.example.com") {
					t.Fatal(s)
				}
				if transport == "grpc" && !strings.Contains(s, "grpc-service-name=mygrpc") {
					t.Fatal(s)
				}
				if security == spec.TLSReality && (!strings.Contains(s, "reality-public-key=") || !strings.Contains(s, "reality-short-id=0123456789abcdef")) {
					t.Fatal(s)
				}
			}
		}
	}
}
func TestSurgeVLESSAdmission(t *testing.T) {
	for _, mutate := range []func(*Line){
		func(l *Line) { l.Inbound.TLS.Reality = nil },
		func(l *Line) { l.Inbound.TLS.Reality.PublicKey = "invalid" },
		func(l *Line) { l.Inbound.TLS.Reality.PublicKey += "\n" },
		func(l *Line) { l.Inbound.TLS.Reality.ShortIDs = []string{"xxx"} },
		func(l *Line) { l.Inbound.TLS.ServerName = "" },
		func(l *Line) { l.UUID = "id, tls=false" },
		func(l *Line) { l.Host = "example.com\n[Rule]" },
		func(l *Line) { l.Inbound.TLS.ServerName = "example.com; bad" },
	} {
		l := surgeVLESSFixture("tcp", spec.TLSReality, "xtls-rprx-vision")
		mutate(&l)
		if s := surgeVLESSLine(l); s != "" {
			t.Fatal(s)
		}
	}
}
func TestSurgeVLESSSelectionAndLegacy(t *testing.T) {
	l := surgeVLESSFixture("tcp", spec.TLSReality, "xtls-rprx-vision")
	for _, tc := range []struct {
		client, ua string
		want       bool
	}{
		{"surge", "", false}, {"", "Surge/5.8", false}, {"surge", "Surge Mac/6.11.0", false},
		{"", "Surge Mac/6.12.0", true}, {"", "Surge/6.0.0 (iPhone; iOS)", true},
		{"surge", "Surge/6.0", false}, {"surge", "Surge/6.12.0", true},
		{"surge-vless", "", true}, {"surge-vless", "Mozilla/5.0", true},
		{"surge-legacy", "Surge Mac/6.12.0", false},
		{"surge", "Surge/6120 CFNetwork/1 Darwin/1", false},
	} {
		r := Pick(tc.client, tc.ua)
		out, err := r.Render([]Line{l}, Account{})
		if err != nil || strings.Contains(string(out), "= vless,") != tc.want {
			t.Fatalf("%+v: %s %v", tc, out, err)
		}
		if r.Name() != "surge" {
			t.Fatal(r.Name())
		}
	}
	old, _ := (Surge{}).Render(append(sample(), l), Account{})
	next, _ := (Surge{VLESS: true}).Render(append(sample(), l), Account{})
	if !strings.Contains(string(next), "= vless,") || strings.Contains(string(old), "= vless,") {
		t.Fatal("wrong version outputs")
	}
}
func TestSurgeVLESSDNSAndIPPolicy(t *testing.T) {
	l := surgeVLESSFixture("tcp", spec.TLSStandard, "")
	l.Host = "example.com"
	l.IPVersion = "ipv6"
	tpl := "# captain-dns-protection: surge-ip-only\n[Proxy]\n{{proxies}}\n"
	if _, err := (Surge{VLESS: true}).RenderWith([]Line{l}, Account{}, tpl); !errors.Is(err, ErrSurgeDNSHostname) {
		t.Fatal(err)
	}
	if _, err := (Surge{VLESS: true}).RenderWith([]Line{l}, Account{}, "[General]\nipv6=false\n[Proxy]\n{{proxies}}"); !errors.Is(err, ErrIPVersionTemplateConflict) {
		t.Fatal(err)
	}
	l.Host = "2001:db8::1"
	out, err := (Surge{VLESS: true}).RenderWith([]Line{l}, Account{}, tpl)
	if err != nil || !strings.Contains(string(out), "ip-version=v6-only") {
		t.Fatalf("%s %v", out, err)
	}
	l.Inbound.Transport.Type = "xhttp"
	l.Name = "omitted"
	out, err = (Surge{VLESS: true}).RenderWith([]Line{l}, Account{}, "[Proxy]\n{{proxies}}\n[Proxy Group]\nALL = select, {{proxy_names}}")
	if err != nil || strings.Contains(string(out), "omitted") {
		t.Fatalf("%s %v", out, err)
	}
}
func TestSurgeVLESSRealParser(t *testing.T) {
	cli := os.Getenv("SURGE_CLI")
	if cli == "" {
		t.Skip("set SURGE_CLI for installed Surge 6.12+ offline validation")
	}
	for _, tc := range []struct {
		tr   string
		sec  spec.TLSMode
		flow string
	}{
		{"tcp", spec.TLSNone, ""}, {"tcp", spec.TLSStandard, "xtls-rprx-vision"}, {"tcp", spec.TLSReality, "xtls-rprx-vision"},
		{"ws", spec.TLSNone, ""}, {"ws", spec.TLSStandard, ""}, {"grpc", spec.TLSStandard, ""}, {"grpc", spec.TLSReality, ""},
	} {
		l := surgeVLESSFixture(tc.tr, tc.sec, tc.flow)
		if tc.sec == spec.TLSStandard {
			l.Inbound.TLS.ALPN = []string{"h2", "http/1.1"}
		}
		out, err := (Surge{VLESS: true}).Render([]Line{l}, Account{})
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "surge.conf")
		if err = os.WriteFile(p, out, 0600); err != nil {
			t.Fatal(err)
		}
		result, err := exec.Command(cli, "--check", p).CombinedOutput()
		if err != nil {
			t.Fatalf("%+v: %s %v\n%s", tc, result, err, out)
		}
	}
}
