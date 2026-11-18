package subscription

import (
	"encoding/base64"
	"encoding/json"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"strings"
	"testing"
)

func TestNaiveSubscriptions(t *testing.T) {
	l := Line{Name: "Naive example", Host: "2001:db8::1", Port: 8445, UUID: "user:@/%", Password: "pass:@/?#%", Inbound: spec.Inbound{Protocol: spec.Naive, TLS: &spec.TLS{Mode: spec.TLSStandard, ServerName: "node.example.com", ALPN: []string{"h2"}}}}
	body, err := (SingBox{}).Render([]Line{l}, Account{})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err = json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	o := doc.Outbounds[2]
	if o["type"] != "naive" || o["username"] != l.UUID || o["password"] != l.Password {
		t.Fatalf("wrong credentials: %#v", o)
	}
	tls := o["tls"].(map[string]any)
	if tls["server_name"] != "node.example.com" || len(tls) != 2 || o["transport"] != nil {
		t.Fatalf("unsupported Naive TLS options: %#v", o)
	}
	l.Username = "local-user"
	o = singboxOutbound(l)
	if o["username"] != "local-user" {
		t.Fatal("local username lost")
	}
	l.Username = ""
	link := shareURI(l)
	got, err := ParseURI(link)
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != l.Host || got.Port != l.Port || got.UUID != l.UUID || got.Password != l.Password || got.Inbound.TLS.ServerName != "node.example.com" {
		t.Fatalf("URI roundtrip failed: %#v", got)
	}
	for _, r := range []Renderer{Clash{}, Stash{}, Surge{}, Surfboard{}, Loon{}, QuantumultX{}, Egern{}} {
		b, e := r.Render([]Line{l}, Account{})
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(b), l.Password) || strings.Contains(string(b), l.Host) {
			t.Fatalf("%s emitted unsupported Naive", r.Name())
		}
	}
	l.IPVersion = "ipv4"
	l.Host = "node.example.com"
	if b, _ := (URIList{}).Render([]Line{l}, Account{}); func() bool {
		raw, _ := base64.StdEncoding.DecodeString(string(b))
		return strings.Contains(string(raw), "naive+")
	}() {
		t.Fatal("strict hostname family leaked into URI")
	}
	for _, mode := range []spec.TLSMode{spec.TLSNone, spec.TLSReality} {
		l.Inbound.TLS.Mode = mode
		if singboxOutbound(l) != nil || shareURI(l) != "" {
			t.Fatal("unsupported security accepted")
		}
	}
}
func TestNaiveURIRequiresCredentials(t *testing.T) {
	l, err := ParseURI("naive+https://alice:password@node.example.com#Naive")
	if err != nil || l.Port != 443 {
		t.Fatalf("default port: %v %#v", err, l)
	}
	for _, s := range []string{"naive+https://node.example.com", "naive+https://alice@node.example.com", "naive+https://alice:@node.example.com"} {
		if _, err := ParseURI(s); err == nil {
			t.Fatal("accepted missing password")
		}
	}
}
