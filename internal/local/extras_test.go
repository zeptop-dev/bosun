package local

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func selfSigned(t *testing.T, names ...string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	kb, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
}

func TestIngresses(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if _, err := s.PutIngress(Ingress{Name: "IPLC"}, ""); err == nil {
		t.Fatal("ingress without addresses accepted")
	}
	if _, err := s.PutIngress(Ingress{Name: "IPLC", LineIP: "198.51.100.20", PortFrom: 17799, PortTo: 17701}, ""); err == nil {
		t.Fatal("inverted range accepted")
	}
	if _, err := s.PutIngress(Ingress{Name: "IPLC", EntryHost: "entry.example.net", EntryDomain: "x.example.com"}, ""); err == nil {
		t.Fatal("entry domain over a host-name entry accepted")
	}
	g, err := s.PutIngress(Ingress{Name: "IPLC", BindIP: "10.10.0.2", LineIP: "198.51.100.20", EntryHost: "203.0.113.30", EntryDomain: "Iplc.Example.com", PortFrom: 17701, PortTo: 17799, PortOffset: 1000}, "")
	if err != nil || len(g.ID) != 8 || g.EntryDomain != "iplc.example.com" || g.ClientHost() != "iplc.example.com" || g.EntryPort(17710) != 18710 {
		t.Fatalf("create: %+v %v", g, err)
	}
	// Inbounds: unknown ingress and ports outside the range are refused.
	if err := s.PutInbound(Inbound{Inbound: spec.Inbound{Tag: "m", Protocol: spec.Mieru, Port: 17710}, Enabled: true, IngressID: "nope"}, ""); err == nil {
		t.Fatal("unknown ingress accepted")
	}
	if err := s.PutInbound(Inbound{Inbound: spec.Inbound{Tag: "m", Protocol: spec.Mieru, Port: 17800}, Enabled: true, IngressID: g.ID}, ""); err == nil || !strings.Contains(err.Error(), "range") {
		t.Fatalf("port outside range: %v", err)
	}
	if err := s.PutInbound(Inbound{Inbound: spec.Inbound{Tag: "m", Protocol: spec.Mieru, Port: 17710}, Enabled: true, IngressID: g.ID}, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.PutInbound(Inbound{Inbound: spec.Inbound{Tag: "hy2", Protocol: spec.Hysteria2, Port: 8443, TLS: &spec.TLS{Mode: spec.TLSStandard, ServerName: "x.example", AutoCert: true}}, Enabled: true}, ""); err != nil {
		t.Fatal(err)
	}
	// The node binds the line inbound to the NIC, the direct one not.
	node, _, _ := s.Node(ctx)
	listen := map[string]string{}
	for _, ib := range node.Inbounds {
		listen[ib.Tag] = ib.Listen
	}
	if listen["m"] != "10.10.0.2" || listen["hy2"] != "" {
		t.Fatalf("listen: %v", listen)
	}
	// Probe: off by default; on, the line gets a source-bound RTT task on
	// the first inbound's port.
	if s.Probe() != nil {
		t.Fatal("probe should be off")
	}
	if err := s.SetProbe(ProbeSettings{Enabled: true, CarrierPing: true, Carriers: []spec.Carrier{{Name: "HK", Addr: "hkix"}}}); err == nil {
		t.Fatal("carrier without port accepted")
	}
	if err := s.SetProbe(ProbeSettings{Enabled: true, Tasks: []spec.PingTask{{Type: "tcp", Target: "1.1.1.1:443", SourceIP: "not-ip"}}}); err == nil {
		t.Fatal("bad source accepted")
	}
	if err := s.SetProbe(ProbeSettings{Enabled: true, CarrierPing: true, Tasks: []spec.PingTask{{Name: "cf", Type: "TCP", Target: "1.1.1.1:443", IntervalSeconds: 30}}}); err != nil {
		t.Fatal(err)
	}
	p := s.Probe()
	if p == nil || !p.CarrierPing || len(p.Tasks) != 2 || p.Tasks[0].ID != 1 || p.Tasks[0].Type != "tcp" {
		t.Fatalf("probe: %+v", p)
	}
	if line := p.Tasks[1]; line.ID != -1 || line.Name != "IPLC" || line.Target != "198.51.100.20:17710" || line.SourceIP != "10.10.0.2" || line.IntervalSeconds != 30 {
		t.Fatalf("line task: %+v", line)
	}
	// Update keeps the id; delete detaches the inbound.
	g2, err := s.PutIngress(Ingress{Name: "IPLC2", LineIP: "198.51.100.20"}, g.ID)
	if err != nil || g2.ID != g.ID || g2.Name != "IPLC2" {
		t.Fatalf("update: %+v %v", g2, err)
	}
	if _, err := s.PutIngress(Ingress{Name: "x", LineIP: "198.51.100.20"}, "missing"); err != ErrNotFound {
		t.Fatalf("update missing: %v", err)
	}
	if err := s.DeleteIngress(g.ID); err != nil {
		t.Fatal(err)
	}
	if ib, _ := s.Inbound("m"); ib.IngressID != "" {
		t.Fatal("inbound should be detached")
	}
	// Adopt/detach round-trips the extras through the snapshot.
	_, _ = s.PutIngress(Ingress{Name: "L", LineIP: "198.51.100.20"}, "")
	_ = s.Adopt("https://captain.example")
	if len(s.ListIngresses()) != 0 {
		t.Fatal("ingresses cleared while managed")
	}
	_ = s.Detach(nil)
	if len(s.ListIngresses()) != 1 || !s.ProbeSettings().Enabled {
		t.Fatal("snapshot should restore ingresses and probe")
	}
	// Persisted files without a probe section load with carrier pings on.
	s2, _, err := Open(s.path, slog.Default())
	if err != nil || !s2.ProbeSettings().CarrierPing {
		t.Fatalf("reload: %v %+v", err, s2.ProbeSettings())
	}
}

func TestRoutingAndCertificates(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	remote := &spec.Remote{Host: "exit.test", Port: 443, UUID: "u", Settings: spec.Inbound{Protocol: spec.VLESS}}
	bad := []Routing{
		{Outbounds: []spec.Outbound{{Tag: "direct", Remote: remote}}},
		{Outbounds: []spec.Outbound{{Tag: "a", Remote: remote}}, Routes: []spec.RouteRule{{Match: []string{"inbound:x"}, Action: "outbound", Value: "nope"}}},
		{Outbounds: []spec.Outbound{{Tag: "a", Remote: remote, ProxyTag: "b"}, {Tag: "b", Remote: remote, ProxyTag: "a"}}},
		{Outbounds: []spec.Outbound{{Tag: "a", Remote: remote}}, DefaultOutbound: "zzz"},
		{Outbounds: []spec.Outbound{{Tag: "a", Remote: &spec.Remote{Host: "h"}}}},
	}
	for i, nr := range bad {
		if err := s.SetRouting(nr); err == nil {
			t.Fatalf("bad routing %d accepted", i)
		}
	}
	good := Routing{Outbounds: []spec.Outbound{{Tag: "exit", Remote: remote}, {Tag: "hop", Remote: remote, ProxyTag: "exit"}},
		Routes: []spec.RouteRule{{Match: []string{"inbound:in-a"}, Action: "outbound", Value: "hop"}, {Match: []string{"domain:cn"}, Action: "direct", Value: "stale"}}, DefaultOutbound: "exit"}
	if err := s.SetRouting(good); err != nil {
		t.Fatal(err)
	}
	nr := s.Routing()
	if len(nr.Outbounds) != 2 || nr.DefaultOutbound != "exit" || nr.Routes[1].Value != "" {
		t.Fatalf("routing: %+v", nr)
	}
	node, _, _ := s.Node(ctx)
	if len(node.Outbounds) != 2 || node.DefaultOutbound != "exit" || len(node.Routes) != 2 {
		t.Fatalf("node routing: %+v", node)
	}

	cert, key := selfSigned(t, "*.example.com", "example.com")
	if _, err := s.PutCertificate("", cert, "garbage"); err == nil {
		t.Fatal("bad pair accepted")
	}
	v, err := s.PutCertificate("", cert, key)
	if err != nil || v.Domain != "*.example.com" || len(v.Names) != 2 || v.NotAfter.Before(time.Now()) {
		t.Fatalf("upload: %+v %v", v, err)
	}
	if _, err := s.PutCertificate("*.example.com", cert, key); err != nil || len(s.ListCertificates()) != 1 {
		t.Fatal("same domain should replace")
	}
	node, _, _ = s.Node(ctx)
	if len(node.Certificates) != 1 || node.Certificates[0].Domain != "*.example.com" || !strings.Contains(node.Certificates[0].KeyPEM, "PRIVATE") {
		t.Fatalf("node certificates: %+v", node.Certificates)
	}
	if err := s.DeleteCertificate("*.example.com"); err != nil || len(s.ListCertificates()) != 0 {
		t.Fatal("delete")
	}
	if err := s.DeleteCertificate("none"); err != ErrNotFound {
		t.Fatal("delete missing")
	}
	// Detach keeping the panel state carries its exits and certificates.
	_ = s.Adopt("https://captain.example")
	st := &agentproto.State{Node: spec.Node{Outbounds: []spec.Outbound{{Tag: "p", Remote: remote}}, DefaultOutbound: "p", Certificates: []spec.Certificate{{Domain: "x.test", CertPEM: cert, KeyPEM: key}}}}
	_ = s.Detach(st)
	if r := s.Routing(); r.DefaultOutbound != "p" || len(s.ListCertificates()) != 1 {
		t.Fatalf("keep: %+v", r)
	}
}
