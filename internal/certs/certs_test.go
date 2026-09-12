package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

// selfIssuer signs CSRs with a throwaway CA so the manager can be exercised
// without an ACME server.
type selfIssuer struct{ key *ecdsa.PrivateKey }

func (s selfIssuer) IssuerKey() string { return "test-ca" }
func (s selfIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: csr.DNSNames[0]},
		DNSNames: csr.DNSNames, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, csr.PublicKey, s.key)
	if err != nil {
		return nil, err
	}
	return &certmagic.IssuedCertificate{Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

func TestEnsureExportsPEM(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dir := t.TempDir()
	m, err := New(Options{Dir: dir, Issuers: []certmagic.Issuer{selfIssuer{key}}})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	certPath, keyPath, err := m.Ensure(context.Background(), "Node.Example.COM", MethodHTTP)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(certPath) != filepath.Join(dir, "node.example.com") {
		t.Fatalf("unexpected path %s", certPath)
	}
	for _, p := range []string{certPath, keyPath} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if blk, _ := pem.Decode(b); blk == nil {
			t.Fatalf("%s is not PEM", p)
		}
	}
	if st, _ := os.Stat(keyPath); st.Mode().Perm() != 0o600 {
		t.Fatalf("key perms %v", st.Mode().Perm())
	}
	sts := m.Status()
	if len(sts) != 1 || sts[0].Error != "" || sts[0].NotAfter.IsZero() || sts[0].Method != MethodHTTP {
		t.Fatalf("status: %+v", sts)
	}
	// Second call is a no-op hit on the cache and returns the same paths.
	if c2, _, err := m.Ensure(context.Background(), "node.example.com", MethodHTTP); err != nil || c2 != certPath {
		t.Fatalf("second ensure: %v %s", err, c2)
	}
	if _, _, err := m.Ensure(context.Background(), "*.example.com", MethodHTTP); err == nil {
		t.Fatal("wildcard must require DNS-01")
	}
	if _, _, err := m.Ensure(context.Background(), "", MethodHTTP); err == nil {
		t.Fatal("empty domain rejected")
	}
	// The panel TLS config can serve the managed certificate.
	if m.TLSConfig() == nil {
		t.Fatal("tls config")
	}
}
