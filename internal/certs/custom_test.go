package certs

import (
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

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func selfSigned(t *testing.T, name string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	kb, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
}

func TestCoversAndPick(t *testing.T) {
	if !Covers("a.example.com", "A.example.com") || !Covers("*.example.com", "jp1.example.com") || Covers("*.example.com", "example.com") || Covers("*.example.com", "a.b.example.com") || Covers("", "x") {
		t.Fatal("Covers")
	}
	list := []spec.Certificate{{Domain: "*.example.com"}, {Domain: "jp1.example.com"}}
	if Pick(list, "jp1.example.com").Domain != "jp1.example.com" || Pick(list, "jp2.example.com").Domain != "*.example.com" || Pick(list, "other.net") != nil {
		t.Fatal("Pick")
	}
}

func TestInstall(t *testing.T) {
	dir := t.TempDir()
	cert, key := selfSigned(t, "jp1.example.com")
	cp, kp, exp, err := Install(dir, spec.Certificate{Domain: "*.example.com", CertPEM: cert, KeyPEM: key})
	if err != nil || exp.Before(time.Now()) {
		t.Fatal(err, exp)
	}
	if cp != filepath.Join(dir, "custom", "_wildcard.example.com", "fullchain.pem") {
		t.Fatal(cp)
	}
	fi, _ := os.Stat(kp)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key perms %v", fi.Mode())
	}
	before, _ := os.Stat(cp)
	time.Sleep(10 * time.Millisecond)
	if _, _, _, err := Install(dir, spec.Certificate{Domain: "*.example.com", CertPEM: cert, KeyPEM: key}); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.Stat(cp); !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("unchanged certificate rewritten")
	}
	if _, _, _, err := Install(dir, spec.Certificate{Domain: "x", CertPEM: cert, KeyPEM: "garbage"}); err == nil {
		t.Fatal("bad key accepted")
	}
}
