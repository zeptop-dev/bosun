package certs

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Custom certificates: PEM pairs the panel pushes, written next to the
// ACME exports and preferred over them for the names they cover.

// Covers reports whether a certificate domain (exact or *.wildcard)
// matches a server name.
func Covers(domain, name string) bool {
	domain, name = strings.ToLower(strings.TrimSpace(domain)), strings.ToLower(strings.TrimSpace(name))
	if domain == "" || name == "" {
		return false
	}
	if domain == name {
		return true
	}
	if strings.HasPrefix(domain, "*.") {
		suffix := domain[1:] // ".example.com"
		return strings.HasSuffix(name, suffix) && !strings.Contains(strings.TrimSuffix(name, suffix), ".")
	}
	return false
}

// Pick returns the pushed certificate for a server name: an exact match
// first, then a wildcard.
func Pick(list []spec.Certificate, name string) *spec.Certificate {
	var wild *spec.Certificate
	for i := range list {
		c := &list[i]
		if !Covers(c.Domain, name) {
			continue
		}
		if !strings.HasPrefix(c.Domain, "*.") {
			return c
		}
		if wild == nil {
			wild = c
		}
	}
	return wild
}

// Install validates a PEM pair and writes it under dir/custom/<domain>/,
// leaving the files alone when they already hold the same bytes. Returns
// the paths and the leaf's expiry.
func Install(dir string, c spec.Certificate) (certPath, keyPath string, notAfter time.Time, err error) {
	pair, err := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM))
	if err != nil {
		return "", "", time.Time{}, errors.New("certificate and key do not parse as a pair: " + err.Error())
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return "", "", time.Time{}, err
	}
	name := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(c.Domain), "*", "_wildcard"))
	if name == "" || strings.ContainsAny(name, "/\\ ") {
		return "", "", time.Time{}, errors.New("bad certificate domain")
	}
	d := filepath.Join(dir, "custom", name)
	if err := os.MkdirAll(d, 0o750); err != nil {
		return "", "", time.Time{}, err
	}
	certPath, keyPath = filepath.Join(d, "fullchain.pem"), filepath.Join(d, "privkey.pem")
	if cur, err := os.ReadFile(certPath); err != nil || string(cur) != c.CertPEM {
		if err := writeAtomic(certPath, []byte(c.CertPEM), 0o644); err != nil {
			return "", "", time.Time{}, err
		}
	}
	if cur, err := os.ReadFile(keyPath); err != nil || string(cur) != c.KeyPEM {
		if err := writeAtomic(keyPath, []byte(c.KeyPEM), 0o600); err != nil {
			return "", "", time.Time{}, err
		}
	}
	return certPath, keyPath, leaf.NotAfter, nil
}
