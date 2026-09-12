// Package certs obtains and renews TLS certificates for inbounds and the
// web panel with ACME (Let's Encrypt) via certmagic. HTTP-01 needs port 80
// reachable on this machine; DNS-01 needs a Cloudflare API token and works
// anywhere, including boxes that only expose a port range.
//
// Certificates are written as PEM files under <Dir>/<domain>/ so the proxy
// cores can read them; the manager rewrites them after every renewal and
// calls OnChange so the agent reloads the cores.
package certs

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"go.uber.org/zap"
)

// Method selects the ACME challenge.
const (
	MethodHTTP = "http" // HTTP-01 on port 80
	MethodDNS  = "dns"  // DNS-01 via Cloudflare
)

// Options configures a Manager.
type Options struct {
	Dir             string // certificate store; PEM exports live in Dir/<domain>/
	Email           string // ACME account contact
	CloudflareToken string // enables DNS-01
	Staging         bool   // use the Let's Encrypt staging CA (test certificates)
	Log             *slog.Logger
	// OnChange runs after a certificate is issued or renewed.
	OnChange func(domain string)
	// Issuers overrides the ACME issuers (tests).
	Issuers []certmagic.Issuer
}

// Status is one managed domain.
type Status struct {
	Domain   string    `json:"domain"`
	Method   string    `json:"method"`
	NotAfter time.Time `json:"not_after"`
	Error    string    `json:"error,omitempty"`
	Updated  time.Time `json:"updated"`
}

// Manager issues and renews certificates.
type Manager struct {
	opts  Options
	log   *slog.Logger
	cache *certmagic.Cache
	http  *certmagic.Config
	dns   *certmagic.Config

	mu     sync.Mutex
	status map[string]*Status
	method map[string]string // domain -> method, so OnEvent knows which config
}

// New builds a manager. Nothing is issued until Ensure is called.
func New(opts Options) (*Manager, error) {
	if opts.Dir == "" {
		return nil, errors.New("certs: dir is required")
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if err := os.MkdirAll(opts.Dir, 0o750); err != nil {
		return nil, err
	}
	m := &Manager{opts: opts, log: opts.Log.With("component", "certs"), status: map[string]*Status{}, method: map[string]string{}}
	storage := &certmagic.FileStorage{Path: filepath.Join(opts.Dir, ".certmagic")}
	m.cache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(c certmagic.Certificate) (*certmagic.Config, error) {
			for _, n := range c.Names {
				if m.methodFor(n) == MethodDNS {
					return m.dns, nil
				}
			}
			return m.http, nil
		},
		Logger: zap.NewNop(),
	})
	base := certmagic.Config{Storage: storage, Logger: zap.NewNop(), OnEvent: m.onEvent, RenewalWindowRatio: 1.0 / 3}
	m.http = certmagic.New(m.cache, base)
	m.dns = certmagic.New(m.cache, base)
	if opts.Issuers != nil {
		m.http.Issuers, m.dns.Issuers = opts.Issuers, opts.Issuers
	} else {
		m.buildIssuers()
	}
	return m, nil
}

// Configure replaces the ACME account settings (email, Cloudflare token),
// e.g. when the panel pushes new ones. Existing certificates keep renewing.
func (m *Manager) Configure(email, cloudflareToken string) {
	m.mu.Lock()
	if m.opts.Issuers != nil || (m.opts.Email == email && m.opts.CloudflareToken == cloudflareToken) {
		m.mu.Unlock()
		return
	}
	m.opts.Email, m.opts.CloudflareToken = email, cloudflareToken
	m.mu.Unlock()
	m.buildIssuers()
}

func (m *Manager) buildIssuers() {
	ca := certmagic.LetsEncryptProductionCA
	if m.opts.Staging {
		ca = certmagic.LetsEncryptStagingCA
	}
	m.http.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(m.http, certmagic.ACMEIssuer{
		CA: ca, Email: m.opts.Email, Agreed: true, DisableTLSALPNChallenge: true, Logger: zap.NewNop(),
	})}
	var solver *certmagic.DNS01Solver
	if m.opts.CloudflareToken != "" {
		solver = &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{DNSProvider: &cloudflare.Provider{APIToken: m.opts.CloudflareToken}}}
	}
	m.dns.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(m.dns, certmagic.ACMEIssuer{
		CA: ca, Email: m.opts.Email, Agreed: true, DisableHTTPChallenge: true, DisableTLSALPNChallenge: true, DNS01Solver: solver, Logger: zap.NewNop(),
	})}
}

// HasDNS reports whether DNS-01 is configured.
func (m *Manager) HasDNS() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.opts.CloudflareToken != "" || m.opts.Issuers != nil
}

func (m *Manager) methodFor(domain string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.method[domain]
}

// Paths returns where the PEM files for a domain live.
func (m *Manager) Paths(domain string) (certPath, keyPath string) {
	d := filepath.Join(m.opts.Dir, strings.ToLower(domain))
	return filepath.Join(d, "fullchain.pem"), filepath.Join(d, "privkey.pem")
}

// Ensure makes sure a valid certificate for domain exists and is kept
// renewed, then returns the PEM paths. The first call for a domain blocks
// while the certificate is obtained (typically well under a minute).
func (m *Manager) Ensure(ctx context.Context, domain, method string) (certPath, keyPath string, err error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || strings.ContainsAny(domain, " /") {
		return "", "", errors.New("certs: a domain is required")
	}
	if method == "" {
		method = MethodHTTP
	}
	if method != MethodHTTP && method != MethodDNS {
		return "", "", fmt.Errorf("certs: unknown method %q", method)
	}
	if method == MethodDNS && !m.HasDNS() {
		return "", "", errors.New("certs: DNS-01 needs a Cloudflare API token (set it in Settings)")
	}
	if strings.HasPrefix(domain, "*.") && method != MethodDNS {
		return "", "", errors.New("certs: wildcard certificates need DNS-01")
	}
	m.mu.Lock()
	m.method[domain] = method
	st := m.status[domain]
	if st == nil {
		st = &Status{Domain: domain}
		m.status[domain] = st
	}
	st.Method = method
	m.mu.Unlock()

	cfg := m.http
	if method == MethodDNS {
		cfg = m.dns
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if err := cfg.ManageSync(ctx, []string{domain}); err != nil {
		m.setError(domain, err)
		return "", "", fmt.Errorf("certs: %s: %w", domain, err)
	}
	if err := m.export(ctx, cfg, domain); err != nil {
		m.setError(domain, err)
		return "", "", err
	}
	certPath, keyPath = m.Paths(domain)
	return certPath, keyPath, nil
}

func (m *Manager) setError(domain string, err error) {
	m.mu.Lock()
	if st := m.status[domain]; st != nil {
		st.Error = err.Error()
		st.Updated = time.Now()
	}
	m.mu.Unlock()
	m.log.Error("certificate", "domain", domain, "err", err)
}

// export writes the managed certificate as PEM files for the cores.
func (m *Manager) export(ctx context.Context, cfg *certmagic.Config, domain string) error {
	cert, err := cfg.CacheManagedCertificate(ctx, domain)
	if err != nil {
		return fmt.Errorf("certs: load %s: %w", domain, err)
	}
	var issuerKey string
	for _, iss := range cfg.Issuers {
		issuerKey = iss.IssuerKey()
	}
	certPEM, err := cfg.Storage.Load(ctx, certmagic.StorageKeys.SiteCert(issuerKey, domain))
	if err != nil {
		return fmt.Errorf("certs: read %s: %w", domain, err)
	}
	keyPEM, err := cfg.Storage.Load(ctx, certmagic.StorageKeys.SitePrivateKey(issuerKey, domain))
	if err != nil {
		return fmt.Errorf("certs: read key %s: %w", domain, err)
	}
	certPath, keyPath := m.Paths(domain)
	if err := os.MkdirAll(filepath.Dir(certPath), 0o750); err != nil {
		return err
	}
	if err := writeAtomic(certPath, certPEM, 0o644); err != nil {
		return err
	}
	if err := writeAtomic(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	m.mu.Lock()
	if st := m.status[domain]; st != nil {
		st.NotAfter, st.Error, st.Updated = cert.Leaf.NotAfter, "", time.Now()
	}
	m.mu.Unlock()
	m.log.Info("certificate ready", "domain", domain, "not_after", cert.Leaf.NotAfter.Format(time.RFC3339))
	return nil
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// onEvent re-exports after a renewal and tells the agent.
func (m *Manager) onEvent(ctx context.Context, event string, data map[string]any) error {
	if event != "cert_obtained" {
		return nil
	}
	renewal, _ := data["renewal"].(bool)
	domain, _ := data["identifier"].(string)
	if !renewal || domain == "" {
		return nil // the initial issuance is exported by Ensure
	}
	cfg := m.http
	if m.methodFor(domain) == MethodDNS {
		cfg = m.dns
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := m.export(ctx, cfg, domain); err != nil {
			m.setError(domain, err)
			return
		}
		m.log.Info("certificate renewed", "domain", domain)
		if m.opts.OnChange != nil {
			m.opts.OnChange(domain)
		}
	}()
	return nil
}

// Status lists every domain the manager has been asked about.
func (m *Manager) Status() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(m.status))
	for _, st := range m.status {
		out = append(out, *st)
	}
	return out
}

// TLSConfig serves the managed certificates, for the web panel.
func (m *Manager) TLSConfig() *tls.Config {
	return m.http.TLSConfig()
}

// Stop releases the renewal maintenance goroutines.
func (m *Manager) Stop() { m.cache.Stop() }
