// Package decoy serves the node's own HTTPS website on loopback so REALITY
// inbounds can use it as their handshake target ("steal yourself"): the
// certificate is real (ACME for the operator's domain), TLS 1.3 + h2 +
// X25519 are what Go's server does by default, and a probe that fails
// REALITY authentication lands on this site instead of being relayed to
// some third party's servers.
package decoy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zeptop-dev/bosun/internal/certs"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Status is what the UI shows.
type Status struct {
	Domain   string `json:"domain"`
	Port     int    `json:"port"`
	Upstream string `json:"upstream,omitempty"`
	Running  bool   `json:"running"`
	// CertReady is true once a certificate for Domain is on disk.
	CertReady bool   `json:"cert_ready"`
	Error     string `json:"error,omitempty"`
}

// Server runs at most one decoy site and reconfigures in place.
type Server struct {
	certs *certs.Manager
	log   *slog.Logger
	// TLSConfig overrides the certificate source (tests).
	TLSConfig *tls.Config

	mu     sync.Mutex
	cfg    *spec.Decoy
	srv    *http.Server
	status Status
	cancel context.CancelFunc
}

// New builds an idle server; Configure starts it.
func New(cm *certs.Manager, log *slog.Logger) *Server {
	return &Server{certs: cm, log: log.With("component", "decoy")}
}

// Status returns the current state.
func (s *Server) Status() *Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg == nil {
		return nil
	}
	st := s.status
	if s.certs != nil && st.Domain != "" {
		for _, c := range s.certs.Status() {
			if strings.EqualFold(c.Domain, st.Domain) && c.Error == "" && !c.NotAfter.IsZero() {
				st.CertReady = true
			}
		}
	}
	return &st
}

// Configure applies d: nil stops the site, a changed config restarts it,
// the same config is a no-op. The certificate is requested in the
// background; until it arrives handshakes fail and Status says so.
func (s *Server) Configure(ctx context.Context, d *spec.Decoy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d == nil || d.Domain == "" {
		s.stopLocked()
		s.cfg = nil
		return
	}
	if s.cfg != nil && same(*s.cfg, *d) && s.srv != nil {
		return
	}
	s.stopLocked()
	cp := *d
	s.cfg = &cp
	s.status = Status{Domain: d.Domain, Port: d.EffectivePort(), Upstream: d.Upstream}
	if err := s.startLocked(ctx); err != nil {
		s.status.Error = err.Error()
		s.log.Error("decoy site failed to start", "domain", d.Domain, "err", err)
	}
}

func same(a, b spec.Decoy) bool {
	return a.Domain == b.Domain && a.EffectivePort() == b.EffectivePort() && a.Upstream == b.Upstream && a.ACME == b.ACME
}

func (s *Server) startLocked(ctx context.Context) error {
	d := s.cfg
	h, err := handler(d)
	if err != nil {
		return err
	}
	tcfg := s.TLSConfig
	if tcfg == nil {
		if s.certs == nil {
			return errors.New("certificate automation is disabled")
		}
		base := s.certs.TLSConfig()
		tcfg = &tls.Config{GetCertificate: base.GetCertificate, MinVersion: tls.VersionTLS12}
	}
	tcfg = tcfg.Clone()
	tcfg.NextProtos = []string{"h2", "http/1.1"}
	tcfg.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(d.EffectivePort()))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	tln := tls.NewListener(ln, tcfg)
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	s.srv = srv
	s.status.Running = true
	go func() {
		if err := srv.Serve(tln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("decoy site stopped", "err", err)
			s.mu.Lock()
			s.status.Running, s.status.Error = false, err.Error()
			s.mu.Unlock()
		}
	}()
	if s.certs != nil && s.TLSConfig == nil {
		cctx, cancel := context.WithCancel(context.Background())
		s.cancel = cancel
		domain, method := d.Domain, d.ACME
		go func() {
			ectx, done := context.WithTimeout(cctx, 5*time.Minute)
			defer done()
			if _, _, err := s.certs.Ensure(ectx, domain, method); err != nil {
				s.log.Error("decoy certificate", "domain", domain, "err", err)
				s.mu.Lock()
				s.status.Error = "certificate: " + err.Error()
				s.mu.Unlock()
			}
		}()
	}
	_ = ctx
	s.log.Info("decoy site up", "domain", d.Domain, "addr", addr, "upstream", d.Upstream)
	return nil
}

func (s *Server) stopLocked() {
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	if s.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = s.srv.Shutdown(ctx)
		cancel()
		s.srv = nil
	}
	s.status.Running = false
}

// Stop shuts the site down.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopLocked()
}

// handler is a reverse proxy to Upstream, or the built-in page.
func handler(d *spec.Decoy) (http.Handler, error) {
	if d.Upstream != "" {
		u, err := url.Parse(d.Upstream)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("upstream must be an http(s) URL, got %q", d.Upstream)
		}
		if !d.AllowPrivate {
			if ip := net.ParseIP(u.Hostname()); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
				return nil, fmt.Errorf("upstream %s is a local address; enable allow_private to proxy local services", u.Host)
			}
			if h := strings.ToLower(u.Hostname()); h == "localhost" {
				return nil, fmt.Errorf("upstream %s is a local address; enable allow_private to proxy local services", u.Host)
			}
		}
		rp := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)
			pr.Out.Host = u.Host
			pr.SetXForwarded()
		}}
		if u.Scheme == "https" && d.Insecure {
			rp.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // operator opted in
		}
		return rp, nil
	}
	page := builtinPage(d.Domain)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(page)
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
	})
	return mux, nil
}

// builtinPage is a plain, plausible placeholder: nothing that names bosun.
func builtinPage(domain string) []byte {
	d := html.EscapeString(domain)
	return []byte(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>` + d + `</title>
<style>body{margin:0;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;background:#f6f7f9;color:#1f2933;display:flex;min-height:100vh;align-items:center;justify-content:center}
main{max-width:520px;padding:40px;background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.08)}h1{font-size:22px;margin:0 0 12px}p{line-height:1.6;margin:0 0 8px;color:#52606d}small{color:#9aa5b1}</style></head>
<body><main><h1>` + d + `</h1><p>This site is under construction. Please check back later.</p><small>&copy; ` + strconv.Itoa(time.Now().Year()) + ` ` + d + `</small></main></body></html>`)
}
