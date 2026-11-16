package captain

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTrustedProxyMigrationAcrossTLSAndHTTPOrigin(t *testing.T) {
	for _, scenario := range []string{"direct", "trusted-proxy", "invalid", "bad-proof", "wrong-target", "redirect", "untrusted-cert", "lost-confirmation", "target-denied", "default-transport"} {
		mode := scenario
		if scenario != "direct" && scenario != "invalid" {
			mode = "trusted-proxy"
		}
		t.Run(scenario, func(t *testing.T) {
			id, key := "migration-01234567890123456789", "secret-01234567890123456789012345"
			expires := time.Now().Add(time.Minute).Unix()
			var credentials atomic.Int32
			var targetURL string
			// HTTP origin behind a TLS-terminating reverse proxy, no TLS exporter here.
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/agent/connection-proof" {
					if r.Header.Get("Authorization") != "" {
						t.Error("anonymous proof leaked token")
					}
					q := r.URL.Query().Get("challenge")
					json.NewEncoder(w).Encode(agentproto.ConnectionProof{ID: id, Challenge: q, Signature: agentproto.ConnectionSignature(func() string {
						if scenario == "bad-proof" {
							return "wrong"
						}
						return key
					}(), id, func() string {
						if scenario == "wrong-target" {
							return targetURL + "wrong"
						}
						return targetURL
					}(), q, agentproto.ProxyConnectionBinding(expires))})
					return
				}
				if r.Header.Get("Authorization") != "Bearer token" {
					t.Error("credential missing")
				}
				credentials.Add(1)
				if scenario == "target-denied" {
					w.WriteHeader(403)
					return
				}
				if scenario == "lost-confirmation" {
					var result agentproto.ConnectionResult
					json.NewDecoder(r.Body).Decode(&result)
					if result.Status == "completed" {
						conn, _, _ := w.(http.Hijacker).Hijack()
						conn.Close()
						return
					}
				}
				w.WriteHeader(200)
			}))
			defer backend.Close()
			proxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if scenario == "redirect" {
					http.Redirect(w, r, "https://elsewhere.example.com", 302)
					return
				}
				req, _ := http.NewRequest(r.Method, backend.URL+r.URL.RequestURI(), r.Body)
				req.Header = r.Header.Clone()
				res, e := http.DefaultClient.Do(req)
				if e != nil {
					if scenario != "lost-confirmation" {
						t.Error(e)
					}
					w.WriteHeader(502)
					return
				}
				defer res.Body.Close()
				w.WriteHeader(res.StatusCode)
				io.Copy(w, res.Body)
			}))
			defer proxy.Close()
			targetURL = proxy.URL
			old := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
			defer old.Close()
			dir := t.TempDir()
			file := filepath.Join(dir, "token")
			os.WriteFile(file, []byte("token"), 0600)
			c, e := New(Config{URL: old.URL, DataDir: dir, TokenFile: file}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			roots := x509.NewCertPool()
			roots.AddCert(old.Certificate())
			roots.AddCert(proxy.Certificate())
			if scenario == "untrusted-cert" {
				roots = x509.NewCertPool()
			}
			c.http = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
			if scenario == "default-transport" {
				original := http.DefaultTransport
				http.DefaultTransport = c.http.Transport
				defer func() { http.DefaultTransport = original }()
				c.http.Transport = nil // New leaves this nil in real production use.
			}
			identity := c.TrafficIdentity()
			c.migrateConnection(agentproto.ConnectionMigration{ID: id, SourceURL: old.URL, TargetURL: targetURL, ProofKey: key, ExpiresAt: expires, VerificationMode: mode})
			if scenario == "trusted-proxy" || scenario == "lost-confirmation" || scenario == "default-transport" {
				if c.ActiveURL() != targetURL || credentials.Load() != 2 {
					t.Fatal("proxy migration failed", c.ActiveURL(), credentials.Load())
				}
				saved, e := config.ReadConnection(dir, old.URL, "token")
				if e != nil || saved.URL != targetURL {
					t.Fatal(saved, e)
				}
			} else if c.ActiveURL() != old.URL || (credentials.Load() != 0 && scenario != "target-denied") {
				t.Fatal("untrusted proxy received token")
			}
			if c.revoked {
				t.Fatal("new target rejection revoked working old identity")
			}
			if c.TrafficIdentity() != identity {
				t.Fatal("identity changed")
			}
		})
	}
}
func TestTrustedProxyTransportRejectsDisabledCertificateValidation(t *testing.T) {
	if _, e := verifiedProxyTransport(&http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}); e == nil {
		t.Fatal("insecure proxy TLS accepted")
	}
	if !strings.Contains(agentproto.ProxyConnectionBinding(1), "trusted-proxy") {
		t.Fatal("missing protocol domain separation")
	}
}
