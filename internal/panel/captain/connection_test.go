package captain

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnectionMigrationAuthenticatedHotSwitch(t *testing.T) {
	id := "012345678901234567890123456789"
	key := "012345678901234567890123456789012345"
	var verified, complete atomic.Int32
	old := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer old.Close()
	var target *httptest.Server
	target = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/connection-proof":
			if r.Header.Get("Authorization") != "" {
				t.Error("token leaked before same-panel proof")
			}
			challenge := r.URL.Query().Get("challenge")
			json.NewEncoder(w).Encode(agentproto.ConnectionProof{ID: id, Challenge: challenge, Signature: agentproto.ConnectionSignature(key, id, target.URL, challenge, func() string {
				b, e := agentproto.ConnectionBinding(r.TLS, challenge)
				if e != nil {
					t.Error(e)
				}
				return b
			}())})
		case "/api/agent/connection-result":
			if r.Header.Get("Authorization") != "Bearer token" {
				t.Error("missing original credential")
			}
			var v agentproto.ConnectionResult
			json.NewDecoder(r.Body).Decode(&v)
			if v.Status == "verified" {
				verified.Add(1)
			} else if v.Status == "completed" {
				complete.Add(1)
			}
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
	defer target.Close()
	dir := t.TempDir()
	file := filepath.Join(dir, "token")
	os.WriteFile(file, []byte("token"), 0600)
	c, err := New(Config{URL: old.URL, DataDir: dir, TokenFile: file}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	roots := x509.NewCertPool()
	roots.AddCert(old.Certificate())
	roots.AddCert(target.Certificate())
	c.http = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	identity := c.TrafficIdentity()
	m := agentproto.ConnectionMigration{ID: id, SourceURL: old.URL, TargetURL: target.URL, ProofKey: key, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	c.migrateConnection(m)
	if c.ActiveURL() != target.URL || verified.Load() != 1 || complete.Load() != 1 {
		t.Fatal("not migrated", c.ActiveURL(), verified.Load(), complete.Load())
	}
	if c.TrafficIdentity() != identity {
		t.Fatal("traffic identity changed")
	}
	c.migrateConnection(m)
	if complete.Load() != 1 {
		t.Fatal("replayed migration")
	}
	restarted, err := New(Config{URL: old.URL, DataDir: dir, TokenFile: file}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if restarted.ActiveURL() != target.URL || restarted.TrafficIdentity() != identity {
		t.Fatal("selection or journal identity lost across restart")
	}
	if _, err = os.Stat(filepath.Join(dir, "captain-connection.json")); err != nil {
		t.Fatal(err)
	}
	_ = context.Background()
}
func TestConnectionMigrationRejectsUnprovenTarget(t *testing.T) {
	var leaked atomic.Bool
	old := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer old.Close()
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
		json.NewEncoder(w).Encode(agentproto.ConnectionProof{ID: "bad", Signature: "bad"})
	}))
	defer target.Close()
	dir := t.TempDir()
	file := filepath.Join(dir, "token")
	os.WriteFile(file, []byte("token"), 0600)
	c, err := New(Config{URL: old.URL, DataDir: dir, TokenFile: file}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	roots := x509.NewCertPool()
	roots.AddCert(old.Certificate())
	roots.AddCert(target.Certificate())
	c.http = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	c.migrateConnection(agentproto.ConnectionMigration{ID: "0123456789012345678901234", SourceURL: old.URL, TargetURL: target.URL, ProofKey: "012345678901234567890123456789012345", ExpiresAt: time.Now().Add(time.Minute).Unix()})
	if leaked.Load() || c.ActiveURL() != old.URL {
		t.Fatal("unproven endpoint received credentials or became active")
	}
	if _, err = os.Stat(filepath.Join(dir, "captain-connection.json")); !os.IsNotExist(err) {
		t.Fatal("failed proof persisted a destination")
	}
}

func TestConnectionMigrationRejectsRelayedSamePanelProof(t *testing.T) {
	id := "012345678901234567890123456789"
	key := "012345678901234567890123456789012345"
	var targetURL string
	legitimate := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/connection-proof" {
			w.WriteHeader(200)
			return
		}
		challenge := r.URL.Query().Get("challenge")
		binding, err := agentproto.ConnectionBinding(r.TLS, challenge)
		if err != nil {
			t.Error(err)
			return
		}
		json.NewEncoder(w).Encode(agentproto.ConnectionProof{ID: id, Challenge: challenge, Signature: agentproto.ConnectionSignature(key, id, targetURL, challenge, binding)})
	}))
	defer legitimate.Close()
	var leaked atomic.Bool
	attacker := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
		response, err := legitimate.Client().Get(legitimate.URL + r.URL.RequestURI())
		if err != nil {
			t.Error(err)
			return
		}
		defer response.Body.Close()
		io.Copy(w, response.Body)
	}))
	defer attacker.Close()
	targetURL = attacker.URL
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	os.WriteFile(tokenFile, []byte("token"), 0600)
	c, err := New(Config{URL: legitimate.URL, DataDir: dir, TokenFile: tokenFile}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	roots := x509.NewCertPool()
	roots.AddCert(legitimate.Certificate())
	roots.AddCert(attacker.Certificate())
	c.http = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	c.migrateConnection(agentproto.ConnectionMigration{ID: id, SourceURL: legitimate.URL, TargetURL: attacker.URL, ProofKey: key, ExpiresAt: time.Now().Add(time.Minute).Unix()})
	if leaked.Load() || c.ActiveURL() != legitimate.URL {
		t.Fatal("relayed proof transferred node authority")
	}
}
