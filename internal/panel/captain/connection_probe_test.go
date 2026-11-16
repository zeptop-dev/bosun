package captain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProbeIsAnonymousAndCannotSwitchOrTrustOnFailure(t *testing.T) {
	for _, kind := range []string{"direct", "trusted-proxy", "bad-proof", "untrusted-cert", "redirect", "lost-result"} {
		t.Run(kind, func(t *testing.T) {
			id, key := "probe-012345678901234567890", "proof-key-012345678901234567890123"
			expires := time.Now().Add(time.Minute).Unix()
			var targetURL string
			var result agentproto.ConnectionProbeResult
			proofs := 0
			receipts := 0
			source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer token" {
					t.Error("source result lacks authentication")
				}
				if e := json.NewDecoder(r.Body).Decode(&result); e != nil {
					t.Error(e)
				}
				receipts++
				if kind == "lost-result" && receipts == 1 {
					conn, _, _ := w.(http.Hijacker).Hijack()
					conn.Close()
					return
				}
				w.WriteHeader(200)
			}))
			defer source.Close()
			target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				proofs++
				if r.Header.Get("Authorization") != "" {
					t.Error("probe sent target credentials")
				}
				if r.Method != "GET" {
					t.Error("probe mutated target")
				}
				if kind == "redirect" {
					http.Redirect(w, r, source.URL, 302)
					return
				}
				q := r.URL.Query().Get("challenge")
				binding, _ := agentproto.ConnectionBinding(r.TLS, q)
				proxyKey := key
				if kind == "bad-proof" {
					proxyKey = "wrong"
				}
				proof := agentproto.ConnectionProof{ID: id, Challenge: q, ProxySignature: agentproto.ConnectionSignature(proxyKey, id, targetURL, q, agentproto.ProbeConnectionBinding(expires))}
				if kind == "direct" {
					proof.Signature = agentproto.ConnectionSignature(key, id, targetURL, q, binding)
				}
				json.NewEncoder(w).Encode(proof)
			}))
			defer target.Close()
			keypair, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if e != nil {
				t.Fatal(e)
			}
			cert := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, e := x509.CreateCertificate(rand.Reader, cert, cert, &keypair.PublicKey, keypair)
			if e != nil {
				t.Fatal(e)
			}
			target.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: keypair}}}
			target.StartTLS()
			targetURL = target.URL
			dir := t.TempDir()
			token := filepath.Join(dir, "token")
			os.WriteFile(token, []byte("token"), 0600)
			c, e := New(Config{URL: source.URL, DataDir: dir, TokenFile: token}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			roots := x509.NewCertPool()
			roots.AddCert(source.Certificate())
			if kind != "untrusted-cert" {
				roots.AddCert(target.Certificate())
			}
			c.http.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}
			before := c.TrafficIdentity()
			probe := agentproto.ConnectionProbe{ID: id, TargetURL: targetURL, ProofKey: key, ExpiresAt: expires}
			if kind == "direct" {
				c.connectionProbeMu.Lock()
				c.probeConnection(probe)
				cursor, _ := c.connectionProbeCursor.Load().(string)
				if cursor != id || c.connectionProbeNext.Load() == nil || proofs != 0 {
					t.Fatal("busy probe lost delivery cursor or queued work")
				}
				c.connectionProbeMu.Unlock()
				c.processProbe()
			} else {
				c.probeConnection(probe)
			}
			if kind == "lost-result" {
				if c.connectionProbePending == nil {
					t.Fatal("lost diagnostic receipt not retained")
				}
				c.finishProbeReceipt()
				if receipts != 2 || c.connectionProbePending != nil || proofs != 1 {
					t.Fatal("receipt retried by re-probing or not cleared", receipts, proofs)
				}
			}
			want := kind
			if kind == "lost-result" {
				want = "trusted-proxy"
			}
			if kind != "direct" && kind != "trusted-proxy" && kind != "lost-result" {
				want = "failed"
			}
			if result.Status != want {
				t.Fatalf("%s: %+v", kind, result)
			}
			if c.ActiveURL() != source.URL || c.TrafficIdentity() != before {
				t.Fatal("probe changed connection identity")
			}
			if _, e = os.Stat(filepath.Join(dir, "captain-connection.json")); !os.IsNotExist(e) {
				t.Fatal("probe persisted a selection")
			}
			if kind == "untrusted-cert" && proofs != 0 {
				t.Fatal("invalid certificate accepted")
			}
		})
	}
}
