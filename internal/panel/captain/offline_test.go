package captain

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func recoveryRig(t *testing.T) (Config, *atomic.Int32) {
	t.Helper()
	code := new(atomic.Int32)
	code.Store(200)
	st := agentproto.State{Revision: "revision", Node: spec.Node{ID: "node", Mode: spec.NodeFull, ServiceControl: &spec.ServiceControl{Revision: "pause", Mode: spec.ServiceControlPause}}, Users: []spec.User{{ID: 1, Name: "account"}}, Jobs: []agentproto.Job{{ID: "never-replay", Kind: "rollback"}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(code.Load())
		if n != 200 {
			w.WriteHeader(n)
			return
		}
		w.Header().Set("ETag", "revision")
		json.NewEncoder(w).Encode(st)
	}))
	t.Cleanup(srv.Close)
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("private-token"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{URL: srv.URL, TokenFile: file, OfflineMaxAge: time.Hour}
	c, err := New(cfg, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = c.Node(context.Background()); err != nil {
		t.Fatal(err)
	}
	return cfg, code
}
func recoveredClient(t *testing.T, cfg Config) *Client {
	t.Helper()
	c, e := New(cfg, slog.Default())
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestOfflineRestartPreservesPolicyAndNeverJobs(t *testing.T) {
	cfg, code := recoveryRig(t)
	code.Store(503)
	c := recoveredClient(t, cfg)
	node, moved, err := c.Node(context.Background())
	if err != nil || !moved || node.ID != "node" || node.ServiceControl.Mode != spec.ServiceControlPause {
		t.Fatalf("recovery failed: %v %v", moved, err)
	}
	if len(c.Jobs()) != 0 || len(c.State().Jobs) != 0 {
		t.Fatal("cached job replay")
	}
	if e := c.ServiceLeaseError(); e != nil {
		t.Fatal(e)
	}
	c.mu.Lock()
	c.verifiedAt = time.Now().Add(-2 * time.Hour)
	c.mu.Unlock()
	if c.ServiceLeaseError() == nil {
		t.Fatal("runtime lease did not expire")
	}
	if _, _, e := c.Node(context.Background()); e == nil {
		t.Fatal("expired memory renewed offline")
	}
	code.Store(200)
	if _, _, e := c.Node(context.Background()); e != nil || c.ServiceLeaseError() != nil {
		t.Fatal("online recovery failed", e)
	}
	if len(c.Jobs()) != 1 {
		t.Fatal("fresh jobs did not resume")
	}
}
func TestOfflineRejectsCacheAndAuthorizationFailures(t *testing.T) {
	for _, kind := range []string{"corrupt", "stale", "future", "token", "url", "permission", "symlink", "401", "403", "400", "404", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			cfg, code := recoveryRig(t)
			file := filepath.Join(cfg.TokenFile+".recovery", "state.json")
			switch kind {
			case "corrupt":
				os.WriteFile(file, []byte("{}"), 0600)
			case "stale", "future":
				c := recoveredClient(t, cfg)
				code.Store(503)
				if _, _, e := c.Node(context.Background()); e != nil {
					t.Fatal(e)
				}
				c.mu.Lock()
				if kind == "stale" {
					c.verifiedAt = time.Now().Add(-2 * time.Hour)
				} else {
					c.verifiedAt = time.Now().Add(time.Hour)
				}
				c.mu.Unlock()
				c.saveSnapshot()
			case "token":
				os.WriteFile(cfg.TokenFile, []byte("another-token"), 0600)
			case "url":
				cfg.URL += "/different"
			case "permission":
				os.Chmod(file, 0644)
			case "symlink":
				old := file + ".old"
				os.Rename(file, old)
				os.Symlink(old, file)
			}
			code.Store(503)
			switch kind {
			case "401":
				code.Store(401)
			case "403":
				code.Store(403)
			case "400":
				code.Store(400)
			case "404":
				code.Store(404)
			case "malformed":
				code.Store(200)
				cfg.URL += "/not-json"
				code.Store(204)
			}
			c := recoveredClient(t, cfg)
			if _, _, e := c.Node(context.Background()); e == nil {
				t.Fatal("unsafe state accepted")
			}
			if kind == "401" || kind == "403" {
				code.Store(503)
				c = recoveredClient(t, cfg)
				if _, _, e := c.Node(context.Background()); e == nil {
					t.Fatal("rejected snapshot survived restart")
				}
			}
		})
	}
}
func TestOfflineDisabledAndPersistenceFailure(t *testing.T) {
	cfg, code := recoveryRig(t)
	cfg.OfflineMaxAge = 0
	code.Store(503)
	c := recoveredClient(t, cfg)
	if _, _, e := c.Node(context.Background()); e == nil {
		t.Fatal("default enabled recovery")
	}
	cfg.OfflineMaxAge = time.Hour
	os.Chmod(cfg.TokenFile+".recovery", 0755)
	code.Store(200)
	c = recoveredClient(t, cfg)
	if _, _, e := c.Node(context.Background()); e != nil || c.ServiceLeaseError() != nil {
		t.Fatal("snapshot failure invalidated authenticated live state", e)
	}
}
func TestOffline304RenewsOnlyValidatedState(t *testing.T) {
	cfg, code := recoveryRig(t)
	c := recoveredClient(t, cfg)
	code.Store(503)
	if _, _, e := c.Node(context.Background()); e != nil {
		t.Fatal(e)
	}
	c.mu.Lock()
	c.verifiedAt = time.Now().Add(-2 * time.Hour)
	c.mu.Unlock()
	code.Store(304)
	// Recovery has no ETag; an unsolicited 304 must not renew a disk snapshot.
	if _, _, e := c.Node(context.Background()); e == nil {
		t.Fatal("unsolicited 304 validated cached state")
	}
}

func TestOfflineSaveFailureInvalidatesOlderSnapshotWithoutRevokingLiveState(t *testing.T) {
	cfg, code := recoveryRig(t)
	c := recoveredClient(t, cfg)
	if _, _, err := c.Node(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A valid in-memory state that exceeds the recovery file limit simulates a
	// failed replacement while an older, still-unexpired snapshot exists.
	c.mu.Lock()
	c.state.Revision = strings.Repeat("x", snapshotLimit)
	c.mu.Unlock()
	c.saveSnapshot()
	if err := c.ServiceLeaseError(); err != nil {
		t.Fatal("snapshot failure revoked live authorization", err)
	}
	if _, err := os.Stat(filepath.Join(c.snapshotDir(), "state.json")); !os.IsNotExist(err) {
		t.Fatal("old snapshot was not invalidated", err)
	}
	code.Store(503)
	restarted := recoveredClient(t, cfg)
	if _, _, err := restarted.Node(context.Background()); err == nil {
		t.Fatal("restart reused stale authorization after a failed replacement")
	}
}

func TestOfflineCloneCannotBeMutatedByRenderPreparation(t *testing.T) {
	cfg, code := recoveryRig(t)
	c := recoveredClient(t, cfg)
	node, _, err := c.Node(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	node.ServiceControl.Mode = spec.ServiceControlNormal
	if c.State().Node.ServiceControl.Mode != spec.ServiceControlPause {
		t.Fatal("caller changed authenticated snapshot")
	}
	code.Store(503)
	c = recoveredClient(t, cfg)
	node, _, err = c.Node(context.Background())
	if err != nil || node.ServiceControl.Mode != spec.ServiceControlPause {
		t.Fatal("snapshot changed", err)
	}
}
func TestOfflineTransientTransportAndCancellation(t *testing.T) {
	cfg, _ := recoveryRig(t)
	c := recoveredClient(t, cfg)
	c.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	})
	if _, _, e := c.Node(context.Background()); e != nil {
		t.Fatal("network outage did not recover", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if transientStateError(ctx.Err()) {
		t.Fatal("cancel permits recovery")
	}
	if transientStateError(&tls.CertificateVerificationError{Err: errors.New("invalid certificate")}) {
		t.Fatal("TLS validation permits recovery")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOfflineLeaseBounds(t *testing.T) {
	cfg, _ := recoveryRig(t)
	for _, age := range []time.Duration{-time.Second, 25 * time.Hour} {
		cfg.OfflineMaxAge = age
		if _, err := New(cfg, slog.Default()); err == nil {
			t.Fatal("invalid lease accepted", age)
		}
	}
}

func TestOfflineDeliveryRejectionRevokesLease(t *testing.T) {
	for _, kind := range []string{"report", "beat"} {
		for _, status := range []int32{401, 403} {
			t.Run(kind+http.StatusText(int(status)), func(t *testing.T) {
				cfg, code := recoveryRig(t)
				c := recoveredClient(t, cfg)
				if _, _, err := c.Node(context.Background()); err != nil {
					t.Fatal(err)
				}
				code.Store(status)
				if kind == "report" {
					_, _ = c.Report(context.Background(), agentproto.Report{})
				} else {
					_ = c.Beat(context.Background(), agentproto.Beat{})
				}
				if c.ServiceLeaseError() == nil {
					t.Fatal("delivery authorization rejection left lease valid")
				}
				code.Store(503)
				if _, _, err := recoveredClient(t, cfg).Node(context.Background()); err == nil {
					t.Fatal("rejected delivery resurrected cached credentials")
				}
			})
		}
	}
}

func TestOfflineLateStateCannotUndoRevocation(t *testing.T) {
	cfg, code := recoveryRig(t)
	c := recoveredClient(t, cfg)
	if _, _, err := c.Node(context.Background()); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_ = json.NewEncoder(w).Encode(agentproto.State{Revision: "old", Node: spec.Node{ID: "node"}})
	}))
	defer server.Close()
	c.cfg.URL = server.URL
	result := make(chan error, 1)
	go func() { _, err := c.fetch(context.Background()); result <- err }()
	<-entered
	c.revokeLease()
	close(release)
	if err := <-result; err == nil {
		t.Fatal("late state accepted after newer rejection")
	}
	if c.ServiceLeaseError() == nil {
		t.Fatal("late state revived revoked lease")
	}
	c.cfg.URL = cfg.URL
	code.Store(200)
	if _, err := c.fetch(context.Background()); err != nil || c.ServiceLeaseError() != nil {
		t.Fatal("fresh state after rejection cannot recover", err)
	}
}

func TestOfflineTruncatedRejectionRevokesLease(t *testing.T) {
	for _, kind := range []string{"state", "report", "beat"} {
		t.Run(kind, func(t *testing.T) {
			cfg, _ := recoveryRig(t)
			c := recoveredClient(t, cfg)
			if _, _, err := c.Node(context.Background()); err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "100")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("short"))
			}))
			defer srv.Close()
			c.cfg.URL = srv.URL
			switch kind {
			case "state":
				_, _ = c.fetch(context.Background())
			case "report":
				_, _ = c.Report(context.Background(), agentproto.Report{})
			case "beat":
				_ = c.Beat(context.Background(), agentproto.Beat{})
			}
			if c.ServiceLeaseError() == nil {
				t.Fatal("partial rejection body left cached authorization valid")
			}
		})
	}
}
