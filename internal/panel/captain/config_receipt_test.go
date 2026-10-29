package captain

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/panel"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

type configurationServer struct {
	mu                        sync.Mutex
	state                     agentproto.State
	delivery                  string
	status                    int
	retired, foreign          bool
	lastSession, lastDelivery string
	reports                   []agentproto.Report
}

func (s *configurationServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == http.MethodPost {
		var report agentproto.Report
		_ = json.NewDecoder(r.Body).Decode(&report)
		s.reports = append(s.reports, report)
		_ = json.NewEncoder(w).Encode(agentproto.ReportResponse{})
		return
	}
	s.lastSession, s.lastDelivery = r.Header.Get(agentproto.ConfigSessionHeader), r.Header.Get(agentproto.ConfigDeliveryHeader)
	if s.status != 0 {
		w.WriteHeader(s.status)
		return
	}
	state := s.state
	delivery := ""
	if !s.retired {
		delivery = s.delivery
		state.ConfigDelivery = &agentproto.ConfigDelivery{ID: delivery, Session: s.lastSession}
		if s.foreign {
			state.ConfigDelivery.Session = "another-session"
		}
	}
	etag := `"` + state.Revision + `"`
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag && s.lastDelivery == delivery {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_ = json.NewEncoder(w).Encode(state)
}

func configClient(t *testing.T, offline bool) (*Client, *configurationServer) {
	t.Helper()
	s := &configurationServer{delivery: "delivery-one", state: agentproto.State{Revision: "state-one", ConfigRevision: "structure-one", Node: spec.Node{ID: "node"}}}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("test-token"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{URL: srv.URL, TokenFile: file}
	if offline {
		cfg.OfflineMaxAge = time.Hour
	}
	c, err := New(cfg, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	return c, s
}

func consumeConfig(t *testing.T, c *Client, changed bool) panel.ConfigState {
	t.Helper()
	if _, moved, err := c.Node(context.Background()); err != nil || moved != changed {
		t.Fatal("node", moved, err)
	}
	if _, moved, err := c.Users(context.Background()); err != nil || moved != changed {
		t.Fatal("users", moved, err)
	}
	if _, moved, err := c.Forwards(context.Background()); err != nil || moved != changed {
		t.Fatal("forwards", moved, err)
	}
	_, n, f := c.ConsumedConfig()
	if n != f {
		t.Fatal("incoherent consumed fixture", n, f)
	}
	return n
}

func TestConfigSessionHeadersAndStableDelivery304(t *testing.T) {
	c, s := configClient(t, false)
	first := consumeConfig(t, c, true)
	if !first.Valid() || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(first.Session) {
		t.Fatal(first)
	}
	if got := consumeConfig(t, c, false); got != first {
		t.Fatal(got)
	}
	s.mu.Lock()
	if s.lastSession != first.Session || s.lastDelivery != first.DeliveryID {
		t.Fatal("missing session/delivery request headers")
	}
	s.mu.Unlock()
	second, err := New(c.cfg, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if second.configSession == c.configSession {
		t.Fatal("new process reused configuration session")
	}
	consumeConfig(t, second, true)
}

func TestConfigNewDeliveryAndRetirementConsumeUnchangedRevision(t *testing.T) {
	c, s := configClient(t, false)
	consumeConfig(t, c, true)
	s.mu.Lock()
	s.delivery = "delivery-two"
	s.mu.Unlock()
	if got := consumeConfig(t, c, true); got.DeliveryID != "delivery-two" || got.StateRevision != "state-one" {
		t.Fatal(got)
	}
	s.mu.Lock()
	s.retired = true
	s.mu.Unlock()
	if got := consumeConfig(t, c, true); got.Valid() || got.DeliveryID != "" {
		t.Fatal("retired metadata survived", got)
	}
	consumeConfig(t, c, false)
}

func TestConfigConsumedTuplesNeverBorrowWatcherOrMixedUsers(t *testing.T) {
	c, s := configClient(t, false)
	first := consumeConfig(t, c, true)
	s.mu.Lock()
	s.state.Revision, s.delivery = "state-two", "delivery-two"
	s.mu.Unlock()
	if _, err := c.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, n, f := c.ConsumedConfig()
	if n != first || f != first {
		t.Fatal("watch advanced consumed metadata")
	}
	_, _, _ = c.Users(context.Background())
	_, n, f = c.ConsumedConfig()
	if n.Valid() || f != first {
		t.Fatal("mixed user snapshot confirmed configuration", n, f)
	}
	_, _, _ = c.Forwards(context.Background())
	_, n, f = c.ConsumedConfig()
	if n.Valid() || f.DeliveryID != "delivery-two" {
		t.Fatal(n, f)
	}
	_, _, _ = c.Node(context.Background())
	_, n, f = c.ConsumedConfig()
	if !n.Valid() || n != f || n.ConfigRevision != first.ConfigRevision {
		t.Fatal("dynamic state could not converge", n, f)
	}
}

func TestConfigReportPreservesFrozenReceiptDespiteWatcher(t *testing.T) {
	c, s := configClient(t, false)
	first := consumeConfig(t, c, true)
	r := &agentproto.ConfigReceipt{DeliveryID: first.DeliveryID, Session: first.Session, ConfigRevision: first.ConfigRevision, StateRevision: first.StateRevision, Sequence: 7, ObservedAt: time.Now().UTC(), Applied: true}
	s.mu.Lock()
	s.state.Revision, s.delivery = "new-state", "new-delivery"
	s.mu.Unlock()
	if _, err := c.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := c.Report(context.Background(), agentproto.Report{ConfigReceipt: r}); err != nil {
			t.Fatal(err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, report := range s.reports {
		if report.Revision != "new-state" || !reflect.DeepEqual(report.ConfigReceipt, r) {
			t.Fatal("watcher or HTTP retry rewrote observed receipt", report.ConfigReceipt)
		}
	}
}

func TestConfigOfflineSnapshotCannotDeliverForNewSession(t *testing.T) {
	c, s := configClient(t, true)
	first := consumeConfig(t, c, true)
	raw, err := os.ReadFile(filepath.Join(c.snapshotDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var signed signedSnapshot
	var snapshot offlineSnapshot
	if json.Unmarshal(raw, &signed) != nil || json.Unmarshal(signed.Payload, &snapshot) != nil {
		t.Fatal("invalid snapshot fixture")
	}
	if snapshot.State.ConfigDelivery != nil {
		t.Fatal("delivery persisted for replay")
	}
	s.mu.Lock()
	s.status = 503
	s.mu.Unlock()
	restarted, err := New(c.cfg, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if got := consumeConfig(t, restarted, true); got.Valid() || got.DeliveryID != "" {
		t.Fatal("cached delivery was confirmed", got)
	}
	s.mu.Lock()
	s.status = 0
	s.mu.Unlock()
	got := consumeConfig(t, restarted, true)
	if !got.Valid() || got.Session == first.Session {
		t.Fatal("fresh delivery did not bind the new process", got)
	}
}

func TestConfigForeignSessionAndRevocationNeverConfirm(t *testing.T) {
	c, s := configClient(t, false)
	s.mu.Lock()
	s.foreign = true
	s.mu.Unlock()
	if got := consumeConfig(t, c, true); got.Valid() {
		t.Fatal("foreign session accepted")
	}
	s.mu.Lock()
	s.foreign = false
	s.mu.Unlock()
	if got := consumeConfig(t, c, true); !got.Valid() {
		t.Fatal("valid metadata was not consumed")
	}
	c.revokeLease()
	if c.ServiceLeaseError() != nil {
		t.Fatal("default service policy changed without offline lease")
	}
	_, n, f := c.ConsumedConfig()
	if n.Valid() || f.Valid() {
		t.Fatal("rejected token retained configuration evidence")
	}
	if got := consumeConfig(t, c, false); !got.Valid() {
		t.Fatal("fresh authorized revalidation did not recover")
	}
}
