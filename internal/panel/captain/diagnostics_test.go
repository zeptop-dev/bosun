package captain

import (
	"context"
	"encoding/json"
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

	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func diagnosticsClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("diagnostic-test-token"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{URL: srv.URL, TokenFile: file, OfflineMaxAge: time.Hour}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func diagnosticControl(r *http.Request, epoch string, generation uint64, remaining int64) *agentproto.DiagnosticsControl {
	// Only candidate commands carry a challenge; active and stopped commands
	// from Captain have an empty challenge after the process proves possession.
	return &agentproto.DiagnosticsControl{Session: r.Header.Get(agentproto.ConfigSessionHeader), RequestNonce: r.Header.Get(agentproto.DiagnosticsNonceHeader), Epoch: epoch, Generation: generation, RemainingMS: remaining, IntervalMS: 1000}
}
func diagnosticStateResponse(w http.ResponseWriter, r *http.Request, command *agentproto.DiagnosticsControl) {
	w.Header().Set("ETag", "same-revision")
	json.NewEncoder(w).Encode(agentproto.State{Revision: "same-revision", ConfigRevision: "cfg1-test", ConfigDelivery: &agentproto.ConfigDelivery{ID: "delivery", Session: r.Header.Get(agentproto.ConfigSessionHeader)}, Node: spec.Node{ID: "1", ServiceControl: &spec.ServiceControl{Mode: spec.ServiceControlPause}}, Diagnostics: command})
}
func awaitDiagnostic(t *testing.T, samples <-chan agentproto.DiagnosticsSample) agentproto.DiagnosticsSample {
	t.Helper()
	select {
	case s := <-samples:
		return s
	case <-time.After(4 * time.Second):
		t.Fatal("missing diagnostic sample")
		return agentproto.DiagnosticsSample{}
	}
}

func TestDiagnosticsMetadataDoesNotApplyOrPersist(t *testing.T) {
	var generation atomic.Uint64
	generation.Store(1)
	var posts atomic.Int32
	c := diagnosticsClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			posts.Add(1)
			w.WriteHeader(204)
			return
		}
		if r.Header.Get(agentproto.DiagnosticsVersionHeader) != "1" || r.Header.Get(agentproto.DiagnosticsNonceHeader) == "" {
			t.Error("missing negotiation headers")
		}
		if generation.Load() > 1 && (r.Header.Get(agentproto.DiagnosticsChallengeHeader) != "challenge" || r.Header.Get(agentproto.DiagnosticsCursorHeader) != "epoch:1") {
			t.Error("challenge-only cursor was not echoed")
		}
		control := diagnosticControl(r, "epoch", generation.Load(), 0)
		if generation.Load() == 1 {
			control.Challenge = "challenge"
		}
		diagnosticStateResponse(w, r, control)
	})
	ctx := context.Background()
	if _, moved, err := c.Node(ctx); err != nil || !moved {
		t.Fatalf("initial: %v %v", moved, err)
	}
	before, err := os.ReadFile(filepath.Join(c.snapshotDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	generation.Store(2)
	if _, moved, err := c.Node(ctx); err != nil || moved {
		t.Fatalf("metadata reapplied configuration: %v %v", moved, err)
	}
	after, err := os.ReadFile(filepath.Join(c.snapshotDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("metadata rewrote offline snapshot")
	}
	if c.State().Diagnostics != nil || strings.Contains(string(after), "diagnostics") {
		t.Fatal("transient lease entered persistent/cached state")
	}
	if posts.Load() != 0 {
		t.Fatal("challenge-only control sampled")
	}
}

func TestDiagnosticsCandidateHandshakeAcceptsEmptyActiveAndStopChallenge(t *testing.T) {
	var requests, posts atomic.Int32
	samples := make(chan agentproto.DiagnosticsSample, 4)
	c := diagnosticsClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts.Add(1)
			var sample agentproto.DiagnosticsSample
			if err := json.NewDecoder(r.Body).Decode(&sample); err != nil {
				t.Error(err)
			}
			samples <- sample
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var control *agentproto.DiagnosticsControl
		switch requests.Add(1) {
		case 1:
			if r.Header.Get(agentproto.DiagnosticsChallengeHeader) != "" || r.Header.Get(agentproto.DiagnosticsCursorHeader) != "" {
				t.Error("first request carried an unissued challenge or cursor")
			}
			control = diagnosticControl(r, "candidate", 1, 0)
			control.Challenge = "candidate-challenge"
		case 2:
			if r.Header.Get(agentproto.DiagnosticsChallengeHeader) != "candidate-challenge" || r.Header.Get(agentproto.DiagnosticsCursorHeader) != "candidate:1" {
				t.Error("candidate challenge and cursor were not echoed")
			}
			control = diagnosticControl(r, "active", 3, 5000)
		case 3:
			if r.Header.Get(agentproto.DiagnosticsChallengeHeader) != "" || r.Header.Get(agentproto.DiagnosticsCursorHeader) != "active:3" {
				t.Error("activated process retained a consumed challenge or lost its cursor")
			}
			control = diagnosticControl(r, "stopped", 4, 0)
		default:
			t.Error("unexpected state request")
		}
		diagnosticStateResponse(w, r, control)
	})
	if moved, err := c.fetch(context.Background()); err != nil || !moved {
		t.Fatal("candidate state failed", moved, err)
	}
	c.mu.Lock()
	candidateIdle := c.diagnostics.deadline.IsZero() && c.diagnostics.wake == nil
	c.mu.Unlock()
	if !candidateIdle || posts.Load() != 0 {
		t.Fatal("challenge-only candidate started sampling")
	}
	if moved, err := c.fetch(context.Background()); err != nil || moved {
		t.Fatal("active metadata reapplied configuration", moved, err)
	}
	sample := awaitDiagnostic(t, samples)
	if sample.Epoch != "active" || sample.Sequence != 1 || sample.CPUPercent != nil || sample.NetUpBytesPerSecond != nil || sample.NetDownBytesPerSecond != nil {
		t.Fatal("empty-challenge activation did not start a fresh epoch", sample)
	}
	if moved, err := c.fetch(context.Background()); err != nil || moved {
		t.Fatal("stop metadata reapplied configuration", moved, err)
	}
	c.mu.Lock()
	stopped := c.diagnostics.deadline.IsZero() && c.diagnostics.challenge == "" && c.diagnostics.cursor == "stopped:4"
	c.mu.Unlock()
	if !stopped {
		t.Fatal("empty-challenge stop was not accepted and acknowledged")
	}
	select {
	case <-samples:
		t.Fatal("stopped process sent another sample")
	case <-time.After(1100 * time.Millisecond):
	}
}

func TestDiagnosticsCommandFreshnessAndOrdering(t *testing.T) {
	// A pre-created wake channel suppresses the worker: this test exercises the
	// protocol clock and request ordering independently from OS sampling.
	c := &Client{configSession: "session", diagnostics: diagnosticState{wake: make(chan struct{}, 1)}}
	now := time.Now()
	request := func(order uint64, started time.Time) diagnosticRequest {
		return diagnosticRequest{order: order, started: started, session: "session", nonce: "nonce"}
	}
	command := func(generation uint64) *agentproto.DiagnosticsControl {
		return &agentproto.DiagnosticsControl{Session: "session", RequestNonce: "nonce", Epoch: "epoch", Generation: generation, RemainingMS: 15000, IntervalMS: 1000}
	}
	if c.acceptDiagnosticsLocked(request(1, now.Add(-11*time.Second)), command(1), now) != true || c.diagnostics.cursor != "" || !c.diagnostics.deadline.IsZero() {
		t.Fatal("late command acknowledged or activated")
	}
	start := now.Add(-2 * time.Second)
	c.acceptDiagnosticsLocked(request(2, start), command(1), now)
	deadline := start.Add(15 * time.Second)
	if !c.diagnostics.deadline.Equal(deadline) {
		t.Fatal("lease measured from response arrival")
	}
	c.acceptDiagnosticsLocked(request(3, now), command(1), now)
	if !c.diagnostics.deadline.Equal(deadline) {
		t.Fatal("same generation renewed lease")
	}
	c.acceptDiagnosticsLocked(request(4, now), command(2), now)
	renewed := c.diagnostics.deadline
	older := command(3)
	older.Epoch = "old-epoch"
	c.acceptDiagnosticsLocked(request(3, now), older, now)
	if c.diagnostics.epoch != "epoch" || !c.diagnostics.deadline.Equal(renewed) {
		t.Fatal("out-of-order response replaced lease")
	}
	stopped := command(2)
	stopped.RemainingMS = 0
	c.acceptDiagnosticsLocked(request(5, now), stopped, now)
	if !c.diagnostics.deadline.Equal(renewed) {
		t.Fatal("same-generation replay changed the lease")
	}
	stopped.Generation = 3
	c.acceptDiagnosticsLocked(request(6, now), stopped, now)
	if !c.diagnostics.deadline.IsZero() {
		t.Fatal("new stop generation did not stop")
	}
	c.authGeneration++
	c.stopDiagnosticsLocked()
	c.acceptDiagnosticsLocked(request(7, now), command(4), now)
	if !c.diagnostics.deadline.IsZero() {
		t.Fatal("pre-revocation response restarted lease")
	}
}

func TestDiagnosticsRejectsForeignOrInvalidControls(t *testing.T) {
	for _, kind := range []string{"nonce", "session", "oversized", "interval", "expired", "invalid header"} {
		t.Run(kind, func(t *testing.T) {
			c := &Client{configSession: "session", diagnostics: diagnosticState{wake: make(chan struct{}, 1)}}
			now := time.Now()
			r := diagnosticRequest{order: 1, started: now.Add(-time.Second), nonce: "nonce", session: "session"}
			command := &agentproto.DiagnosticsControl{Session: "session", RequestNonce: "nonce", Epoch: "epoch", Generation: 1, RemainingMS: 15000, IntervalMS: 1000}
			switch kind {
			case "nonce":
				command.RequestNonce = "other"
			case "session":
				command.Session = "other"
			case "oversized":
				command.RemainingMS++
			case "interval":
				command.IntervalMS = 1
			case "expired":
				command.RemainingMS = 500
			case "invalid header":
				command.Challenge = "bad\x00header"
			}
			c.acceptDiagnosticsLocked(r, command, now)
			if !c.diagnostics.deadline.IsZero() {
				t.Fatal("invalid command activated")
			}
		})
	}
}

func TestDiagnosticsAgedResponseImmediatelyRefetchesWithoutAcknowledgement(t *testing.T) {
	var requests, posts atomic.Int32
	c := diagnosticsClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			posts.Add(1)
			w.WriteHeader(204)
			return
		}
		if requests.Add(1) == 1 {
			diagnosticStateResponse(w, r, diagnosticControl(r, "too-old", 1, 15000))
			return
		}
		if r.URL.RawQuery != "" || r.Header.Get(agentproto.DiagnosticsCursorHeader) != "" || r.Header.Get(agentproto.DiagnosticsChallengeHeader) != "" {
			t.Error("stale command was acknowledged or refetch still long-polled")
		}
		diagnosticStateResponse(w, r, diagnosticControl(r, "fresh", 2, 0))
	})
	base := time.Now()
	read := 0
	c.diagnostics.now = func() time.Time {
		offsets := []time.Duration{0, 11 * time.Second, 12 * time.Second, 12 * time.Second}
		v := base.Add(offsets[read])
		read++
		return v
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if moved, err := c.fetchWait(ctx, "30s"); err != nil || !moved {
		t.Fatal("fresh refetch failed", moved, err)
	}
	if requests.Load() != 2 || posts.Load() != 0 {
		t.Fatal("late active command sampled or was not refetched")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.diagnostics.cursor != "fresh:2" || !c.diagnostics.deadline.IsZero() {
		t.Fatal("fresh stop control did not supersede ignored response")
	}
}

func TestDiagnosticsSlowMetadataCannotBlockConfigurationForever(t *testing.T) {
	var requests atomic.Int32
	c := diagnosticsClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		diagnosticStateResponse(w, r, diagnosticControl(r, "late", 1, 0))
	})
	base := time.Now()
	read := 0
	c.diagnostics.now = func() time.Time { v := base.Add(time.Duration(read) * 11 * time.Second); read++; return v }
	if moved, err := c.fetch(context.Background()); err != nil || !moved {
		t.Fatal("normal state lost to diagnostics retry", moved, err)
	}
	if requests.Load() != 2 || c.State().Revision != "same-revision" || c.diagnostics.cursor != "" {
		t.Fatal("slow diagnostic metadata was not bounded")
	}
}

func TestDiagnosticsSameEpochResumeKeepsSequenceAndResetsRates(t *testing.T) {
	for _, stop := range []string{"expiry", "command"} {
		t.Run(stop, func(t *testing.T) {
			var generation atomic.Uint64
			generation.Store(1)
			var remaining atomic.Int64
			remaining.Store(250)
			samples := make(chan agentproto.DiagnosticsSample, 16)
			c := diagnosticsClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					diagnosticStateResponse(w, r, diagnosticControl(r, "same-worker", generation.Load(), remaining.Load()))
					return
				}
				var sample agentproto.DiagnosticsSample
				json.NewDecoder(r.Body).Decode(&sample)
				samples <- sample
				w.WriteHeader(204)
			})
			if _, err := c.fetch(context.Background()); err != nil {
				t.Fatal(err)
			}
			first := awaitDiagnostic(t, samples)
			if stop == "expiry" {
				time.Sleep(350 * time.Millisecond)
			} else {
				generation.Store(2)
				remaining.Store(0)
				if _, err := c.fetch(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			generation.Store(3)
			remaining.Store(3000)
			if _, err := c.fetch(context.Background()); err != nil {
				t.Fatal(err)
			}
			resumed := awaitDiagnostic(t, samples)
			if resumed.Epoch != first.Epoch || resumed.Sequence <= first.Sequence || resumed.CPUPercent != nil || resumed.NetUpBytesPerSecond != nil || resumed.NetDownBytesPerSecond != nil {
				t.Fatal("same-epoch resume reset sequence or retained stale baseline", resumed)
			}
		})
	}
}

func TestDiagnosticsWorkerRenewalEpochAndIndependentMonitoring(t *testing.T) {
	var generation atomic.Uint64
	generation.Store(1)
	var newEpoch atomic.Bool
	samples := make(chan agentproto.DiagnosticsSample, 32)
	c := diagnosticsClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			epoch := "epoch"
			if newEpoch.Load() {
				epoch = "second"
			}
			diagnosticStateResponse(w, r, diagnosticControl(r, epoch, generation.Load(), 5000))
			return
		}
		if r.URL.Path != "/api/agent/diagnostics" {
			t.Errorf("diagnostic worker used %s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		if len(raw) > 8192 {
			t.Error("oversized sample")
		}
		var sample agentproto.DiagnosticsSample
		if err := json.Unmarshal(raw, &sample); err != nil {
			t.Error(err)
		}
		samples <- sample
		w.WriteHeader(204)
	})
	if _, _, err := c.Node(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := awaitDiagnostic(t, samples)
	if first.Sequence != 1 || first.CPUPercent != nil || first.NetUpBytesPerSecond != nil || first.NetDownBytesPerSecond != nil {
		t.Fatal("first sample invented rates", first)
	}
	generation.Store(2)
	if _, moved, err := c.Node(context.Background()); err != nil || moved {
		t.Fatal("renewal changed configuration", moved, err)
	}
	second := awaitDiagnostic(t, samples)
	if second.Epoch != first.Epoch || second.Sequence <= first.Sequence {
		t.Fatal("renewal reset sequence", second)
	}
	newEpoch.Store(true)
	generation.Store(3)
	if _, _, err := c.Node(context.Background()); err != nil {
		t.Fatal(err)
	}
	third := awaitDiagnostic(t, samples)
	if third.Epoch != "second" || third.Sequence != 1 || third.NetUpBytesPerSecond != nil || third.CPUPercent != nil {
		t.Fatal("epoch retained old baseline", third)
	}
	// The fixture has ServiceControlPause and no Probe configuration throughout.
	if c.State().Probe != nil || c.State().Node.ServiceControl.Mode != spec.ServiceControlPause {
		t.Fatal("fixture did not exercise independent passive monitoring")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-samples:
		t.Fatal("sample queued after close")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestDiagnosticsSlowPostDoesNotCatchUpOrOutliveLease(t *testing.T) {
	for _, expires := range []bool{false, true} {
		t.Run(map[bool]string{false: "arrival budget", true: "expiry during cooldown"}[expires], func(t *testing.T) {
			type arrival struct {
				at     time.Time
				sample agentproto.DiagnosticsSample
			}
			arrivals := make(chan arrival, 8)
			var posts atomic.Int32
			c := diagnosticsClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					remaining := int64(5000)
					if expires {
						remaining = 1400
					}
					diagnosticStateResponse(w, r, diagnosticControl(r, "epoch", 1, remaining))
					return
				}
				var sample agentproto.DiagnosticsSample
				if err := json.NewDecoder(r.Body).Decode(&sample); err != nil {
					t.Error(err)
				}
				if posts.Add(1) == 1 {
					// Simulate upstream transit within the two-second POST budget.
					// The next scheduled one-second tick passes before acceptance.
					timer := time.NewTimer(1100 * time.Millisecond)
					defer timer.Stop()
					select {
					case <-timer.C:
					case <-r.Context().Done():
						return
					}
				}
				arrivals <- arrival{at: time.Now(), sample: sample}
				w.WriteHeader(http.StatusNoContent)
			})
			if _, err := c.fetch(context.Background()); err != nil {
				t.Fatal(err)
			}
			var first arrival
			select {
			case first = <-arrivals:
			case <-time.After(3 * time.Second):
				t.Fatal("slow sample was not accepted before its deadline")
			}
			if expires {
				select {
				case <-arrivals:
					t.Fatal("worker sent a catch-up sample instead of waiting through lease expiry")
				case <-time.After(800 * time.Millisecond):
				}
				return
			}
			select {
			case second := <-arrivals:
				if spacing := second.at.Sub(first.at); spacing < 500*time.Millisecond {
					t.Fatalf("slow POST caused arrival burst within Captain's budget: %v", spacing)
				}
				if second.sample.Sequence != first.sample.Sequence+1 || second.sample.ElapsedMS < 1500 {
					t.Fatal("slow POST queued a stale sample or lost actual elapsed time", second.sample)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("slow successful POST stopped an otherwise active lease")
			}
		})
	}
}

func TestDiagnosticsWorkerExpiresAndRevokesInFlight(t *testing.T) {
	for _, stop := range []string{"expiry", "revoke", "offline"} {
		t.Run(stop, func(t *testing.T) {
			started, finished := make(chan struct{}, 1), make(chan struct{}, 1)
			var code atomic.Int32
			code.Store(200)
			c := diagnosticsClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					if code.Load() != 200 {
						w.WriteHeader(int(code.Load()))
						return
					}
					remaining := int64(5000)
					if stop == "expiry" {
						remaining = 300
					}
					diagnosticStateResponse(w, r, diagnosticControl(r, "epoch", 1, remaining))
					return
				}
				started <- struct{}{}
				io.Copy(io.Discard, r.Body)
				<-r.Context().Done()
				finished <- struct{}{}
			})
			if _, _, err := c.Node(context.Background()); err != nil {
				t.Fatal(err)
			}
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("worker did not send")
			}
			switch stop {
			case "revoke":
				code.Store(401)
				_, _, _ = c.Node(context.Background())
			case "offline":
				code.Store(503)
				_, _, _ = c.Node(context.Background())
			}
			select {
			case <-finished:
			case <-time.After(3 * time.Second):
				t.Fatal("in-flight diagnostics survived stop")
			}
			select {
			case <-started:
				t.Fatal("stopped worker queued another sample")
			case <-time.After(1100 * time.Millisecond):
			}
		})
	}
}

func TestDiagnosticsLateStateCannotReplaceNewerOrRevokedLease(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "newer", true: "revoked"}[revoke], func(t *testing.T) {
			firstStarted, release := make(chan struct{}), make(chan struct{})
			var requests atomic.Int32
			c := diagnosticsClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					w.WriteHeader(204)
					return
				}
				if requests.Add(1) == 1 {
					close(firstStarted)
					<-release
					json.NewEncoder(w).Encode(agentproto.State{Revision: "old-state", Node: spec.Node{ID: "1"}, Diagnostics: diagnosticControl(r, "old", 1, 15000)})
					return
				}
				if revoke {
					w.WriteHeader(401)
					return
				}
				diagnosticStateResponse(w, r, diagnosticControl(r, "new", 2, 15000))
			})
			firstDone := make(chan error, 1)
			go func() { _, err := c.fetch(context.Background()); firstDone <- err }()
			<-firstStarted
			_, err := c.fetch(context.Background())
			if !revoke && err != nil {
				t.Fatal(err)
			}
			close(release)
			err = <-firstDone
			if revoke && err == nil {
				t.Fatal("pre-rejection state accepted")
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			if revoke {
				if !c.diagnostics.deadline.IsZero() {
					t.Fatal("late 200 resurrected lease")
				}
			} else if c.diagnostics.epoch != "new" {
				t.Fatal("older request replaced current diagnostics")
			}
			if !revoke && c.state.Revision != "same-revision" {
				t.Fatal("older request replaced current configuration")
			}
		})
	}
}

func TestDiagnosticsNewer304RejectsOlder200Control(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var requests atomic.Int32
	c := diagnosticsClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch requests.Add(1) {
		case 1:
			diagnosticStateResponse(w, r, diagnosticControl(r, "initial", 1, 0))
		case 2:
			close(started)
			<-release
			diagnosticStateResponse(w, r, diagnosticControl(r, "old-response", 2, 15000))
		default:
			w.WriteHeader(304)
		}
	})
	if _, err := c.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := c.fetch(context.Background()); done <- err }()
	<-started
	if _, err := c.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.diagnostics.epoch != "initial" || !c.diagnostics.deadline.IsZero() {
		t.Fatal("older 200 bypassed later 304 ordering")
	}
}
