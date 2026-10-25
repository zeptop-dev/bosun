package agent

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

type revisionPanel struct {
	nopDriver
	nodeRevision, forwardRevision string
	forwardError                  error
	forwards                      []spec.Forward
}

func (p *revisionPanel) ConsumedRevisions() (string, string) {
	return p.nodeRevision, p.forwardRevision
}
func (p *revisionPanel) Forwards(context.Context) ([]spec.Forward, bool, error) {
	return p.forwards, true, p.forwardError
}
func (*revisionPanel) Report(context.Context, agentproto.Report) (bool, error) { return false, nil }

func revisionRig(t *testing.T) (*Agent, *revisionPanel, *lifecycleCounter) {
	t.Helper()
	p := &revisionPanel{nodeRevision: "first", forwardRevision: "first"}
	c := &lifecycleCounter{fakeCore: fakeCore{name: "singbox", protos: []spec.Protocol{spec.VLESS}}}
	reg := core.NewRegistry()
	reg.Register(c)
	a := New(&config.Config{DataDir: t.TempDir()}, p, reg, nil, slog.Default())
	a.node = &spec.Node{Inbounds: []spec.Inbound{{Tag: "listener", Protocol: spec.VLESS, Port: 443}}}
	return a, p, c
}
func appliedRevision(t *testing.T, a *Agent, want string) {
	t.Helper()
	if got := a.buildReport(nil, spec.SystemStatus{}).AppliedRevision; got != want {
		t.Fatalf("applied revision = %q, want %q", got, want)
	}
}
func applyRevision(t *testing.T, a *Agent) {
	t.Helper()
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.applyForwards(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAppliedRevisionRequiresBothPathsAndDoesNotSurviveRestart(t *testing.T) {
	a, p, _ := revisionRig(t)
	appliedRevision(t, a, "")
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	appliedRevision(t, a, "")
	if err := a.applyForwards(context.Background()); err != nil {
		t.Fatal(err)
	}
	appliedRevision(t, a, "first")
	// A newer forward revision must not borrow the old core confirmation.
	p.forwardRevision = "second"
	if err := a.applyForwards(context.Background()); err != nil {
		t.Fatal(err)
	}
	appliedRevision(t, a, "")
	p.nodeRevision = "second"
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	appliedRevision(t, a, "second")
	restarted := New(a.cfg, p, a.reg, nil, slog.Default())
	appliedRevision(t, restarted, "")
}

func TestAppliedRevisionClearsBeforeEarlyCheckpointFailure(t *testing.T) {
	a, p, c := revisionRig(t)
	applyRevision(t, a)
	appliedRevision(t, a, "first")
	p.nodeRevision, p.forwardRevision = "second", "second"
	a.node.Inbounds[0].Port = 8443
	c.statsErr = errors.New("stats unavailable before reconfiguration")
	if err := a.apply(context.Background()); err == nil {
		t.Fatal("expected checkpoint failure")
	}
	// Reproduce the original false-green condition: the old process/tag is
	// still running, yet the new listening port has not been applied.
	if !c.Running() || len(a.CoreStatus()["singbox"].Inbounds) != 1 {
		t.Fatal("test did not preserve the previously applied core")
	}
	if err := a.applyForwards(context.Background()); err != nil {
		t.Fatal(err)
	}
	appliedRevision(t, a, "")
	c.statsErr = nil
	applyRevision(t, a)
	appliedRevision(t, a, "second")
}

func TestAppliedRevisionDoesNotAcknowledgePartialCoreOrForwardFailure(t *testing.T) {
	a, p, _ := revisionRig(t)
	second := &fakeCore{name: "xray", protos: []spec.Protocol{spec.Trojan}}
	a.reg.Register(second)
	a.node.Inbounds = append(a.node.Inbounds, spec.Inbound{Tag: "other", Protocol: spec.Trojan, Port: 8443})
	applyRevision(t, a)
	appliedRevision(t, a, "first")
	second.fail = errors.New("one core failed")
	if err := a.apply(context.Background()); err == nil {
		t.Fatal("expected partial apply failure")
	}
	if err := a.applyForwards(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !a.dirty {
		t.Fatal("successful forwards cleared the pending core retry")
	}
	appliedRevision(t, a, "")
	second.fail = nil
	applyRevision(t, a)
	for _, failure := range []string{"read", "backend"} {
		t.Run(failure, func(t *testing.T) {
			if failure == "read" {
				p.forwardError = errors.New("forward source unavailable")
			} else {
				p.forwards = []spec.Forward{{Tag: "bad", Port: 18443, Protocol: "tcp", Target: "192.0.2.10:443", Backend: "realm"}}
			}
			if err := a.applyForwards(context.Background()); err == nil {
				t.Fatal("expected forward failure")
			}
			appliedRevision(t, a, "")
			if !a.dirty {
				t.Fatal("forward failure must be retried")
			}
			failedAt := a.lastForwardAttempt
			// WG/certificate reconciliation applies only cores. It must not
			// erase or starve the failed-forward retry and acknowledgment.
			if err := a.apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			appliedRevision(t, a, "")
			if !a.dirty || !a.applyRetryDue(failedAt.Add(retryFloor+time.Second)) {
				t.Fatal("core-only apply lost the forward retry")
			}
			p.forwardError, p.forwards = nil, nil
			applyRevision(t, a)
			appliedRevision(t, a, "first")
		})
	}
	a.fwd.Stop()
}

func TestAppliedRevisionClearsForModeChangeAndMixedPull(t *testing.T) {
	a, p, _ := revisionRig(t)
	applyRevision(t, a)
	a.modeChanging.Store(true)
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.applyForwards(context.Background()); err != nil {
		t.Fatal(err)
	}
	appliedRevision(t, a, "")
	a.modeChanging.Store(false)
	applyRevision(t, a)
	// Captain returns no node/users revision for a watcher update between
	// those accessors; successfully applying that mixture proves no revision.
	p.nodeRevision = ""
	applyRevision(t, a)
	appliedRevision(t, a, "")
}

func TestAppliedRevisionDoesNotClaimUserlessInboundIsListening(t *testing.T) {
	a, _, _ := revisionRig(t)
	mita := &fakeCore{name: "mita", protos: []spec.Protocol{spec.Mieru}}
	a.reg.Register(mita)
	a.node.Inbounds = append(a.node.Inbounds, spec.Inbound{Tag: "waiting", Protocol: spec.Mieru, Port: 8443})
	applyRevision(t, a)
	appliedRevision(t, a, "first")
	state := a.buildReport(nil, spec.SystemStatus{}).Cores["mita"]
	if state.Running || len(state.Inbounds) != 0 || a.Status().Skipped["waiting"] == "" {
		t.Fatal("configuration acknowledgment must preserve the idle listener's distinct runtime state", state)
	}
}

func TestAppliedRevisionRevokedForCoreActivationAndRollback(t *testing.T) {
	for _, fail := range []bool{false, true} {
		a, _, next, req := coreChangeRig(t)
		a.setAppliedCoreRevision("first")
		a.setAppliedForwardRevision("first")
		if fail {
			next.fail = errors.New("replacement cannot start")
		}
		err := a.activateCore(context.Background(), context.Background(), req)
		if (err != nil) != fail {
			t.Fatalf("activation failure = %v, want %v", err, fail)
		}
		appliedRevision(t, a, "")
		select {
		case <-a.kick:
		default:
			t.Fatal("activation/rollback must schedule complete re-application")
		}
	}
}
