package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/decoy"
	"github.com/zeptop-dev/bosun/internal/panel"
	"github.com/zeptop-dev/bosun/internal/servicecontrol"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

type configRevisionPanel struct {
	*revisionPanel
	node, forwards panel.ConfigState
	offline        bool
	leaseError     error
	users          []spec.User
	usersChanged   bool
}

func (p *configRevisionPanel) ConsumedConfig() (string, panel.ConfigState, panel.ConfigState) {
	return "process-session", p.node, p.forwards
}
func (p *configRevisionPanel) OfflineRecoveryActive() bool { return p.offline }
func (p *configRevisionPanel) ServiceLeaseError() error    { return p.leaseError }
func (p *configRevisionPanel) Users(context.Context) ([]spec.User, bool, error) {
	changed := p.usersChanged
	p.usersChanged = false
	return p.users, changed, nil
}
func (p *configRevisionPanel) advance(state, delivery string) {
	p.nodeRevision, p.forwardRevision = state, state
	p.node = panel.ConfigState{Session: "process-session", DeliveryID: delivery, ConfigRevision: "static-config", StateRevision: state, Online: true}
	p.forwards = p.node
}
func configRevisionRig(t *testing.T) (*Agent, *configRevisionPanel, *lifecycleCounter) {
	t.Helper()
	a, base, c := revisionRig(t)
	p := &configRevisionPanel{revisionPanel: base}
	p.advance("first", "delivery-one")
	a.driver = p
	return a, p, c
}
func expectConfigReceipt(t *testing.T, a *Agent, applied bool) *agentproto.ConfigReceipt {
	t.Helper()
	r := a.buildReport(nil, spec.SystemStatus{}).ConfigReceipt
	if r == nil || r.Applied != applied || r.Sequence == 0 || r.ObservedAt.IsZero() || r.ObservedAt.Location() != time.UTC {
		t.Fatal("unexpected configuration receipt", r)
	}
	return r
}

func TestConfigReceiptRequiresBothPathsAndNewDeliveryApplication(t *testing.T) {
	a, p, _ := configRevisionRig(t)
	first := expectConfigReceipt(t, a, false)
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	expectConfigReceipt(t, a, false)
	if err := a.applyForwards(context.Background()); err != nil {
		t.Fatal(err)
	}
	ready := expectConfigReceipt(t, a, true)
	if ready.Sequence <= first.Sequence {
		t.Fatal("observation sequence did not advance")
	}
	// A new attempt with identical state must not borrow the previous delivery.
	p.advance("first", "delivery-two")
	expectConfigReceipt(t, a, false)
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	expectConfigReceipt(t, a, false)
	if err := a.applyForwards(context.Background()); err != nil {
		t.Fatal(err)
	}
	expectConfigReceipt(t, a, true)
	restarted := New(a.cfg, p, a.reg, nil, a.log)
	expectConfigReceipt(t, restarted, false)
}

func TestConfigReceiptDynamicUserFailureCannotBorrowStructuralSuccess(t *testing.T) {
	a, p, c := configRevisionRig(t)
	applyRevision(t, a)
	old := expectConfigReceipt(t, a, true)
	p.advance("new-users", "new-delivery")
	a.users = []spec.User{{ID: 1, Name: "replacement"}}
	c.fail = errors.New("user update failed")
	if err := a.apply(context.Background()); err == nil {
		t.Fatal("fixture did not fail user update")
	}
	if err := a.applyForwards(context.Background()); err != nil {
		t.Fatal(err)
	}
	now := expectConfigReceipt(t, a, false)
	if now.ConfigRevision != old.ConfigRevision || now.StateRevision == old.StateRevision {
		t.Fatal("fixture did not preserve structural identity")
	}
	c.fail = nil
	applyRevision(t, a)
	expectConfigReceipt(t, a, true)
	p.forwardError = errors.New("forwards unavailable")
	if err := a.applyForwards(context.Background()); err == nil {
		t.Fatal("fixture did not fail forwards")
	}
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	expectConfigReceipt(t, a, false)
}

func TestConfigReceiptRejectsMixedOfflineAndForeignTuples(t *testing.T) {
	for _, kind := range []string{"mixed", "offline", "foreign", "revoked", "retired"} {
		t.Run(kind, func(t *testing.T) {
			a, p, _ := configRevisionRig(t)
			applyRevision(t, a)
			switch kind {
			case "mixed":
				p.forwards.DeliveryID = "different"
			case "offline":
				p.offline = true
			case "foreign":
				p.node.Session, p.forwards.Session = "foreign", "foreign"
			case "revoked":
				p.leaseError = errors.New("rejected")
			case "retired":
				p.node.DeliveryID, p.forwards.DeliveryID = "", ""
			}
			if r := a.buildReport(nil, spec.SystemStatus{}).ConfigReceipt; r != nil {
				t.Fatal("unsafe tuple emitted a receipt", r)
			}
		})
	}
}

func TestConfigReceiptSilentPartialApplyNeverGreen(t *testing.T) {
	for _, kind := range []string{"unsupported", "invalid", "certificate", "route", "limits", "scoped_limits"} {
		t.Run(kind, func(t *testing.T) {
			a, _, _ := configRevisionRig(t)
			switch kind {
			case "unsupported":
				a.node.Inbounds = append(a.node.Inbounds, spec.Inbound{Tag: "missing", Protocol: spec.Snell, Port: 8443, SnellPSK: "test-key"})
			case "invalid":
				a.node.Inbounds[0].Port = -1
			case "certificate":
				a.skipped = map[string]string{"listener": "certificate unavailable"}
			case "route":
				a.node.Routes = []spec.RouteRule{{Match: []string{"unknown:test"}, Action: "direct"}}
			case "limits":
				a.users = []spec.User{{ID: 1, Name: "limited", SpeedLimitMbps: 10}}
			case "scoped_limits":
				a.node.Inbounds[0].ScopedUsers = true
				a.node.Inbounds[0].Users = []spec.User{{ID: 2, Name: "scoped", SpeedLimitMbps: 10}}
			}
			applyRevision(t, a)
			appliedRevision(t, a, "first") // legacy behavior remains compatible
			expectConfigReceipt(t, a, false)
			applyRevision(t, a) // degraded in-memory users must not become falsely green
			expectConfigReceipt(t, a, false)
		})
	}
}

func TestConfigReceiptExpectedUserlessIdleIsNotAnApplyFailure(t *testing.T) {
	a, _, _ := configRevisionRig(t)
	a.reg.Register(&fakeCore{name: "mita", protos: []spec.Protocol{spec.Mieru}})
	a.node.Inbounds = append(a.node.Inbounds, spec.Inbound{Tag: "idle", Protocol: spec.Mieru, Port: 8443})
	applyRevision(t, a)
	expectConfigReceipt(t, a, true)
	if a.CoreStatus()["mita"].Running {
		t.Fatal("idle fixture unexpectedly listening")
	}
}

func TestConfigReceiptOmittedUserLimitNeedsFreshUsers(t *testing.T) {
	a, p, _ := configRevisionRig(t)
	a.users = []spec.User{{ID: 1, Name: "limited", SpeedLimitMbps: 10}}
	applyRevision(t, a)
	expectConfigReceipt(t, a, false)
	p.users, p.usersChanged = []spec.User{{ID: 1, Name: "unlimited"}}, true
	p.advance("fresh-users", "fresh-delivery")
	if moved, err := a.pull(context.Background()); err != nil || !moved {
		t.Fatal(moved, err)
	}
	applyRevision(t, a)
	expectConfigReceipt(t, a, true)
}

func TestConfigReceiptPauseAndLocalInvalidationsDoNotConfirmNewConfig(t *testing.T) {
	a, _, _ := configRevisionRig(t)
	applyRevision(t, a)
	expectConfigReceipt(t, a, true)
	a.modeChanging.Store(true)
	expectConfigReceipt(t, a, false)
	a.modeChanging.Store(false)
	a.ReloadCerts("")
	expectConfigReceipt(t, a, false)
	applyRevision(t, a)
	expectConfigReceipt(t, a, true)
	var script string
	fail := false
	a.ServiceControl = &servicecontrol.Manager{Dir: t.TempDir(), Run: serviceControlTestRunner(&script, &fail)}
	a.node.ServiceControl = &spec.ServiceControl{Revision: "paused", Mode: "pause"}
	applyRevision(t, a)
	expectConfigReceipt(t, a, false)
}

func TestConfigReceiptFrozenWithReportForTransportRetry(t *testing.T) {
	a, _, _ := configRevisionRig(t)
	applyRevision(t, a)
	full := a.buildReport(nil, spec.SystemStatus{})
	before := *full.ConfigReceipt
	transport := newReportTransport(context.Background())
	defer transport.close()
	p := &blockedReporter{make(chan agentproto.Report, 1), make(chan struct{})}
	if err := transport.sendReport(p, full); err != nil {
		t.Fatal(err)
	}
	full.ConfigReceipt.Sequence = 999
	full.ConfigReceipt.Applied = false
	received := <-p.received
	if received.ConfigReceipt == nil || *received.ConfigReceipt != before {
		t.Fatal("HTTP worker shared mutable observation", received.ConfigReceipt)
	}
	close(p.release)
	receiveDelivery(t, transport)
	if next := a.buildReport(nil, spec.SystemStatus{}).ConfigReceipt; next.Sequence <= before.Sequence {
		t.Fatal("new observation reused sequence")
	}
}

type configStopFailure struct {
	*lifecycleCounter
	stopError error
}

func (c *configStopFailure) Stop(ctx context.Context) error {
	if c.stopError != nil {
		return c.stopError
	}
	return c.lifecycleCounter.Stop(ctx)
}

func TestConfigReceiptMonitorNeedsSuccessfulEmptyCleanup(t *testing.T) {
	a, p, c := configRevisionRig(t)
	a.cfg.NodeMode = spec.NodeMonitor
	a.node = &spec.Node{Mode: spec.NodeMonitor}
	c.running = true
	stopping := &configStopFailure{lifecycleCounter: c, stopError: errors.New("cannot stop old core")}
	a.reg = core.NewRegistry()
	a.reg.Register(stopping)
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.applyForwards(context.Background()); err == nil {
		t.Fatal("failed monitor cleanup was accepted")
	}
	expectConfigReceipt(t, a, false)
	stopping.stopError = nil
	if err := a.applyForwards(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.Running() {
		t.Fatal("empty monitor state left a core running")
	}
	expectConfigReceipt(t, a, true)
	// A legacy empty mode preserves monitor safety, but cannot confirm a new
	// structural delivery that semantically defaults to full mode.
	a.node.Mode = ""
	applyRevision(t, a)
	expectConfigReceipt(t, a, false)
	a.node.Mode = spec.NodeMonitor
	p.revisionPanel.forwards = []spec.Forward{{Tag: "unexpected", Port: 8443, Protocol: "tcp", Target: "192.0.2.10:443"}}
	if err := a.applyForwards(context.Background()); !errors.Is(err, spec.ErrMonitorOnly) {
		t.Fatal("nonempty monitor forwarding was accepted", err)
	}
	expectConfigReceipt(t, a, false)
}

func TestConfigReceiptModeTransitionRequiresNewModeProcess(t *testing.T) {
	a, p, _ := configRevisionRig(t)
	applyRevision(t, a)
	p.advance("monitor-state", "monitor-delivery")
	a.node = &spec.Node{Mode: spec.NodeMonitor, ModeRevision: 1}
	a.ChangeMode = func(spec.NodeMode, uint64, string) error { return nil }
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.applyForwards(context.Background()); err != nil {
		t.Fatal(err)
	}
	expectConfigReceipt(t, a, false)
	if !a.modeChanging.Load() {
		t.Fatal("fixture did not enter mode transition")
	}
}

func TestConfigReceiptDecoyMustBeReadyOrActuallyDisabled(t *testing.T) {
	for _, kind := range []string{"missing_server", "certificate_disabled", "certificate_pending", "disabled_still_running"} {
		t.Run(kind, func(t *testing.T) {
			a, _, _ := configRevisionRig(t)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := ln.Addr().(*net.TCPAddr).Port
			_ = ln.Close()
			desired := &spec.Decoy{Domain: "example.com", Port: port}
			if kind != "missing_server" {
				a.Decoy = decoy.New(nil, a.log)
				t.Cleanup(a.Decoy.Stop)
				if kind != "certificate_disabled" {
					a.Decoy.TLSConfig = &tls.Config{}
				}
			}
			if kind != "disabled_still_running" {
				a.node.Decoy = desired
			}
			applyRevision(t, a)
			if kind == "disabled_still_running" {
				// An independently restarted old listener is not evidence that the
				// currently desired disabled configuration is still applied.
				a.Decoy.Configure(context.Background(), desired)
			}
			if kind == "certificate_pending" || kind == "disabled_still_running" {
				if st := a.Decoy.Status(); st == nil || !st.Running || st.CertReady {
					t.Fatal("invalid pending fixture", st)
				}
			}
			appliedRevision(t, a, "first")
			expectConfigReceipt(t, a, false)
			if a.Decoy != nil {
				a.node.Decoy = nil
				applyRevision(t, a)
				if a.Decoy.Status() != nil {
					t.Fatal("disabled decoy still configured")
				}
				expectConfigReceipt(t, a, true)
			}
		})
	}
}
