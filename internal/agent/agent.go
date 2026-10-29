// Package agent is the managed-mode control loop: pull desired state from the
// panel, render it onto cores, and push accounting back.
package agent

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"

	"github.com/zeptop-dev/bosun/internal/audit"

	"github.com/zeptop-dev/bosun/internal/connlog"

	"github.com/zeptop-dev/bosun/internal/egressguard"

	"log/slog"
	"sync"
	"time"

	"github.com/zeptop-dev/bosun/internal/doctor"
	"github.com/zeptop-dev/bosun/internal/probe"

	"github.com/zeptop-dev/bosun/internal/certs"
	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/coreinstall"
	"github.com/zeptop-dev/bosun/internal/decoy"
	"github.com/zeptop-dev/bosun/internal/firewall"
	"github.com/zeptop-dev/bosun/internal/forward"
	"github.com/zeptop-dev/bosun/internal/ingressguard"
	"github.com/zeptop-dev/bosun/internal/metrics"
	"github.com/zeptop-dev/bosun/internal/panel"
	"github.com/zeptop-dev/bosun/internal/servicecontrol"
	"github.com/zeptop-dev/bosun/internal/shaper"
	"github.com/zeptop-dev/bosun/internal/sysinfo"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Agent wires one panel driver to a core registry.
// retryFloor is the least time between retries of a failed apply.
const retryFloor = 30 * time.Second

type Agent struct {
	ChangeMode         func(spec.NodeMode, uint64, string) error
	modeChanging       atomic.Bool
	CoreManager        *coreinstall.Manager
	coreChanges        chan coreChange
	statsCollectionErr error
	cfg                *config.Config
	driver             panel.Driver
	reg                *core.Registry
	fwd                *forward.Manager
	metrics            *metrics.Registry
	log                *slog.Logger

	// started is when this process came up, so checks can tell "nothing
	// has happened yet" from "something stopped happening".
	started time.Time

	node  *spec.Node
	users []spec.User
	// userIDs maps spec.User.Name (the stats key) to the panel user ID.
	userIDs map[string]int64

	statusMu     sync.Mutex
	appliedCores map[string][]string // guarded by statusMu; successful last apply only
	status       Status
	// The two apply paths run separately. Only matching, successful consumed
	// revisions acknowledge the whole configuration; neither survives restart.
	appliedCoreRevision    string // guarded by statusMu
	appliedForwardRevision string // guarded by statusMu

	// Upgrade is called (in its own goroutine, once per requested version)
	// when the panel asks the node to move to another release.
	Upgrade      func(version string)
	upgradeAsked string
	// Rollback puts the previous binary back (the "rollback" node job);
	// it returns the version now installed and the agent restarts after
	// the result has been reported.
	Rollback func() (string, error)
	// Remove starts an external worker; only that worker reports completion.
	Remove func(context.Context, agentproto.Job) error

	// Certs obtains certificates for inbounds with auto_cert; nil disables.
	Certs *certs.Manager
	// Decoy serves the node's own HTTPS site for REALITY to steal; nil disables.
	Decoy *decoy.Server
	// Alert delivers an operator notification (Telegram); nil = none.
	Alert func(text string)
	// Shaper enforces per-user speed limits in the kernel; nil = none.
	ServiceControl        *servicecontrol.Manager
	serviceControlPending atomic.Bool
	Shaper                *shaper.Shaper
	wireGuard             *wireGuardRuntime
	wireGuardActive       atomic.Bool
	shaperMu              sync.Mutex
	// Realm runs forward rules with the realm backend; nil rejects them.
	Realm *forward.Realm
	// Guard drops packets for mita ports that arrive on the wrong local
	// address (mita cannot bind one itself); nil = not enforced.
	Guard *ingressguard.Guard
	// Egress keeps the core account away from private, metadata and
	// loopback ranges; nil = off. EgressAllow are the operator's
	// exemptions, EgressLoopbackPorts the local ports a core may reach
	// (DNS stub, hysteria's auth callback, the decoy site).
	Egress              *egressguard.Guard
	EgressAllow         []string
	EgressDisabled      bool
	EgressUpstreams     []spec.EgressUpstream
	EgressLoopbackPorts []int
	// EgressProtectedPorts are the cores' own control APIs: only root
	// (bosun) may reach them, whoever else runs on the node.
	EgressProtectedPorts []int
	// Conn buffers accepted connections for the report when the node spec
	// asks for them; nil = never.
	Conn *connlog.Collector
	// Audit matches connections against the node's audit rules; nil = off.
	Audit *audit.Collector
	// Firewall opens listening ports in ufw/firewalld; nil = off.
	Firewall *firewall.Manager
	// ExtraPorts are opened along with the inbounds (the web panel port).
	ExtraPorts []firewall.Port
	// WARPAccount / SaveWARP read and persist the node's Cloudflare WARP
	// identity (local store); nil disables from_node WARP outbounds.
	WARPAccount func() *spec.WARPAccount
	SaveWARP    func(*spec.WARPAccount) error
	// kick re-applies the current state (after a certificate renewal).
	kick         chan struct{}
	forceRestart bool
	// dirty is set when the last apply failed part-way; the next pull tick
	// retries even though the panel revision did not move (with a floor
	// between attempts so a broken core is not restarted every second).
	dirty              bool
	coreDirty          bool
	forwardDirty       bool
	lastAttempt        time.Time
	lastForwardAttempt time.Time
	// kernelNode/kernelByTag are what the last apply handed to the kernel
	// helpers, so forwards applied afterwards can refresh the firewall.
	privatePolicyKey    string
	privatePolicyActive bool
	kernelNode          *spec.Node
	kernelByTag         map[string]string
	// pending* are traffic deltas the cores already zeroed but the panel
	// has not acknowledged; they ride along on the next report.
	pendingTraffic  map[trafficKey]*spec.UserTraffic
	pendingInbound  map[string]spec.Traffic
	pendingOutbound map[string]spec.Traffic
	// Keep the identities of each successfully applied core, not the latest
	// desired users: a failed apply must still bill the old process correctly.
	coreUserIDs map[string]map[string]int64
	// counters for /metrics
	applyErrors, reportFailures atomic.Int64
	lastApplyOK, lastReportOK   atomic.Int64 // unix seconds
	// reportNow asks the run loop for an out-of-band report (job results).
	reportNow chan struct{}
	delivery  *reportTransport // owned by Run; workers only send frozen values
	// doctorNow asks the run loop for a self-check a few seconds after an
	// apply, so the panel does not show the previous state for up to ten
	// minutes after inbounds change.
	doctorNow chan struct{}
	// Jobs handed down by the panel: which ran, which are running, and
	// results waiting for the next report.
	jobsMu      sync.Mutex
	jobsDone    map[string]bool
	jobsRunning map[string]bool
	jobResults  []agentproto.JobResult

	// Probe beats: host sampler and latency runner, driven by the panel's
	// probe config when the driver is a panel.Beater.
	sampler sysinfo.Sampler
	probes  probe.Runner
	// Version is the bosun release string.
	Version string
	// skipped are inbounds left out of the last apply (no certificate yet).
	customCerts map[string]agentproto.CertStatus // pushed certificates by domain
	skipped     map[string]string

	// Doctor: last periodic report, the one last sent to the panel and the
	// one waiting to ride on the next report; when the panel last accepted
	// a report and the last report error (for the panel check).
	lastDoctor     *doctor.Report
	sentDoctor     *doctor.Report
	sentDoctorAt   time.Time
	pendingDoctor  *doctor.Report
	lastReport     time.Time
	trafficJournal *trafficJournal // owned by the serial report loop
	lastReportErr  string
}

// ReloadCerts asks the agent to restart the cores so renewed certificate
// files are picked up.
func (a *Agent) ReloadCerts(string) {
	a.statusMu.Lock()
	a.forceRestart = true
	a.statusMu.Unlock()
	select {
	case a.kick <- struct{}{}:
	default:
	}
}

// Status is what the agent is doing, for the local UI.
type Status struct {
	Delivery    DeliveryStatus    `json:"delivery"`
	Panel       string            `json:"panel"`
	Ready       bool              `json:"ready"` // bootstrap done, first apply attempted
	Inbounds    int               `json:"inbounds"`
	Users       int               `json:"users"`
	LastPull    time.Time         `json:"last_pull"`
	LastApply   time.Time         `json:"last_apply"`
	LastError   string            `json:"last_error,omitempty"`
	CoreRunning map[string]bool   `json:"core_running"`
	CoreInbound map[string]int    `json:"core_inbounds"`
	Forwards    []forward.Stats   `json:"-"`
	Assign      map[string]string `json:"assign"` // inbound tag -> core
	// Skipped lists inbounds not running and why (usually a missing
	// certificate); they are retried on the next pull.
	Skipped map[string]string `json:"skipped,omitempty"`
	// Decoy is the self-hosted site state (nil when not configured).
	Decoy *decoy.Status `json:"decoy,omitempty"`
	// Shaper is the per-user speed limit state (nil when unused).
	Shaper *shaper.Status `json:"shaper,omitempty"`
	// Guard is the strict-ingress state (nil = no rules).
	Guard *ingressguard.Status `json:"guard,omitempty"`
	// Egress is the core egress guard state (nil = off).
	Egress *egressguard.Status `json:"egress,omitempty"`
	// CoreUser is the account the cores run as ("" = bosun itself).
	CoreUser string `json:"core_user,omitempty"`
	// RejectedRules are the panel's rules this node refused to render.
	RejectedRules []string `json:"rejected_rules,omitempty"`
	// Firewall is the auto-open state (nil = off or no firewall).
	Firewall *firewall.Status `json:"firewall,omitempty"`
}

// Status returns a snapshot of the agent state.
func (a *Agent) Status() Status {
	a.statusMu.Lock()
	defer a.statusMu.Unlock()
	st := a.status
	st.Panel = a.driver.Name()
	st.CoreRunning = map[string]bool{}
	for _, name := range a.reg.Names() {
		c, _ := a.reg.Get(name)
		st.CoreRunning[name] = c.Running()
	}
	st.Forwards = a.fwd.Snapshot()
	return st
}

func (a *Agent) setStatus(f func(*Status)) {
	a.statusMu.Lock()
	f(&a.status)
	a.statusMu.Unlock()
}

// ForwardStats exposes relay counters for the local UI.
func (a *Agent) ForwardStats() []forward.Stats { return a.fwd.Snapshot() }

// New builds an agent. metrics may be nil.
func New(cfg *config.Config, driver panel.Driver, reg *core.Registry, mreg *metrics.Registry, log *slog.Logger) *Agent {
	a := &Agent{coreChanges: make(chan coreChange), cfg: cfg, driver: driver, reg: reg, fwd: forward.NewManager(log), metrics: mreg, log: log.With("component", "agent"), started: time.Now(), kick: make(chan struct{}, 1), reportNow: make(chan struct{}, 1), doctorNow: make(chan struct{}, 1), jobsDone: map[string]bool{}, jobsRunning: map[string]bool{}}
	dir := ""
	if cfg != nil && cfg.DataDir != "" {
		dir = filepath.Join(cfg.DataDir, "service-control")
	}
	a.ServiceControl = &servicecontrol.Manager{Dir: dir}
	a.serviceControlPending.Store(true)
	if mreg != nil {
		a.registerMetrics()
	}
	return a
}

// Run blocks until ctx is cancelled, then stops every core.
func (a *Agent) Run(ctx context.Context) error {
	defer a.stopAll()
	if err := a.clearWireGuard(ctx); err != nil {
		var hostOnly *wireGuardForwardingCleanupError
		if !errors.As(err, &hostOnly) {
			return fmt.Errorf("clear previous WireGuard state: %w", err)
		}
		a.log.Error("WireGuard host-rule cleanup pending", "err", err)
	}
	if a.EgressDisabled && !a.MonitorOnly() {
		a.applyEgress(ctx, &spec.Node{})
	}

	if err := a.bootstrap(ctx); err != nil {
		return err
	}
	if err := a.apply(ctx); err != nil {
		// A bad inbound must not take the whole node down in local mode:
		// keep running so the UI can fix it.
		a.log.Error("initial apply failed", "err", err)
	}
	if err := a.applyForwards(ctx); err != nil {
		a.log.Error("forwards", "err", err)
	}
	a.setStatus(func(s *Status) { s.Ready = true })
	a.runJobs(ctx)

	var wake <-chan struct{}
	if n, ok := a.driver.(panel.Notifier); ok {
		wake = n.Changed()
	}
	iv := a.driver.Intervals()
	pull := time.NewTicker(iv.Pull)
	push := time.NewTicker(iv.Push)
	defer pull.Stop()
	defer push.Stop()
	leaseTick := time.NewTicker(time.Second)
	defer leaseTick.Stop()
	wgTick := time.NewTicker(15 * time.Second)
	defer wgTick.Stop()
	// Self-check: once shortly after start, then every 10 minutes.
	firewallTick := time.NewTicker(time.Minute)
	defer firewallTick.Stop()
	doctorTick := time.NewTicker(10 * time.Minute)
	defer doctorTick.Stop()
	go func() {
		select {
		case <-ctx.Done():
		case <-time.After(30 * time.Second):
			a.runDoctor(ctx)
		}
	}()
	a.log.Info("running", "pull", iv.Pull, "push", iv.Push)

	// Beats run on their own ticker so the panel can ask for 5-10s host
	// samples without touching the traffic report cadence.
	beater, _ := a.driver.(panel.Beater)
	beat := time.NewTicker(time.Hour)
	beat.Stop()
	defer beat.Stop()
	defer a.probes.Stop()
	beatEvery := time.Duration(0)
	reconfigureBeat := func() {
		if beater == nil {
			// Standalone: the local store decides when it can, else the
			// config file; results only show up on /metrics and in the
			// local UI.
			if src, ok := a.driver.(panel.ProbeSource); ok {
				a.configureProbe(ctx, src.Probe())
			} else {
				a.configureProbe(ctx, a.cfg.Probe.Spec())
			}
			return
		}
		cfg := beater.Probe()
		a.configureProbe(ctx, cfg)
		want := time.Duration(0)
		if cfg != nil && cfg.Enabled {
			want = 10 * time.Second
			if cfg.BeatSeconds >= 3 {
				want = time.Duration(cfg.BeatSeconds) * time.Second
			}
		}
		if want == beatEvery {
			return
		}
		beatEvery = want
		if want == 0 {
			beat.Stop()
			a.log.Info("probe beats off")
			return
		}
		beat.Reset(want)
		a.log.Info("probe beats on", "every", want)
	}
	reconfigureBeat()

	transport := newReportTransport(ctx)
	a.delivery = transport
	defer func() { transport.close(); a.delivery = nil }()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-wake:
			// Coalesce bursts of edits before rendering.
			time.Sleep(300 * time.Millisecond)
			a.pullApply(ctx)
			a.runJobs(ctx)
			reconfigureBeat()
		case change := <-a.coreChanges:
			change.done <- a.activateCore(ctx, change.ctx, change.request)
		case <-a.reportNow:
			a.requestReport(ctx)
		case result := <-transport.reports:
			transport.reportBusy = false
			if a.finishDurableReport(result.report, result.changed, result.err) {
				a.pullApply(ctx)
				a.runJobs(ctx)
				reconfigureBeat()
			}
			if transport.reportAgain {
				transport.reportAgain = false
				a.requestReport(ctx)
			}
		case result := <-transport.beats:
			transport.beatBusy = false
			if result.err != nil {
				a.log.Warn("beat failed", "err", result.err)
			} else {
				a.probes.Acknowledge(result.beat.Host.Pings)
			}
		case <-a.doctorNow:
			a.runDoctor(ctx)
		case <-a.kick:
			if a.node != nil {
				if err := a.apply(ctx); err != nil {
					a.log.Error("apply failed", "err", err)
				}
				// Configure probe sampling before the self-check.
				reconfigureBeat()
				a.scheduleDoctor()
			}
		case <-beat.C:
			if beater != nil && !transport.beatBusy {
				bctx, cancel := context.WithTimeout(ctx, 8*time.Second)
				host := a.sampler.Sample(bctx)
				host.Pings = a.probes.Batch()
				cancel()
				transport.sendBeat(beater, agentproto.Beat{Host: host})
			}
		case <-pull.C:
			if changed, err := a.pull(ctx); err != nil {
				a.log.Warn("pull failed", "err", err)
			} else if changed || a.applyRetryDue(time.Now()) {
				if a.dirty && !changed {
					a.log.Info("retrying the last apply that failed")
				}
				if err := a.apply(ctx); err != nil {
					a.log.Error("apply failed", "err", err)
				}
				if err := a.applyForwards(ctx); err != nil {
					a.log.Error("forwards", "err", err)
				}
				// Same reason as in the kick branch: exporters first, then
				// the self-check that reports on them.
				reconfigureBeat()
				a.scheduleDoctor()
			}
			a.runJobs(ctx)
			if niv := a.driver.Intervals(); niv != iv {
				iv = niv
				pull.Reset(iv.Pull)
				push.Reset(iv.Push)
				a.log.Info("intervals updated", "pull", iv.Pull, "push", iv.Push)
			}
			reconfigureBeat()
		case <-leaseTick.C:
			_ = a.expireOfflineLease(ctx)
		case <-wgTick.C:
			if a.wireGuardActive.Load() && a.node != nil && !a.modeChanging.Load() {
				if err := a.apply(ctx); err != nil {
					a.log.Error("WireGuard health reconcile", "err", err)
				}
			}
		case <-firewallTick.C:
			if a.node != nil && !a.modeChanging.Load() {
				if err := a.refreshServiceControl(ctx); err != nil {
					a.log.Warn("service control reconcile", "err", err)
				}
			}
			if a.Firewall != nil && !a.modeChanging.Load() {
				if err := a.Firewall.Refresh(ctx); err != nil {
					a.log.Warn("firewall reconcile", "err", err)
				}
				st := a.Firewall.Status()
				a.setStatus(func(s *Status) { s.Firewall = &st })
			}
		case <-doctorTick.C:
			a.runDoctor(ctx)
		case <-push.C:
			if a.requestReport(ctx) {
				// The panel says newer state exists: pull now instead of
				// waiting for the next tick.
				if changed, err := a.pull(ctx); err != nil {
					a.log.Warn("pull failed", "err", err)
				} else if changed {
					if err := a.apply(ctx); err != nil {
						a.log.Error("apply failed", "err", err)
					}
					if err := a.applyForwards(ctx); err != nil {
						a.log.Error("forwards", "err", err)
					}
					a.runJobs(ctx)
				}
			}
		}
	}
}

// pullApply is one pull followed by apply when anything moved.
func (a *Agent) pullApply(ctx context.Context) {
	changed, err := a.pull(ctx)
	if err != nil {
		a.log.Warn("pull failed", "err", err)
		return
	}
	if !changed {
		return
	}
	if err := a.apply(ctx); err != nil {
		a.log.Error("apply failed", "err", err)
	}
	if err := a.applyForwards(ctx); err != nil {
		a.log.Error("forwards", "err", err)
	}
	a.scheduleDoctor()
}

// scheduleDoctor runs the self-check shortly after an apply, once the
// cores have had a moment to bind their listeners; the run loop does the
// actual work so nothing races with the next pull.
func (a *Agent) scheduleDoctor() {
	time.AfterFunc(3*time.Second, func() {
		select {
		case a.doctorNow <- struct{}{}:
		default:
		}
	})
}

// bootstrap keeps trying until the panel has given us both node and users.
func (a *Agent) bootstrap(ctx context.Context) error {
	delay := 2 * time.Second
	for {
		_, err := a.pull(ctx)
		if err == nil && a.node != nil && a.users != nil {
			return nil
		}
		if err == nil {
			err = errors.New("panel returned no data")
		}
		a.log.Warn("bootstrap: panel not ready", "err", err, "retry_in", delay)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay = min(delay*2, 60*time.Second)
	}
}

// pull refreshes node and users; changed reports whether either moved.
func (a *Agent) pull(ctx context.Context) (bool, error) {
	changed := false
	node, nodeChanged, err := a.driver.Node(ctx)
	if err != nil {
		_ = a.expireOfflineLease(ctx)
		return false, fmt.Errorf("node: %w", err)
	}
	if nodeChanged {
		if a.proxyModeReady(node) && (node.ServiceControl == nil || node.ServiceControl.Mode == spec.ServiceControlNormal) {
			a.resolveCerts(ctx, node)
		}
		a.node = node
		changed = true
		a.log.Info("node config updated", "inbounds", len(node.Inbounds), "outbounds", len(node.Outbounds))
	}
	users, usersChanged, err := a.driver.Users(ctx)
	if err != nil {
		return false, fmt.Errorf("users: %w", err)
	}
	if usersChanged {
		a.users = users
		changed = true
		a.log.Info("user list updated", "users", len(users))
	}
	if changed {
		a.rebuildUserIndex()
	}
	a.setStatus(func(s *Status) {
		s.LastPull = time.Now()
		if a.node != nil {
			s.Inbounds = len(a.node.Inbounds)
		}
		s.Users = len(a.users)
	})
	return changed, nil
}

// rebuildUserIndex maps stats keys (user names) to panel IDs across the
// node-level list and every inbound's scoped list.
func (a *Agent) rebuildUserIndex() {
	a.userIDs = make(map[string]int64, len(a.users))
	for _, u := range a.users {
		a.userIDs[u.Name] = u.ID
	}
	if a.node != nil {
		for _, ib := range a.node.Inbounds {
			for _, u := range ib.Users {
				a.userIDs[u.Name] = u.ID
			}
		}
	}
}

// ProbeResults returns the latest carrier and task measurements.
func (a *Agent) ProbeResults() []spec.PingResult { return a.probes.Results() }

func with(l map[string]string, k, v string) map[string]string {
	out := make(map[string]string, len(l)+1)
	for kk, vv := range l {
		out[kk] = vv
	}
	out[k] = v
	return out
}

func (a *Agent) stopAll() {
	a.shaperMu.Lock()
	defer a.shaperMu.Unlock()
	// Run's context has already been cancelled; child processes are still
	// alive until Stop. Persist their final sample before closing the driver.
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := a.checkpointTraffic(drainCtx); err != nil {
		a.log.Error("could not checkpoint traffic before shutdown", "err", err)
	}
	drainCancel()
	if c, ok := a.driver.(interface{ Close() error }); ok {
		_ = c.Close()
	}
	a.fwd.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, name := range a.reg.Names() {
		c, _ := a.reg.Get(name)
		if c.Running() {
			if err := c.Stop(ctx); err != nil {
				a.log.Warn("stop failed", "core", name, "err", err)
			}
		}
	}
	if err := a.clearWireGuard(ctx); err != nil {
		a.log.Warn("WireGuard shutdown cleanup", "err", err)
	}
}

// SampleHost shares resource baselines with reports, beats and exporters.
func (a *Agent) SampleHost(ctx context.Context) spec.SystemStatus { return a.sampler.Sample(ctx) }

func (a *Agent) configureProbe(ctx context.Context, cfg *spec.Probe) {
	var options *spec.ResourceOptions
	if cfg != nil {
		options = cfg.Resources
	}
	a.sampler.Configure(options)
	a.probes.Configure(ctx, cfg)
}
