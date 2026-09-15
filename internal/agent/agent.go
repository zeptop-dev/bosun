// Package agent is the managed-mode control loop: pull desired state from the
// panel, render it onto cores, and push accounting back.
package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/zeptop-dev/bosun/internal/doctor"
	"github.com/zeptop-dev/bosun/internal/komari"
	"github.com/zeptop-dev/bosun/internal/probe"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/zeptop-dev/bosun/internal/certs"
	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/decoy"
	"github.com/zeptop-dev/bosun/internal/firewall"
	"github.com/zeptop-dev/bosun/internal/forward"
	"github.com/zeptop-dev/bosun/internal/ingressguard"
	"github.com/zeptop-dev/bosun/internal/metrics"
	"github.com/zeptop-dev/bosun/internal/panel"
	"github.com/zeptop-dev/bosun/internal/shaper"
	"github.com/zeptop-dev/bosun/internal/sysinfo"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Agent wires one panel driver to a core registry.
// retryFloor is the least time between retries of a failed apply.
const retryFloor = 30 * time.Second

type Agent struct {
	cfg     *config.Config
	driver  panel.Driver
	reg     *core.Registry
	fwd     *forward.Manager
	metrics *metrics.Registry
	log     *slog.Logger

	node  *spec.Node
	users []spec.User
	// userIDs maps spec.User.Name (the stats key) to the panel user ID.
	userIDs map[string]int64

	statusMu sync.Mutex
	status   Status

	// Upgrade is called (in its own goroutine, once per requested version)
	// when the panel asks the node to move to another release.
	Upgrade      func(version string)
	upgradeAsked string

	// Certs obtains certificates for inbounds with auto_cert; nil disables.
	Certs *certs.Manager
	// Decoy serves the node's own HTTPS site for REALITY to steal; nil disables.
	Decoy *decoy.Server
	// Alert delivers an operator notification (Telegram); nil = none.
	Alert func(text string)
	// Shaper enforces per-user speed limits in the kernel; nil = none.
	Shaper *shaper.Shaper
	// Realm runs forward rules with the realm backend; nil rejects them.
	Realm *forward.Realm
	// Guard drops packets for mita ports that arrive on the wrong local
	// address (mita cannot bind one itself); nil = not enforced.
	Guard *ingressguard.Guard
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
	dirty       bool
	lastAttempt time.Time
	// kernelNode/kernelByTag are what the last apply handed to the kernel
	// helpers, so forwards applied afterwards can refresh the firewall.
	kernelNode  *spec.Node
	kernelByTag map[string]string
	// pending* are traffic deltas the cores already zeroed but the panel
	// has not acknowledged; they ride along on the next report.
	pendingTraffic  map[int64]*spec.UserTraffic
	pendingInbound  map[string]spec.Traffic
	pendingOutbound map[string]spec.Traffic
	// reportNow asks the run loop for an out-of-band report (job results).
	reportNow chan struct{}
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
	// komari reports to a Komari server when the driver carries a config.
	komari komari.Exporter
	// Version is the bosun release string reported to Komari.
	Version string
	// skipped are inbounds left out of the last apply (no certificate yet).
	customCerts map[string]agentproto.CertStatus // pushed certificates by domain
	skipped     map[string]string

	// Doctor: last periodic report, the one last sent to the panel and the
	// one waiting to ride on the next report; when the panel last accepted
	// a report and the last report error (for the panel check).
	lastDoctor    *doctor.Report
	sentDoctor    *doctor.Report
	sentDoctorAt  time.Time
	pendingDoctor *doctor.Report
	lastReport    time.Time
	lastReportErr string
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
	a := &Agent{cfg: cfg, driver: driver, reg: reg, fwd: forward.NewManager(log), metrics: mreg, log: log.With("component", "agent"), kick: make(chan struct{}, 1), reportNow: make(chan struct{}, 1), jobsDone: map[string]bool{}, jobsRunning: map[string]bool{}}
	if mreg != nil {
		a.registerMetrics()
	}
	return a
}

// Run blocks until ctx is cancelled, then stops every core.
func (a *Agent) Run(ctx context.Context) error {
	defer a.stopAll()

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
	// The firewall openings computed during apply did not see the forward
	// listeners yet (they start after); refresh once they are up.
	if a.kernelNode != nil {
		a.applyKernelHelpers(ctx, a.kernelNode, a.kernelByTag)
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
	// Self-check: once shortly after start, then every 10 minutes.
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
	defer a.komari.Stop()
	a.komari.CredFile, a.komari.Sampler, a.komari.Prober, a.komari.Log, a.komari.Version = filepath.Join(a.cfg.DataDir, "komari.json"), &a.sampler, &a.probes, a.log, a.Version
	ks, _ := a.driver.(panel.KomariSource)
	beatEvery := time.Duration(0)
	reconfigureBeat := func() {
		if ks != nil {
			a.komari.Configure(ctx, ks.Komari())
		}
		if beater == nil {
			// Standalone: the local store decides when it can, else the
			// config file; results only show up on /metrics and in the
			// local UI.
			if src, ok := a.driver.(panel.ProbeSource); ok {
				a.probes.Configure(ctx, src.Probe())
			} else {
				a.probes.Configure(ctx, a.cfg.Probe.Spec())
			}
			return
		}
		cfg := beater.Probe()
		a.probes.Configure(ctx, cfg)
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
		case <-a.reportNow:
			a.report(ctx)
		case <-a.kick:
			if a.node != nil {
				if err := a.apply(ctx); err != nil {
					a.log.Error("apply failed", "err", err)
				}
			}
		case <-beat.C:
			if beater != nil {
				bctx, cancel := context.WithTimeout(ctx, 8*time.Second)
				host := a.sampler.Sample(bctx)
				host.Pings = a.probes.Results()
				if err := beater.Beat(bctx, agentproto.Beat{Host: host}); err != nil {
					a.log.Warn("beat failed", "err", err)
				}
				cancel()
			}
		case <-pull.C:
			if changed, err := a.pull(ctx); err != nil {
				a.log.Warn("pull failed", "err", err)
			} else if changed || (a.dirty && time.Since(a.lastAttempt) >= retryFloor) {
				if a.dirty && !changed {
					a.log.Info("retrying the last apply that failed")
				}
				if err := a.apply(ctx); err != nil {
					a.log.Error("apply failed", "err", err)
				}
				if err := a.applyForwards(ctx); err != nil {
					a.log.Error("forwards", "err", err)
				}
			}
			a.runJobs(ctx)
			if niv := a.driver.Intervals(); niv != iv {
				iv = niv
				pull.Reset(iv.Pull)
				push.Reset(iv.Push)
				a.log.Info("intervals updated", "pull", iv.Pull, "push", iv.Push)
			}
			reconfigureBeat()
		case <-doctorTick.C:
			a.runDoctor(ctx)
		case <-push.C:
			if a.report(ctx) {
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
		return false, fmt.Errorf("node: %w", err)
	}
	if nodeChanged {
		a.resolveCerts(ctx, node)
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

// ResolveCerts fills certificate paths for standard-TLS inbounds from local
// config. It is exported so `bosun render` produces the same output as `run`.
func ResolveCerts(cfg *config.Config, node *spec.Node, log *slog.Logger) {
	for i := range node.Inbounds {
		t := node.Inbounds[i].TLS
		if t == nil || t.Mode != spec.TLSStandard || t.AutoCert {
			continue
		}
		certPath, keyPath, ok := cfg.CertFor(t.ServerName)
		if !ok {
			log.Warn("no local certificate for inbound; TLS will fail",
				"inbound", node.Inbounds[i].Tag, "server_name", t.ServerName)
			continue
		}
		t.CertPath, t.KeyPath = certPath, keyPath
	}
}

// resolveCerts fills local certificate paths and obtains ACME certificates
// for inbounds that ask for them. An inbound whose certificate cannot be
// obtained is skipped (not rendered) rather than breaking the whole core;
// it is retried on the next pull.
func (a *Agent) resolveCerts(ctx context.Context, node *spec.Node) {
	ResolveCerts(a.cfg, node, a.log)
	skipped := map[string]string{}
	if a.Certs != nil && node.ACME != nil {
		a.Certs.Configure(node.ACME.Email, node.ACME.CloudflareToken)
	}
	// Pushed certificates win over ACME and local config for the names
	// they cover.
	custom := map[string]agentproto.CertStatus{}
	customDir := filepath.Join(a.cfg.DataDir, "certs")
	for i := range node.Inbounds {
		ib := &node.Inbounds[i]
		t := ib.TLS
		if t == nil || t.Mode != spec.TLSStandard {
			continue
		}
		c := certs.Pick(node.Certificates, t.ServerName)
		if c == nil {
			continue
		}
		certPath, keyPath, notAfter, err := certs.Install(customDir, *c)
		st := agentproto.CertStatus{Domain: c.Domain, Method: "custom", NotAfter: notAfter}
		if err != nil {
			st.Error = err.Error()
			skipped[ib.Tag] = "pushed certificate for " + c.Domain + ": " + err.Error()
			custom[c.Domain] = st
			continue
		}
		custom[c.Domain] = st
		t.CertPath, t.KeyPath, t.AutoCert = certPath, keyPath, false
	}
	a.statusMu.Lock()
	a.customCerts = custom
	a.statusMu.Unlock()
	for i := range node.Inbounds {
		ib := &node.Inbounds[i]
		t := ib.TLS
		if t == nil || t.Mode != spec.TLSStandard || !t.AutoCert {
			continue
		}
		if a.Certs == nil {
			skipped[ib.Tag] = "certificate automation is disabled"
			continue
		}
		certPath, keyPath, err := a.Certs.Ensure(ctx, t.ServerName, t.ACME)
		if err != nil {
			skipped[ib.Tag] = err.Error()
			continue
		}
		t.CertPath, t.KeyPath = certPath, keyPath
	}
	a.statusMu.Lock()
	a.skipped = skipped
	a.statusMu.Unlock()
}

// apply renders the current state onto each core and starts, restarts or
// stops cores as their assignment changes.
func (a *Agent) apply(ctx context.Context) error {
	a.lastAttempt = time.Now()
	err := a.applyInner(ctx)
	a.dirty = err != nil
	a.setStatus(func(s *Status) {
		s.LastApply = time.Now()
		s.LastError = ""
		if err != nil {
			s.LastError = err.Error()
		}
		s.Skipped = a.skipped
	})
	return err
}

func (a *Agent) applyInner(ctx context.Context) error {
	a.statusMu.Lock()
	restart := a.forceRestart
	a.forceRestart = false
	skipped := a.skipped
	a.statusMu.Unlock()
	if a.Decoy != nil {
		a.Decoy.Configure(ctx, a.node.Decoy)
		st := a.Decoy.Status()
		a.setStatus(func(s *Status) { s.Decoy = st })
	}
	inbounds := make([]spec.Inbound, 0, len(a.node.Inbounds))
	for _, ib := range a.node.Inbounds {
		// Tags become file names and nft comments; a panel may not push
		// anything that is not a plain identifier.
		if !spec.ValidTag(ib.Tag) || !spec.ValidListen(ib.Listen) {
			a.log.Warn("inbound skipped", "inbound", ib.Tag, "reason", "invalid tag or listen address")
			continue
		}
		if _, skip := skipped[ib.Tag]; skip {
			a.log.Warn("inbound skipped", "inbound", ib.Tag, "reason", skipped[ib.Tag])
			continue
		}
		inbounds = append(inbounds, ib)
	}
	assign, err := a.reg.Assign(inbounds)
	if err != nil {
		return err
	}
	node := a.node
	if resolved, err := a.resolveWARP(*node); err != nil {
		return err
	} else {
		node = &resolved
	}
	// Per-user speed limits: the kernel shaper must exist for the marks
	// the cores stamp to mean anything; without it the limits are ignored
	// (and the doctor says so).
	var limits []shaper.Limit
	for _, u := range a.users {
		if l := node.EffectiveSpeedLimit(u); l > 0 {
			limits = append(limits, shaper.Limit{UserID: u.ID, Mbps: l})
		}
	}
	if a.Shaper == nil || !a.Shaper.Supported() {
		if len(limits) > 0 {
			cp := *node
			cp.UserSpeedLimitMbps = 0
			node = &cp
			users := make([]spec.User, 0, len(a.users))
			for _, u := range a.users {
				u.SpeedLimitMbps = 0
				users = append(users, u)
			}
			a.users = users
			a.log.Warn("speed limits configured but shaping is unavailable on this host (needs Linux with nft and tc)")
		}
		limits = nil
	}
	defer func() {
		if a.Shaper != nil {
			if err := a.Shaper.Apply(ctx, limits); err != nil {
				a.log.Error("speed limit shaper", "err", err)
			}
			st := a.Shaper.Status()
			a.setStatus(func(s *Status) {
				if st.Users == 0 && st.Error == "" {
					s.Shaper = nil
				} else {
					s.Shaper = &st
				}
			})
		}
	}()
	byTag := map[string]string{}
	perCore := map[string]int{}
	for name, list := range assign {
		perCore[name] = len(list)
		for _, ib := range list {
			byTag[ib.Tag] = name
		}
	}
	a.setStatus(func(s *Status) { s.Assign, s.CoreInbound = byTag, perCore })
	a.kernelNode, a.kernelByTag = node, byTag
	defer a.applyKernelHelpers(ctx, node, byTag)
	for _, name := range a.reg.Names() {
		c, _ := a.reg.Get(name)
		inbounds := assign[name]
		if len(inbounds) == 0 {
			if c.Running() {
				a.log.Info("core has no inbounds, stopping", "core", name)
				if err := c.Stop(ctx); err != nil {
					return fmt.Errorf("%s: stop: %w", name, err)
				}
			}
			continue
		}
		bundle, err := c.Render(node, inbounds, a.users)
		if err != nil {
			return fmt.Errorf("%s: render: %w", name, err)
		}
		if restart && c.Running() {
			// Certificate files changed underneath: a plain Apply would see
			// an identical config and do nothing.
			if err := c.Stop(ctx); err != nil {
				return fmt.Errorf("%s: stop for reload: %w", name, err)
			}
		}
		if c.Running() {
			err = c.Apply(ctx, bundle)
		} else {
			err = c.Start(ctx, bundle)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		a.log.Info("core applied", "core", name, "inbounds", len(inbounds), "users", len(a.users))
	}
	return nil
}

// applyKernelHelpers runs after the cores: the strict-ingress rules for
// mita inbounds bound to a line address, and the firewall openings for
// every listener. Failures are logged and shown by the doctor, never
// fatal for the apply.
func (a *Agent) applyKernelHelpers(ctx context.Context, node *spec.Node, byTag map[string]string) {
	var rules []ingressguard.Rule
	var ports []firewall.Port
	for _, ib := range node.Inbounds {
		if _, served := byTag[ib.Tag]; !served {
			continue
		}
		for _, p := range listenPorts(ib) {
			ports = append(ports, p)
			if byTag[ib.Tag] == "mita" && ib.Listen != "" && ib.Listen != "0.0.0.0" && ib.Listen != "::" {
				rules = append(rules, ingressguard.Rule{IP: ib.Listen, Proto: p.Proto, Port: p.Port})
			}
		}
	}
	if a.Guard != nil {
		if err := a.Guard.Apply(ctx, rules); err != nil {
			a.log.Error("strict ingress", "err", err)
		}
		st := a.Guard.Status()
		a.setStatus(func(s *Status) {
			if len(rules) == 0 && st.Error == "" {
				s.Guard = nil
			} else {
				s.Guard = &st
			}
		})
	}
	if a.Firewall != nil {
		for _, f := range a.fwd.Snapshot() {
			for _, proto := range forwardProtocols(f.Protocol) {
				ports = append(ports, firewall.Port{Proto: proto, Port: f.Port})
			}
		}
		ports = append(ports, a.ExtraPorts...)
		if err := a.Firewall.Apply(ctx, ports); err != nil {
			a.log.Warn("firewall auto-open", "err", err)
		}
		st := a.Firewall.Status()
		a.setStatus(func(s *Status) {
			if st.Kind == "" && st.Error == "" {
				s.Firewall = nil
			} else {
				s.Firewall = &st
			}
		})
	}
}

func forwardProtocols(p string) []string {
	switch p {
	case "udp":
		return []string{"udp"}
	case "both":
		return []string{"tcp", "udp"}
	}
	return []string{"tcp"}
}

// listenPorts lists the transport ports an inbound occupies.
func listenPorts(ib spec.Inbound) []firewall.Port {
	switch ib.Protocol {
	case spec.Hysteria2, spec.TUIC, spec.WireGuard:
		return []firewall.Port{{Proto: "udp", Port: ib.Port}}
	case spec.Mieru:
		switch strings.ToUpper(ib.MieruTransport) {
		case "UDP":
			return []firewall.Port{{Proto: "udp", Port: ib.Port}}
		case "BOTH":
			return []firewall.Port{{Proto: "tcp", Port: ib.Port}, {Proto: "udp", Port: ib.Port + 1}}
		}
		return []firewall.Port{{Proto: "tcp", Port: ib.Port}}
	case spec.Shadowsocks, spec.Snell:
		return []firewall.Port{{Proto: "tcp", Port: ib.Port}, {Proto: "udp", Port: ib.Port}}
	}
	return []firewall.Port{{Proto: "tcp", Port: ib.Port}}
}

// report collects per-user traffic from every running core and pushes it
// with a host snapshot. It returns true when the panel signals newer state.
func (a *Agent) report(ctx context.Context) bool {
	if a.pendingTraffic == nil {
		a.pendingTraffic = map[int64]*spec.UserTraffic{}
		a.pendingInbound = map[string]spec.Traffic{}
		a.pendingOutbound = map[string]spec.Traffic{}
	}
	// Deltas the panel never acknowledged are carried forward: the cores
	// zero their counters on read, so this map is the only copy.
	totals := a.pendingTraffic
	for _, name := range a.reg.Names() {
		c, _ := a.reg.Get(name)
		if !c.Running() {
			continue
		}
		stats, err := c.Stats(ctx, true)
		if err != nil {
			a.log.Warn("stats failed", "core", name, "err", err)
			continue
		}
		for userName, t := range stats {
			if t.Up == 0 && t.Down == 0 {
				continue
			}
			id, ok := a.userIDs[userName]
			if !ok {
				continue
			}
			ut := totals[id]
			if ut == nil {
				ut = &spec.UserTraffic{UserID: id}
				totals[id] = ut
			}
			ut.Up += t.Up
			ut.Down += t.Down
		}
	}
	list := make([]spec.UserTraffic, 0, len(totals))
	for _, t := range totals {
		list = append(list, *t)
	}
	perInbound := a.pendingInbound
	for _, name := range a.reg.Names() {
		c, _ := a.reg.Get(name)
		is, ok := c.(core.InboundStatser)
		if !ok || !c.Running() {
			continue
		}
		stats, err := is.InboundStats(ctx, true)
		if err != nil {
			a.log.Debug("inbound stats failed", "core", name, "err", err)
			continue
		}
		for tag, t := range stats {
			if t.Up == 0 && t.Down == 0 {
				continue
			}
			cur := perInbound[tag]
			cur.Up += t.Up
			cur.Down += t.Down
			perInbound[tag] = cur
		}
	}
	perOutbound := a.pendingOutbound
	for _, name := range a.reg.Names() {
		c, _ := a.reg.Get(name)
		os, ok := c.(core.OutboundStatser)
		if !ok || !c.Running() {
			continue
		}
		stats, err := os.OutboundStats(ctx, true)
		if err != nil {
			a.log.Debug("outbound stats failed", "core", name, "err", err)
			continue
		}
		for tag, t := range stats {
			if t.Up == 0 && t.Down == 0 || tag == "api" || tag == "block" {
				continue
			}
			cur := perOutbound[tag]
			cur.Up += t.Up
			cur.Down += t.Down
			perOutbound[tag] = cur
		}
	}
	host := sysinfo.Snapshot(ctx)

	if rep, ok := a.driver.(panel.Reporter); ok {
		full := a.buildReport(list, host)
		full.Jobs = a.takeJobResults()
		if len(perInbound) > 0 {
			full.Inbounds = perInbound
		}
		if len(perOutbound) > 0 {
			full.Outbounds = perOutbound
		}
		changed, err := rep.Report(ctx, full)
		if err != nil {
			// The deltas stay in the pending maps and go out with the next
			// report; job results are requeued the same way.
			a.requeueJobResults(full.Jobs)
			a.log.Error("report failed; traffic deltas kept for the next attempt", "users", len(list), "err", err)
			a.statusMu.Lock()
			a.lastReportErr = err.Error()
			a.statusMu.Unlock()
			return false
		}
		a.pendingTraffic, a.pendingInbound, a.pendingOutbound = map[int64]*spec.UserTraffic{}, map[string]spec.Traffic{}, map[string]spec.Traffic{}
		a.log.Debug("report sent", "users", len(list), "state_changed", changed)
		a.statusMu.Lock()
		a.lastReport, a.lastReportErr = time.Now(), ""
		if a.pendingDoctor != nil {
			a.sentDoctor, a.sentDoctorAt, a.pendingDoctor = a.pendingDoctor, time.Now(), nil
		}
		a.statusMu.Unlock()
		if ur, ok := a.driver.(panel.UpgradeRequester); ok && a.Upgrade != nil {
			if v := ur.UpgradeRequested(); v != "" && v != a.upgradeAsked {
				a.upgradeAsked = v
				a.log.Info("panel requested upgrade", "version", v)
				go a.Upgrade(v)
			}
		}
		return changed
	}
	if len(list) > 0 {
		if err := a.driver.PushTraffic(ctx, list); err != nil {
			a.log.Error("push traffic failed", "users", len(list), "err", err)
		} else {
			a.log.Debug("traffic pushed", "users", len(list))
		}
	}
	if err := a.driver.PushStatus(ctx, host); err != nil {
		a.log.Warn("push status failed", "err", err)
	}
	return false
}

// buildReport assembles the combined report for Reporter drivers.
func (a *Agent) buildReport(traffic []spec.UserTraffic, host spec.SystemStatus) agentproto.Report {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rep := agentproto.Report{Traffic: traffic, Host: host, Cores: map[string]agentproto.CoreStatus{}, Online: map[string][]string{}}
	a.statusMu.Lock()
	rep.Doctor = a.pendingDoctor
	a.statusMu.Unlock()
	for _, name := range a.reg.Names() {
		c, _ := a.reg.Get(name)
		rep.Cores[name] = agentproto.CoreStatus{Running: c.Running()}
		if tr, ok := c.(core.OnlineTracker); ok && c.Running() {
			online, err := tr.Online(ctx)
			if err != nil {
				a.log.Warn("online lookup failed", "core", name, "err", err)
				continue
			}
			for user, ips := range online {
				rep.Online[user] = append(rep.Online[user], ips...)
			}
		}
	}
	if len(rep.Online) == 0 {
		rep.Online = nil
	}
	if a.Certs != nil {
		for _, st := range a.Certs.Status() {
			rep.Certs = append(rep.Certs, agentproto.CertStatus{Domain: st.Domain, Method: st.Method, NotAfter: st.NotAfter, Error: st.Error})
		}
	}
	a.statusMu.Lock()
	for _, st := range a.customCerts {
		rep.Certs = append(rep.Certs, st)
	}
	a.statusMu.Unlock()
	for _, s := range a.fwd.Snapshot() {
		rep.Forwards = append(rep.Forwards, agentproto.ForwardStatus{
			Tag: s.Tag, Up: s.Up, RTTMillis: s.RTT.Milliseconds(), LastError: s.LastError,
			ActiveConn: s.ActiveConn, TotalConn: s.TotalConn, BytesIn: s.BytesIn, BytesOut: s.BytesOut,
		})
	}
	return rep
}

// applyForwards reconciles relay rules: the panel's if it manages them,
// otherwise the local config's.
func (a *Agent) applyForwards(ctx context.Context) error {
	a.fwd.Realm = a.Realm
	rules := a.cfg.ForwardSpecs()
	if src, ok := a.driver.(panel.ForwardSource); ok {
		fw, changed, err := src.Forwards(ctx)
		if err != nil {
			return err
		}
		if changed {
			a.node.Forwards = fw
		}
		rules = append(rules, a.node.Forwards...)
	}
	return a.fwd.Apply(rules)
}

// KomariStatus reports the exporter's state for the UI.
func (a *Agent) KomariStatus() komari.Status { return a.komari.Status() }

// ProbeResults returns the latest carrier and task measurements.
func (a *Agent) ProbeResults() []spec.PingResult { return a.probes.Results() }

func (a *Agent) registerMetrics() {
	m := a.metrics
	m.Describe("bosun_core_running", "gauge", "1 if the core process is running")
	m.Describe("bosun_users", "gauge", "users currently provisioned")
	m.Describe("bosun_forward_up", "gauge", "1 if the forward target answered the last probe")
	m.Describe("bosun_forward_probe_rtt_seconds", "gauge", "last probe round trip to the forward target")
	m.Describe("bosun_forward_connections_active", "gauge", "open relayed connections or udp sessions")
	m.Describe("bosun_forward_connections_total", "counter", "relayed connections or udp sessions since start")
	m.Describe("bosun_forward_bytes_total", "counter", "relayed bytes by direction (in = client to target)")
	m.Describe("bosun_probe_latency_seconds", "gauge", "last latency of a carrier probe or panel task (-1 = lost)")
	m.Describe("bosun_probe_loss_ratio", "gauge", "recent loss ratio of a carrier probe")
	m.Add(func() []metrics.Sample {
		var out []metrics.Sample
		for _, p := range a.probes.Results() {
			l := map[string]string{"name": p.Name}
			lat := p.LatencyMs / 1000
			if p.LatencyMs < 0 {
				lat = -1
			}
			out = append(out, metrics.Sample{Name: "bosun_probe_latency_seconds", Labels: l, Value: lat})
			if p.TaskID == 0 {
				out = append(out, metrics.Sample{Name: "bosun_probe_loss_ratio", Labels: l, Value: p.Loss / 100})
			}
		}
		for _, name := range a.reg.Names() {
			c, _ := a.reg.Get(name)
			v := 0.0
			if c.Running() {
				v = 1
			}
			out = append(out, metrics.Sample{Name: "bosun_core_running", Labels: map[string]string{"core": name}, Value: v})
		}
		out = append(out, metrics.Sample{Name: "bosun_users", Value: float64(len(a.users))})
		for _, s := range a.fwd.Snapshot() {
			l := map[string]string{"tag": s.Tag, "target": s.Target, "protocol": s.Protocol}
			up := 0.0
			if s.Up {
				up = 1
			}
			out = append(out,
				metrics.Sample{Name: "bosun_forward_up", Labels: l, Value: up},
				metrics.Sample{Name: "bosun_forward_probe_rtt_seconds", Labels: l, Value: s.RTT.Seconds()},
				metrics.Sample{Name: "bosun_forward_connections_active", Labels: l, Value: float64(s.ActiveConn)},
				metrics.Sample{Name: "bosun_forward_connections_total", Labels: l, Value: float64(s.TotalConn)},
				metrics.Sample{Name: "bosun_forward_bytes_total", Labels: with(l, "dir", "in"), Value: float64(s.BytesIn)},
				metrics.Sample{Name: "bosun_forward_bytes_total", Labels: with(l, "dir", "out"), Value: float64(s.BytesOut)},
			)
		}
		return out
	})
}

func with(l map[string]string, k, v string) map[string]string {
	out := make(map[string]string, len(l)+1)
	for kk, vv := range l {
		out[kk] = vv
	}
	out[k] = v
	return out
}

func (a *Agent) stopAll() {
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
}
