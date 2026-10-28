package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/zeptop-dev/bosun/internal/egressguard"

	"github.com/zeptop-dev/bosun/internal/audit"

	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/runas"

	"log/slog"
	"path/filepath"
	"time"

	"github.com/zeptop-dev/bosun/internal/certs"
	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/firewall"
	"github.com/zeptop-dev/bosun/internal/ingressguard"
	"github.com/zeptop-dev/bosun/internal/panel"
	"github.com/zeptop-dev/bosun/internal/shaper"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

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
func (a *Agent) apply(ctx context.Context) (err error) {
	revision, _ := a.consumedRevisions()
	a.setAppliedCoreRevision("")
	defer func() {
		if err == nil && !a.modeChanging.Load() {
			a.setAppliedCoreRevision(revision)
		}
	}()
	a.lastAttempt = time.Now()
	err = a.wireGuardFailure(ctx, a.applyInner(ctx))
	a.coreDirty = err != nil
	a.dirty = a.coreDirty || a.forwardDirty
	if err != nil {
		a.applyErrors.Add(1)
	} else {
		a.lastApplyOK.Store(time.Now().Unix())
	}
	a.setStatus(func(s *Status) {
		s.LastApply = time.Now()
		s.LastError = ""
		if err != nil {
			s.LastError = err.Error()
		}
		if s.Skipped == nil {
			s.Skipped = a.skipped
		}
	})
	return err
}

// withSkip adds a reason to the skipped map without touching the shared
// certificate-driven one (copy on first write).
func withSkip(m map[string]string, tag, reason string) map[string]string {
	cp := make(map[string]string, len(m)+1)
	for k, v := range m {
		cp[k] = v
	}
	cp[tag] = reason
	return cp
}

func (a *Agent) applyInner(ctx context.Context) error {
	a.shaperMu.Lock()
	defer a.shaperMu.Unlock()
	if err := a.reconcileServiceControl(ctx); err != nil {
		if a.serviceControlActive() {
			return errors.Join(err, a.stopControlledServices(ctx))
		}
		return err
	}
	if a.serviceControlPaused() {
		return a.stopControlledServices(ctx)
	}
	if handled, err := a.applyNodeMode(ctx); handled {
		return err
	}
	if a.serviceControlActive() {
		a.resolveCerts(ctx, a.node)
	}
	if err := a.prepareWireGuard(ctx); err != nil {
		return err
	}
	if err := a.checkpointTraffic(ctx); err != nil {
		// A failed disk/stats read must not hold revoked private access open.
		if a.privatePolicyActive || a.node.HasPrivateAccess() {
			return errors.Join(err, a.stopPrivateCores(ctx))
		}
		return err
	}
	if err := a.node.ValidatePrivateAccessNode(); err != nil {
		if a.privatePolicyActive || a.node.HasPrivateAccess() {
			return errors.Join(err, a.stopPrivateCores(ctx))
		}
		return err
	}

	// Keep the stored automatic intent intact across guard changes/restarts.
	desired, err := a.node.ResolvePrivateAccessIntent(a.EgressDisabled)
	if err != nil {
		return errors.Join(err, a.stopPrivateCores(ctx))
	}
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
	for _, ib := range desired.Inbounds {
		// The shared shape check: a panel may not push anything a core
		// would choke on (bad tag, missing key, REALITY without dest...).
		// Such an inbound is left out with the reason instead of breaking
		// the core's whole config.
		if err := ib.Validate(); err != nil {
			a.log.Warn("inbound skipped", "inbound", ib.Tag, "reason", err.Error())
			if spec.ValidTag(ib.Tag) {
				skipped = withSkip(skipped, ib.Tag, "invalid: "+err.Error())
			}
			continue
		}
		if _, skip := skipped[ib.Tag]; skip {
			a.log.Warn("inbound skipped", "inbound", ib.Tag, "reason", skipped[ib.Tag])
			continue
		}
		inbounds = append(inbounds, ib)
	}
	// One inbound nobody can serve must not hold the rest hostage: it is
	// left out with the reason (shown by the doctor) and retried next pull.
	assign, unsupported := a.reg.Split(inbounds)
	for tag, reason := range unsupported {
		a.log.Warn("inbound skipped", "inbound", tag, "reason", reason)
		skipped = withSkip(skipped, tag, reason)
	}
	// Some authenticated servers reject an empty user list. Keep their
	// listeners idle until a grant arrives, without failing other inbounds.
	for name, list := range assign {
		kept := list[:0:0]
		for _, ib := range list {
			if coreWaitsForUsers(name, ib) && len(ib.EffectiveUsers(a.users)) == 0 {
				skipped = withSkip(skipped, ib.Tag, "waiting for users (core cannot start without any)")
				continue
			}
			kept = append(kept, ib)
		}
		assign[name] = kept
	}
	a.setStatus(func(s *Status) { s.Skipped = skipped })
	node := desired
	if resolved, err := a.resolveWARP(*node); err != nil {
		return err
	} else {
		node = &resolved
	}
	// The panel is not trusted to send a renderable spec: one bad match
	// makes a core refuse its whole config, which would strand every
	// inbound on the node. Bad rules are dropped and reported.
	if node = validateNode(node, a.log, func(msgs []string) {
		a.setStatus(func(s *Status) { s.RejectedRules = msgs })
	}); node == nil {
		return fmt.Errorf("agent: node spec is unusable")
	}
	// Audit rules: "block" ones go first in the route list of every core
	// with routing; the matcher records hits for both actions.
	if blocks := audit.BlockRules(node.AuditRules); len(blocks) > 0 {
		cp := *node
		cp.Routes = append(append([]spec.RouteRule(nil), blocks...), node.Routes...)
		node = &cp
	}
	if a.Audit != nil {
		a.Audit.SetRules(node.AuditRules)
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
			if node.HasPrivateAccess() || hasWireGuard(node) {
				return errors.Join(fmt.Errorf("private access with speed limits requires Linux nft and tc"), a.stopPrivateCores(ctx))
			}
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
	// Marking sockets for the shaper needs CAP_NET_ADMIN, so sing-box and
	// xray get it only while limits are really installed (after the
	// branch above may have dropped them), and a change means a restart so
	// the running processes pick it up.
	if err := a.preparePrivateAccess(ctx, node, limits); err != nil {
		return err
	}
	if err := a.prepareWireGuardShaping(ctx, node, limits); err != nil {
		return err
	}
	if runas.SetNetAdmin(len(limits) > 0 || node.HasDualPrivateAccess()) && runas.Active() {
		a.log.Info("core capabilities changed, restarting cores", "net_admin", len(limits) > 0)
		restart = true
	}
	defer func() {
		if a.Shaper != nil && !hasWireGuardTransit(node) {
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
	// Every core gets its turn even when an earlier one fails: the apply
	// is still reported dirty (and retried) but the healthy cores serve.
	var errs []error
	for _, name := range a.reg.Names() {
		err := a.applyCore(ctx, name, node, assign[name], restart)
		a.statusMu.Lock()
		if a.appliedCores == nil {
			a.appliedCores = map[string][]string{}
		}
		delete(a.appliedCores, name)
		if err == nil {
			for _, ib := range assign[name] {
				a.appliedCores[name] = append(a.appliedCores[name], ib.Tag)
			}
		}
		a.statusMu.Unlock()
		if err != nil {
			a.log.Error("core apply failed", "core", name, "err", err)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (a *Agent) applyCore(ctx context.Context, name string, node *spec.Node, inbounds []spec.Inbound, restart bool) error {
	c, _ := a.reg.Get(name)
	if len(inbounds) == 0 && !(name == "xray" && len(node.ReverseClients) > 0) {
		if c.Running() {
			a.log.Info("core has no inbounds, stopping", "core", name)
			if err := c.Stop(ctx); err != nil {
				return fmt.Errorf("%s: stop: %w", name, err)
			}
		}
		return nil
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
	a.rememberCoreUsers(name, inbounds)
	a.log.Info("core applied", "core", name, "inbounds", len(inbounds), "users", len(a.users))
	return nil
}

func (a *Agent) rememberCoreUsers(name string, inbounds []spec.Inbound) {
	if a.coreUserIDs == nil {
		a.coreUserIDs = map[string]map[string]int64{}
	}
	ids := map[string]int64{}
	for _, u := range a.users {
		ids[u.Name] = u.ID
	}
	for _, ib := range inbounds {
		for _, u := range ib.EffectiveUsers(a.users) {
			ids[u.Name] = u.ID
		}
	}
	a.coreUserIDs[name] = ids
}

// needsHTTP01 reports whether anything on this node asks for a certificate
// over HTTP-01: a served inbound with auto_cert, or the decoy site.
func needsHTTP01(node *spec.Node, byTag map[string]string) bool {
	for _, ib := range node.Inbounds {
		if _, served := byTag[ib.Tag]; !served {
			continue
		}
		if t := ib.TLS; t != nil && t.Mode == spec.TLSStandard && t.AutoCert && t.ACME != certs.MethodDNS {
			return true
		}
	}
	if d := node.Decoy; d != nil && d.Domain != "" && d.ACME != certs.MethodDNS {
		return true
	}
	return false
}

// applyKernelHelpers runs after the cores: the strict-ingress rules for
// mita inbounds bound to a line address (only for mita builds that cannot
// bind one themselves), and the firewall openings for every listener. Failures are logged and shown by the doctor, never
// fatal for the apply.
func (a *Agent) applyKernelHelpers(ctx context.Context, node *spec.Node, byTag map[string]string) {
	var rules []ingressguard.Rule
	var ports []firewall.Port
	for _, link := range node.WireGuardLinks {
		if !link.Exit {
			ports = append(ports, firewall.Port{Proto: "udp", Port: link.ListenPort, Source: fmt.Sprintf("wireguard:%d", link.Slot)})
		}
	}
	// mita >= 3.37.0 binds the address itself; older builds listen
	// everywhere and need the nftables guard.
	guardMita := !nativeListen(a.reg)
	for _, ib := range node.Inbounds {
		if _, served := byTag[ib.Tag]; !served {
			continue
		}
		for _, p := range listenPorts(ib) {
			p.Source = "inbound:" + ib.Tag
			ports = append(ports, p)
			if guardMita && byTag[ib.Tag] == "mita" && ib.Listen != "" && ib.Listen != "0.0.0.0" && ib.Listen != "::" {
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
	if a.Conn != nil {
		a.Conn.SetEnabled(node.ConnLog)
	}
	_ = a.applyEgress(ctx, node)
	if a.Firewall != nil {
		for _, f := range a.fwd.Snapshot() {
			for _, proto := range forwardProtocols(f.Protocol) {
				ports = append(ports, firewall.Port{Proto: proto, Port: f.Port, Source: "forward:" + f.Tag})
			}
		}
		ports = append(ports, a.ExtraPorts...)
		// A certificate the node gets itself uses HTTP-01 unless it was
		// told to use DNS-01, and that challenge needs port 80 reachable
		// from the internet — at every renewal too, two months after
		// anyone last thought about the firewall.
		if needsHTTP01(node, byTag) {
			ports = append(ports, firewall.Port{Proto: "tcp", Port: 80, Source: "certificate:http01"})
		}
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

// applyForwards reconciles relay rules: the panel's if it manages them,
// otherwise the local config's.
func (a *Agent) applyForwards(ctx context.Context) (err error) {
	// Revoke confirmation even on early mode/read/validation failures.
	a.setAppliedForwardRevision("")
	a.lastForwardAttempt = time.Now()
	revision := ""
	defer func() {
		a.forwardDirty = err != nil
		a.dirty = a.coreDirty || a.forwardDirty
		if err == nil && !a.modeChanging.Load() {
			a.setAppliedForwardRevision(revision)
		}
	}()
	if a.modeChanging.Load() {
		return nil
	}
	if a.MonitorOnly() || (a.node != nil && a.node.Mode == spec.NodeMonitor) {
		return spec.ValidateMonitorState(a.node, a.users, a.cfg.ForwardSpecs())
	}
	if !a.proxyModeReady(a.node) {
		return errors.New("forwarding waits for the current node mode revision")
	}
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
		_, revision = a.consumedRevisions()
	}
	// A forward-only pull can change the owned NAT scope without a core apply.
	if err = a.reconcileServiceControl(ctx); err != nil {
		if a.serviceControlActive() {
			return errors.Join(err, a.fwd.Apply(nil))
		}
		return err
	}
	if a.serviceControlPaused() {
		return a.fwd.Apply(nil)
	}
	err = a.fwd.Apply(rules)
	if a.kernelNode != nil {
		a.applyKernelHelpers(ctx, a.kernelNode, a.kernelByTag)
	}
	return err
}

// nativeListen reports whether the mita core binds addresses itself
// (mita >= 3.37.0), making the ingress guard unnecessary.
func nativeListen(reg *core.Registry) bool {
	c, ok := reg.Get("mita")
	if !ok {
		return false
	}
	nl, ok := c.(interface{ NativeListen() bool })
	return ok && nl.NativeListen()
}

// validateNode drops the route and audit rules the cores would refuse and
// reports them; report gets one line per dropped rule (empty when all are
// fine). It returns a copy, or the node unchanged when nothing was wrong.
func validateNode(node *spec.Node, log *slog.Logger, report func([]string)) *spec.Node {
	var msgs []string
	routes := make([]spec.RouteRule, 0, len(node.Routes))
	for _, r := range node.Routes {
		if err := spec.ValidateRouteRule(r); err != nil {
			msgs = append(msgs, "route rule dropped: "+err.Error())
			continue
		}
		routes = append(routes, r)
	}
	rules := make([]spec.AuditRule, 0, len(node.AuditRules))
	for _, r := range node.AuditRules {
		if err := spec.ValidateAuditRule(r); err != nil {
			msgs = append(msgs, "audit rule dropped: "+err.Error())
			continue
		}
		rules = append(rules, r)
	}
	if report != nil {
		report(msgs)
	}
	if len(msgs) == 0 {
		return node
	}
	for _, m := range msgs {
		log.Error("panel sent a rule this node cannot render", "detail", m)
	}
	cp := *node
	cp.Routes, cp.AuditRules = routes, rules
	return &cp
}

// applyEgress also runs before bootstrap when disabled: offline panels must not
// leave a previous process's destination restrictions installed.
func (a *Agent) applyEgress(ctx context.Context, node *spec.Node) error {
	grants, err := node.PrivateGrants(a.users)
	if err != nil {
		return err
	}
	if a.Egress != nil {
		uid, _ := runas.IDs()
		allow := append([]string{}, a.EgressAllow...)
		// A private or link-local resolver is the node's only way to
		// resolve names; keep it reachable.
		upstreams := append([]spec.EgressUpstream{}, a.EgressUpstreams...)
		upstreams = append(upstreams, node.EgressUpstreams...)
		for _, resolver := range egressguard.ResolverAllow("") {
			for _, protocol := range []string{"tcp", "udp"} {
				upstreams = append(upstreams, spec.EgressUpstream{CIDR: resolver, Protocol: protocol, Port: 53})
			}
		}
		ports := append([]int{53}, a.EgressLoopbackPorts...)
		if node.Decoy != nil && node.Decoy.Port > 0 {
			ports = append(ports, node.Decoy.Port)
		}
		applyErr := a.Egress.Apply(ctx, uid, egressguard.Options{PrivateGrants: nftPrivateGrants(grants), Disabled: a.EgressDisabled, Upstreams: upstreams, Allow: allow, LoopbackPorts: ports, ProtectedPorts: a.EgressProtectedPorts})
		if applyErr != nil {
			a.log.Error("egress guard", "err", applyErr)
		}
		st := a.Egress.Status()
		a.setStatus(func(s *Status) {
			s.Egress = &st
			s.CoreUser = runas.Name()
		})
		return applyErr
	}
	return nil
}

func coreWaitsForUsers(name string, ib spec.Inbound) bool {
	return name == "mita" || name == "singbox-extended" && (ib.Protocol == spec.Mieru || ib.Protocol == spec.SSH)
}

// Core-only permissions are enforced by the renderer, never by nft grants.
func nftPrivateGrants(grants []spec.PrivateGrant) []spec.PrivateGrant {
	var out []spec.PrivateGrant
	for _, g := range grants {
		if !g.CoreOnly {
			out = append(out, g)
		}
	}
	return out
}
