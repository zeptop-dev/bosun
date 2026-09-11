// Package agent is the managed-mode control loop: pull desired state from the
// panel, render it onto cores, and push accounting back.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"gitlab.com/boyang-hu/bosun/internal/config"
	"gitlab.com/boyang-hu/bosun/internal/core"
	"gitlab.com/boyang-hu/bosun/internal/forward"
	"gitlab.com/boyang-hu/bosun/internal/metrics"
	"gitlab.com/boyang-hu/bosun/internal/panel"
	"gitlab.com/boyang-hu/bosun/internal/sysinfo"
	"gitlab.com/boyang-hu/bosun/pkg/agentproto"
	"gitlab.com/boyang-hu/bosun/pkg/spec"
)

// Agent wires one panel driver to a core registry.
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
}

// New builds an agent. metrics may be nil.
func New(cfg *config.Config, driver panel.Driver, reg *core.Registry, mreg *metrics.Registry, log *slog.Logger) *Agent {
	a := &Agent{cfg: cfg, driver: driver, reg: reg, fwd: forward.NewManager(log), metrics: mreg, log: log.With("component", "agent")}
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
		return fmt.Errorf("initial apply: %w", err)
	}
	if err := a.applyForwards(ctx); err != nil {
		a.log.Error("forwards", "err", err)
	}

	iv := a.driver.Intervals()
	pull := time.NewTicker(iv.Pull)
	push := time.NewTicker(iv.Push)
	defer pull.Stop()
	defer push.Stop()
	a.log.Info("running", "pull", iv.Pull, "push", iv.Push)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-pull.C:
			if changed, err := a.pull(ctx); err != nil {
				a.log.Warn("pull failed", "err", err)
			} else if changed {
				if err := a.apply(ctx); err != nil {
					a.log.Error("apply failed", "err", err)
				}
				if err := a.applyForwards(ctx); err != nil {
					a.log.Error("forwards", "err", err)
				}
			}
			if niv := a.driver.Intervals(); niv != iv {
				iv = niv
				pull.Reset(iv.Pull)
				push.Reset(iv.Push)
				a.log.Info("intervals updated", "pull", iv.Pull, "push", iv.Push)
			}
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
				}
			}
		}
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
		ResolveCerts(a.cfg, node, a.log)
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
		if t == nil || t.Mode != spec.TLSStandard {
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

// apply renders the current state onto each core and starts, restarts or
// stops cores as their assignment changes.
func (a *Agent) apply(ctx context.Context) error {
	assign, err := a.reg.Assign(a.node.Inbounds)
	if err != nil {
		return err
	}
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
		bundle, err := c.Render(a.node, inbounds, a.users)
		if err != nil {
			return fmt.Errorf("%s: render: %w", name, err)
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

// report collects per-user traffic from every running core and pushes it
// with a host snapshot. It returns true when the panel signals newer state.
func (a *Agent) report(ctx context.Context) bool {
	totals := map[int64]*spec.UserTraffic{}
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
	host := sysinfo.Snapshot(ctx)

	if rep, ok := a.driver.(panel.Reporter); ok {
		changed, err := rep.Report(ctx, a.buildReport(list, host))
		if err != nil {
			// Counters were already reset; this delta is lost. A persistent
			// spool is a later improvement.
			a.log.Error("report failed", "users", len(list), "err", err)
			return false
		}
		a.log.Debug("report sent", "users", len(list), "state_changed", changed)
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
	rep := agentproto.Report{Traffic: traffic, Host: host, Cores: map[string]agentproto.CoreStatus{}}
	for _, name := range a.reg.Names() {
		c, _ := a.reg.Get(name)
		rep.Cores[name] = agentproto.CoreStatus{Running: c.Running()}
	}
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

func (a *Agent) registerMetrics() {
	m := a.metrics
	m.Describe("bosun_core_running", "gauge", "1 if the core process is running")
	m.Describe("bosun_users", "gauge", "users currently provisioned")
	m.Describe("bosun_forward_up", "gauge", "1 if the forward target answered the last probe")
	m.Describe("bosun_forward_probe_rtt_seconds", "gauge", "last probe round trip to the forward target")
	m.Describe("bosun_forward_connections_active", "gauge", "open relayed connections or udp sessions")
	m.Describe("bosun_forward_connections_total", "counter", "relayed connections or udp sessions since start")
	m.Describe("bosun_forward_bytes_total", "counter", "relayed bytes by direction (in = client to target)")
	m.Add(func() []metrics.Sample {
		var out []metrics.Sample
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
