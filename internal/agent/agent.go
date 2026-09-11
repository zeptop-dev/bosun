// Package agent is the managed-mode control loop: pull desired state from the
// panel, render it onto cores, and push accounting back.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"gitlab.com/zeptop-group/bosun/internal/config"
	"gitlab.com/zeptop-group/bosun/internal/core"
	"gitlab.com/zeptop-group/bosun/internal/panel"
	"gitlab.com/zeptop-group/bosun/internal/spec"
	"gitlab.com/zeptop-group/bosun/internal/sysinfo"
)

// Agent wires one panel driver to a core registry.
type Agent struct {
	cfg    *config.Config
	driver panel.Driver
	reg    *core.Registry
	log    *slog.Logger

	node  *spec.Node
	users []spec.User
	// userIDs maps spec.User.Name (the stats key) to the panel user ID.
	userIDs map[string]int64
}

// New builds an agent.
func New(cfg *config.Config, driver panel.Driver, reg *core.Registry, log *slog.Logger) *Agent {
	return &Agent{cfg: cfg, driver: driver, reg: reg, log: log.With("component", "agent")}
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
			}
			if niv := a.driver.Intervals(); niv != iv {
				iv = niv
				pull.Reset(iv.Pull)
				push.Reset(iv.Push)
				a.log.Info("intervals updated", "pull", iv.Pull, "push", iv.Push)
			}
		case <-push.C:
			a.report(ctx)
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
		a.userIDs = make(map[string]int64, len(users))
		for _, u := range users {
			a.userIDs[u.Name] = u.ID
		}
		changed = true
		a.log.Info("user list updated", "users", len(users))
	}
	return changed, nil
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

// report collects per-user traffic from every running core and pushes it,
// then pushes a host status snapshot.
func (a *Agent) report(ctx context.Context) {
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
	if len(totals) > 0 {
		list := make([]spec.UserTraffic, 0, len(totals))
		for _, t := range totals {
			list = append(list, *t)
		}
		if err := a.driver.PushTraffic(ctx, list); err != nil {
			// Counters were already reset; this delta is lost. Acceptable for
			// the first cut, a persistent spool is a later improvement.
			a.log.Error("push traffic failed", "users", len(list), "err", err)
		} else {
			a.log.Debug("traffic pushed", "users", len(list))
		}
	}
	if err := a.driver.PushStatus(ctx, sysinfo.Snapshot(ctx)); err != nil {
		a.log.Warn("push status failed", "err", err)
	}
}

func (a *Agent) stopAll() {
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
