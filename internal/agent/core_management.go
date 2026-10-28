package agent

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

type coreChange struct {
	ctx     context.Context
	request spec.CoreRequest
	done    chan error
}

func (a *Agent) CoreInventory() *spec.CoreInventory {
	if a.CoreManager == nil {
		return nil
	}
	return a.CoreManager.Inventory()
}

// ManageCore downloads in a worker but serializes activation with apply and
// reporting. An expired request never becomes a delayed surprise restart.
func (a *Agent) ManageCore(ctx context.Context, r spec.CoreRequest) error {
	if a.MonitorOnly() || a.modeChanging.Load() {
		return spec.ErrMonitorOnly
	}
	m := a.CoreManager
	if m == nil {
		return errors.New("core management is unavailable")
	}
	if !m.TryLock() {
		return errors.New("another core operation is in progress")
	}
	defer m.Unlock()
	if a.modeChanging.Load() {
		return spec.ErrMonitorOnly
	}
	if m.AlreadyApplied(r) {
		return nil
	}
	if _, err := m.Validate(r); err != nil {
		return err
	}
	if r.Action == "download" {
		return m.Download(ctx, r)
	}
	change := coreChange{ctx: ctx, request: r, done: make(chan error, 1)}
	select {
	case a.coreChanges <- change:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-change.done:
		return err
	case <-ctx.Done():
		// The loop must finish rollback before a subsequent operation starts.
		return <-change.done
	}
}

func (a *Agent) activateCore(runCtx, ctx context.Context, r spec.CoreRequest) error {
	m := a.CoreManager
	if a.serviceControlPaused() {
		return errors.New("resume proxy services before activating a core")
	}
	if a.dirty {
		return errors.New("resolve the failed configuration apply before switching cores")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := m.Validate(r); err != nil {
		return err
	}
	if m.Factory == nil {
		return errors.New("core factory is unavailable")
	}
	old, _ := a.reg.Get(r.Distribution)
	// Isolated configuration paths keep validation from overwriting the old
	// process's configuration before we know the replacement can start.
	work := filepath.Join(a.cfg.DataDir, "core-runtime", r.Distribution, r.Version)
	next, err := m.Factory(r.Distribution, m.Install.Path(r.Distribution, r.Version), work)
	if err != nil {
		return err
	}
	node := a.kernelNode
	if node == nil {
		node = &spec.Node{}
	}
	candidates := a.reg.Candidates()
	replaced := false
	for i := range candidates {
		if candidates[i].Name == r.Distribution {
			candidates[i].Capabilities = next.Capabilities()
			replaced = true
		}
	}
	if !replaced {
		candidates = append(candidates, spec.CoreCandidate{Name: r.Distribution, Capabilities: next.Capabilities()})
	}
	var inbounds []spec.Inbound
	for _, ib := range node.Inbounds {
		before, _ := spec.SelectCore(ib, a.reg.Candidates())
		after, selectErr := spec.SelectCore(ib, candidates)
		if selectErr != nil && before == r.Distribution {
			return selectErr
		}
		if before != "" && before != after {
			return fmt.Errorf("enabling this core would move inbound %q; explicitly pin that inbound first", ib.Tag)
		}
		if after == r.Distribution && !(coreWaitsForUsers(after, ib) && len(ib.EffectiveUsers(a.users)) == 0) {
			inbounds = append(inbounds, ib)
		}
	}
	needed := len(inbounds) > 0 || r.Distribution == "xray" && len(node.ReverseClients) > 0
	var bundle, previous *core.Bundle
	if needed {
		bundle, err = next.Render(node, inbounds, a.users)
		if err != nil {
			return err
		}
		if check, ok := next.(interface {
			Check(context.Context, *core.Bundle) error
		}); ok {
			if err = check.Check(ctx, bundle); err != nil {
				return err
			}
		}
		if old != nil && old.Running() {
			previous, err = old.Render(node, inbounds, a.users)
			if err != nil {
				return err
			}
		}
	}
	// Activation/rollback may stop a previously applied core. A subsequent
	// full apply must confirm the configuration, including failed activation.
	a.setAppliedCoreRevision("")
	defer func() {
		select {
		case a.kick <- struct{}{}:
		default:
		}
	}()
	if old != nil && old.Running() {
		if err = a.drainBeforeCoreChange(ctx, old); err != nil {
			return err
		}
		if err = old.Stop(ctx); err != nil {
			return err
		}
	}
	rollback := func(cause error) error {
		// Cancellation of the request must not cancel restoration of service.
		recoverCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		stopErr := next.Stop(recoverCtx)
		if previous != nil {
			startErr := old.Start(runCtx, previous)
			if startErr == nil {
				startErr = healthyCore(recoverCtx, old)
			}
			if startErr != nil {
				return errors.Join(cause, stopErr, fmt.Errorf("previous core could not be restored: %w", startErr))
			}
		}
		return errors.Join(cause, stopErr)
	}
	if needed {
		if err = next.Start(runCtx, bundle); err != nil {
			return rollback(err)
		}
		if err = healthyCore(ctx, next); err != nil {
			return rollback(err)
		}
	}
	if err = ctx.Err(); err != nil {
		return rollback(err)
	}
	if err = m.Commit(r, a.reg.Names()); err != nil {
		return rollback(err)
	}
	a.reg.Replace(r.Distribution, next)
	a.rememberCoreUsers(r.Distribution, inbounds)
	a.statusMu.Lock()
	if a.appliedCores == nil {
		a.appliedCores = map[string][]string{}
	}
	a.appliedCores[r.Distribution] = nil
	for _, ib := range inbounds {
		a.appliedCores[r.Distribution] = append(a.appliedCores[r.Distribution], ib.Tag)
	}
	a.statusMu.Unlock()
	select {
	case a.reportNow <- struct{}{}:
	default:
	}
	return nil
}

func healthyCore(ctx context.Context, c core.Core) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	readySince := time.Time{}
	for {
		if c.Running() {
			probe, cancel := context.WithTimeout(ctx, time.Second)
			_, err := c.Stats(probe, false)
			cancel()
			if err == nil {
				if readySince.IsZero() {
					readySince = time.Now()
				}
				if time.Since(readySince) >= 400*time.Millisecond {
					return nil
				}
			} else {
				readySince = time.Time{}
			}
		} else {
			readySince = time.Time{}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("core did not become ready: %w", ctx.Err())
		case <-tick.C:
		}
	}
}

func (a *Agent) drainBeforeCoreChange(ctx context.Context, c core.Core) error {
	if _, err := c.Stats(ctx, false); err != nil {
		return fmt.Errorf("cannot read old core counters: %w", err)
	}
	if err := a.checkpointTraffic(ctx); err != nil {
		return fmt.Errorf("save traffic before switching cores: %w", err)
	}
	return nil
}
