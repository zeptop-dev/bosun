package agent

import (
	"context"
	"time"
)

const (
	dependencyShaper uint8 = 1 << iota
	dependencyEgress
	dependencyRecoveryMax = 3
)

// Owned by the serial control loop. No saved node/user snapshot is retained:
// every attempt uses the state just consumed by a successful pull. Exhaustion
// remains armed so an incapable container cannot enter the normal dirty loop.
type dependencyRecovery struct {
	missing  uint8
	attempts int
	next     time.Time
}

func (a *Agent) dependencyRecoveryAllowed() bool {
	if !a.proxyModeReady(a.node) || a.serviceControlPaused() || a.serviceLeaseError() != nil {
		return false
	}
	if source, ok := a.driver.(interface{ OfflineRecoveryActive() bool }); ok && source.OfflineRecoveryActive() {
		return false
	}
	return true
}

func (a *Agent) missingNetworkDependencies() uint8 {
	if !a.dependencyRecoveryAllowed() {
		return 0
	}
	var missing uint8
	if a.Egress != nil && !a.Egress.Supported() {
		missing |= dependencyEgress
	}
	if a.Shaper != nil && !a.Shaper.Supported() {
		for _, u := range a.users {
			if a.node.EffectiveSpeedLimit(u) > 0 {
				missing |= dependencyShaper
			}
		}
		for _, ib := range a.node.Inbounds {
			for _, u := range ib.EffectiveUsers(a.users) {
				if a.node.EffectiveSpeedLimit(u) > 0 {
					missing |= dependencyShaper
				}
			}
		}
	}
	return missing
}

func (a *Agent) recordDependencyApply(missing uint8) {
	if !a.dependencyRecoveryAllowed() {
		a.dependencyRecovery = dependencyRecovery{}
		return
	}
	r := &a.dependencyRecovery
	r.missing |= missing
	st := a.Status()
	if r.missing&dependencyEgress != 0 && missing&dependencyEgress == 0 && st.Egress != nil && st.Egress.Supported && st.Egress.Error == "" {
		r.missing &^= dependencyEgress
	}
	if r.missing&dependencyShaper != 0 && missing&dependencyShaper == 0 && !a.configUserLimitsOmitted && st.Shaper != nil && st.Shaper.Supported && st.Shaper.Error == "" && st.Shaper.DownloadError == "" {
		r.missing &^= dependencyShaper
	}
	if r.missing == 0 {
		a.dependencyRecovery = dependencyRecovery{}
	}
}

// Called only after a successful pull, never by a diagnostic GET. A PATH/tool
// transition is enough to try; it is not proof of kernel permissions or HTB/IFB.
func (a *Agent) dependencyRetryDue(at time.Time) bool {
	if !a.dependencyRecoveryAllowed() {
		// Keep the dependency failure as the owner of this retry budget.
		// Clearing it here would expose coreDirty to the unbounded legacy
		// retry path while authorization is unavailable. A new state resets it.
		return false
	}
	r := &a.dependencyRecovery
	if r.missing == 0 || r.attempts >= dependencyRecoveryMax || at.Before(r.next) {
		return false
	}
	// Restore nft protection as soon as it is available, even if tc/ip are
	// still missing. Successful helpers leave the pending mask separately.
	ready := r.missing&dependencyShaper != 0 && a.Shaper != nil && a.Shaper.Supported() ||
		r.missing&dependencyEgress != 0 && a.Egress != nil && a.Egress.Supported()
	if !ready {
		return false
	}
	r.attempts++
	r.next = at.Add(retryFloor * time.Duration(1<<(r.attempts-1)))
	a.log.Info("network dependencies available; retrying current configuration", "attempt", r.attempts, "maximum", dependencyRecoveryMax)
	return true
}

func (a *Agent) reconcileAfterPull(ctx context.Context, changed bool, at time.Time) bool {
	if changed {
		a.dependencyRecovery = dependencyRecovery{}
	}
	recoverDependencies := !changed && a.dependencyRetryDue(at)
	coreRetry := a.coreApplyRetryDue(at)
	forwardRetry := a.forwardDirty && at.Sub(a.lastForwardAttempt) >= retryFloor
	applyCore := changed || recoverDependencies || coreRetry
	if applyCore {
		if err := a.apply(ctx); err != nil {
			a.log.Error("apply failed", "err", err)
		}
	}
	// A forward-only retry must not restart cores past their dependency budget.
	if applyCore || forwardRetry {
		if err := a.applyForwards(ctx); err != nil {
			a.log.Error("forwards", "err", err)
		}
	}
	return applyCore || forwardRetry
}

// Mark only hard errors from helper initialization. A simultaneous, unrelated
// core render/start error must retain the existing retry path.
type networkDependencyError struct{ error }

func (e *networkDependencyError) Unwrap() error { return e.error }
func dependencyFailure(err error) error {
	if err == nil {
		return nil
	}
	return &networkDependencyError{err}
}
func isDependencyFailure(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := err.(*networkDependencyError); ok {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		errs := joined.Unwrap()
		if len(errs) == 0 {
			return false
		}
		for _, e := range errs {
			if !isDependencyFailure(e) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return isDependencyFailure(wrapped.Unwrap())
	}
	return false
}
