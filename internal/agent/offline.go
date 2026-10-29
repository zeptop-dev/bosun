package agent

import (
	"context"
	"errors"
)

func (a *Agent) serviceLeaseError() error {
	if source, ok := a.driver.(interface{ ServiceLeaseError() error }); ok {
		if err := source.ServiceLeaseError(); err != nil {
			return err
		}
		if offline, ok := a.driver.(interface{ OfflineRecoveryActive() bool }); ok && offline.OfflineRecoveryActive() && a.node != nil {
			if a.node.Mode.Effective() != a.cfg.NodeMode.Effective() || a.node.ModeRevision != a.modeRevision() {
				return errors.New("offline recovery cannot change node mode generation")
			}
		}
	}
	return nil
}

// Called by the serial owner, including while control-plane polling fails. Never
// turn an expired cached authorization into an unbounded local service grant.
func (a *Agent) expireOfflineLease(ctx context.Context) error {
	if err := a.serviceLeaseError(); err != nil && a.node != nil {
		a.shaperMu.Lock()
		defer a.shaperMu.Unlock()
		a.setAppliedCoreRevision("")
		a.setAppliedForwardRevision("")
		a.coreDirty, a.forwardDirty, a.dirty = true, true, true
		stopErr := a.stopControlledServices(ctx)
		a.setStatus(func(s *Status) { s.LastError = err.Error() })
		return errors.Join(err, stopErr)
	}
	return nil
}
