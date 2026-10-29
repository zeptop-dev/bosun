package agent

import (
	"time"

	"github.com/zeptop-dev/bosun/internal/panel"
)

// A periodic WireGuard/core-only reconcile must neither clear a failed
// forward apply nor postpone its retry by continually resetting lastAttempt.
func (a *Agent) applyRetryDue(at time.Time) bool {
	return a.coreDirty && at.Sub(a.lastAttempt) >= retryFloor ||
		a.forwardDirty && at.Sub(a.lastForwardAttempt) >= retryFloor
}

func (a *Agent) consumedRevisions() (string, string) {
	if source, ok := a.driver.(panel.ConsumedRevisionSource); ok {
		return source.ConsumedRevisions()
	}
	return "", ""
}

func (a *Agent) setAppliedCoreRevision(revision string) {
	metadata := panel.ConfigState{}
	if source, ok := a.driver.(panel.ConsumedConfigSource); ok && revision != "" {
		_, metadata, _ = source.ConsumedConfig()
		if metadata.StateRevision != revision || !metadata.Valid() {
			metadata = panel.ConfigState{}
		}
	}
	a.statusMu.Lock()
	a.appliedCoreRevision = revision
	a.appliedCoreConfig = metadata
	a.statusMu.Unlock()
}

func (a *Agent) setAppliedForwardRevision(revision string) {
	metadata := panel.ConfigState{}
	if source, ok := a.driver.(panel.ConsumedConfigSource); ok && revision != "" {
		_, _, metadata = source.ConsumedConfig()
		if metadata.StateRevision != revision || !metadata.Valid() {
			metadata = panel.ConfigState{}
		}
	}
	a.statusMu.Lock()
	a.appliedForwardRevision = revision
	a.appliedForwardConfig = metadata
	a.statusMu.Unlock()
}
