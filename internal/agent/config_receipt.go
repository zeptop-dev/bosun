package agent

import (
	"time"

	"github.com/zeptop-dev/bosun/internal/panel"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

func (a *Agent) partialConfig() {
	a.statusMu.Lock()
	a.configCorePartial = true
	a.statusMu.Unlock()
}

// This is a new observation, frozen with the report before asynchronous HTTP.
// Accounting retry identity is deliberately unrelated to this sequence.
func (a *Agent) configReceipt(appliedRevision string) *agentproto.ConfigReceipt {
	source, ok := a.driver.(panel.ConsumedConfigSource)
	if !ok {
		return nil
	}
	session, node, forwards := source.ConsumedConfig()
	if !node.Valid() || node != forwards || node.Session != session || a.serviceLeaseError() != nil {
		return nil
	}
	if offline, ok := a.driver.(interface{ OfflineRecoveryActive() bool }); ok && offline.OfflineRecoveryActive() {
		return nil
	}
	paused := a.serviceControlPaused()
	modeReady := a.node != nil && a.node.Mode.Effective() == a.cfg.NodeMode.Effective() && a.node.ModeRevision == a.modeRevision()
	a.statusMu.Lock()
	defer a.statusMu.Unlock()
	a.configReceiptSequence++
	applied := appliedRevision == node.StateRevision && a.appliedCoreConfig == node && a.appliedForwardConfig == node && !a.configCorePartial && !a.configUserLimitsOmitted && !a.coreDirty && !a.forwardDirty && !a.modeChanging.Load() && !a.forceRestart && !paused && modeReady
	// Helpers can fail outside core rendering. A configuration receipt must not
	// turn their explicitly reported partial enforcement into a green result.
	if s := a.status; s.Guard != nil && s.Guard.Error != "" || s.Egress != nil && s.Egress.Error != "" || s.Firewall != nil && s.Firewall.Error != "" || s.Shaper != nil && (s.Shaper.Error != "" || s.Shaper.DownloadError != "") {
		applied = false
	}
	return &agentproto.ConfigReceipt{DeliveryID: node.DeliveryID, Session: session, ConfigRevision: node.ConfigRevision, StateRevision: node.StateRevision, Sequence: a.configReceiptSequence, ObservedAt: time.Now().UTC(), Applied: applied}
}
