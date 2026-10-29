package agent

import (
	"time"

	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/panel"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func (a *Agent) partialConfig() {
	a.statusMu.Lock()
	a.configCorePartial = true
	a.statusMu.Unlock()
}

// Decoy certificate acquisition and listener failure are asynchronous. Read its
// live status, rather than the status copied immediately after Configure.
func (a *Agent) configDecoyReady() bool {
	if a.node == nil {
		return false
	}
	desired := a.node.Decoy
	if a.Decoy == nil {
		return desired == nil
	}
	actual := a.Decoy.Status()
	if desired == nil || desired.Domain == "" {
		// Configure(nil) clears cfg and Status becomes nil only after stopping
		// the managed listener. Stop alone leaves a configured, stopped status.
		return actual == nil
	}
	return actual != nil && actual.Domain == desired.Domain && actual.Port == desired.EffectivePort() && actual.Upstream == desired.Upstream && actual.Running && actual.CertReady && actual.Error == ""
}

// A past successful apply cannot confirm the current process after it exits.
// Assignment comes from the accepted render, preserving expected no-user idle
// inbounds and unused registered adapters. Remote forward probes are separate.
func (a *Agent) configRuntimeReady(observed map[string]agentproto.CoreStatus) bool {
	a.statusMu.Lock()
	assigned := make(map[string][]string, len(a.appliedCores))
	for name, tags := range a.appliedCores {
		assigned[name] = append([]string(nil), tags...)
	}
	a.statusMu.Unlock()
	if a.kernelNode != nil && len(a.kernelNode.ReverseClients) > 0 {
		// The reverse-only Xray process has no business inbound tags.
		if _, ok := assigned["xray"]; !ok {
			assigned["xray"] = nil
		}
	}
	for name, tags := range assigned {
		reverse := name == "xray" && a.kernelNode != nil && len(a.kernelNode.ReverseClients) > 0
		if len(tags) == 0 && !reverse {
			continue
		}
		adapter, ok := a.reg.Get(name)
		if !ok || !observed[name].Running || !adapter.Running() {
			return false
		}
		var expected []spec.Inbound
		if a.kernelNode != nil {
			for _, inbound := range a.kernelNode.Inbounds {
				for _, tag := range tags {
					if inbound.Tag == tag {
						expected = append(expected, inbound)
						break
					}
				}
			}
		}
		if processes, ok := adapter.(core.ListenerProcesses); ok {
			pids := processes.ListenerPIDs()
			for _, tag := range tags {
				if pids[tag] <= 0 && pids["*"] <= 0 {
					return false
				}
			}
		}
		if err := core.CheckListeners(adapter, expected); err != nil {
			return false
		}
	}
	if a.node != nil {
		rules := append(a.cfg.ForwardSpecs(), a.node.Forwards...)
		for _, rule := range rules {
			if rule.Backend == "realm" && !a.Realm.Running() {
				return false
			}
		}
	}
	return true
}

// This is a new observation, frozen with the report before asynchronous HTTP.
// Accounting retry identity is deliberately unrelated to this sequence.
func (a *Agent) configReceipt(appliedRevision string, observed map[string]agentproto.CoreStatus) *agentproto.ConfigReceipt {
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
	decoyReady := a.configDecoyReady()
	runtimeReady := a.configRuntimeReady(observed)
	a.statusMu.Lock()
	defer a.statusMu.Unlock()
	a.configReceiptSequence++
	applied := appliedRevision == node.StateRevision && a.appliedCoreConfig == node && a.appliedForwardConfig == node && !a.configCorePartial && !a.configUserLimitsOmitted && !a.coreDirty && !a.forwardDirty && !a.modeChanging.Load() && !a.forceRestart && !paused && modeReady && decoyReady && runtimeReady
	// Helpers can fail outside core rendering. A configuration receipt must not
	// turn their explicitly reported partial enforcement into a green result.
	if s := a.status; s.Guard != nil && s.Guard.Error != "" || s.Egress != nil && s.Egress.Error != "" || s.Firewall != nil && s.Firewall.Error != "" || s.Shaper != nil && (s.Shaper.Error != "" || s.Shaper.DownloadError != "") {
		applied = false
	}
	return &agentproto.ConfigReceipt{DeliveryID: node.DeliveryID, Session: session, ConfigRevision: node.ConfigRevision, StateRevision: node.StateRevision, Sequence: a.configReceiptSequence, ObservedAt: time.Now().UTC(), Applied: applied}
}
