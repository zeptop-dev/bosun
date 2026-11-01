package agent

import "github.com/zeptop-dev/bosun/pkg/agentproto"

// renderedConfig observes adapters' accepted activation files, never Render or
// the desired Node model. The receipt binds this observation to the exact
// consumed full-state delivery. Adapter evidence separately binds every child
// generation, so an automatic restart cannot borrow a former process's files.
func (a *Agent) renderedConfig(receipt *agentproto.ConfigReceipt, observed map[string]agentproto.CoreStatus) *agentproto.RenderedConfigReport {
	out := &agentproto.RenderedConfigReport{Version: 1, Status: "unavailable", Artifacts: []agentproto.RenderedArtifact{}}
	if receipt == nil {
		return out
	}
	a.statusMu.Lock()
	expected := map[string]bool{}
	for name, tags := range a.appliedCores {
		expected[name] = len(tags) > 0
	}
	a.statusMu.Unlock()
	if a.kernelNode != nil && len(a.kernelNode.ReverseClients) > 0 {
		expected["xray"] = true
	}
	complete := receipt.Applied
	for _, name := range a.reg.Names() {
		adapter, ok := a.reg.Get(name)
		if !ok {
			complete = false
			continue
		}
		if !adapter.Running() {
			if expected[name] {
				complete = false
			}
			delete(expected, name)
			continue
		}
		delete(expected, name)
		source, ok := adapter.(interface {
			RenderedConfig() *agentproto.RenderedArtifact
		})
		if !ok || !observed[name].Running {
			complete = false
			continue
		}
		artifact := source.RenderedConfig()
		if artifact == nil || artifact.Core != name || artifact.ActivatedAt.After(receipt.ObservedAt) || agentproto.ValidateRenderedConfigReport(&agentproto.RenderedConfigReport{Version: 1, Status: "observed", Artifacts: []agentproto.RenderedArtifact{*artifact}}) != nil {
			complete = false
			continue
		}
		out.Artifacts = append(out.Artifacts, *artifact)
	}
	for _, needed := range expected {
		if needed {
			complete = false
		}
	}
	if complete {
		out.Status = "observed"
	}
	if agentproto.ValidateRenderedConfigReport(out) != nil {
		out.Status, out.Artifacts = "unavailable", []agentproto.RenderedArtifact{}
	}
	return out
}
