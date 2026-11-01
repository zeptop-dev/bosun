package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

type renderedTestCore struct {
	*lifecycleCounter
	artifact *agentproto.RenderedArtifact
}

func (c *renderedTestCore) RenderedConfig() *agentproto.RenderedArtifact { return c.artifact }

func renderedRig(t *testing.T) (*Agent, *configRevisionPanel, *renderedTestCore) {
	t.Helper()
	a, p, old := configRevisionRig(t)
	c := &renderedTestCore{lifecycleCounter: old, artifact: &agentproto.RenderedArtifact{Core: "singbox", Digest: "rcf1-" + strings.Repeat("a", 64), DigestScope: "process", Scope: "activation_files", Format: "json", Files: 1, Processes: 1, ActivatedAt: time.Now().Add(-time.Second).UTC()}}
	a.reg.Replace("singbox", c)
	return a, p, c
}

func TestRenderedEvidenceRequiresAppliedCurrentDeliveryAndEveryCore(t *testing.T) {
	a, p, c := renderedRig(t)
	if got := a.buildReport(nil, spec.SystemStatus{}).RenderedConfig.Status; got != "unavailable" {
		t.Fatal("unapplied state acquired evidence", got)
	}
	applyRevision(t, a)
	first := a.buildReport(nil, spec.SystemStatus{})
	if first.RenderedConfig.Status != "observed" || len(first.RenderedConfig.Artifacts) != 1 {
		t.Fatal("valid applied activation missing", first.RenderedConfig)
	}
	p.advance("second", "new-delivery")
	second := a.buildReport(nil, spec.SystemStatus{})
	if second.RenderedConfig.Status != "unavailable" || second.ConfigReceipt.DeliveryID == first.ConfigReceipt.DeliveryID {
		t.Fatal("new full state borrowed current evidence")
	}
	applyRevision(t, a)
	if got := a.buildReport(nil, spec.SystemStatus{}).RenderedConfig.Status; got != "observed" {
		t.Fatal("independent reapply did not recover", got)
	}
	c.artifact = nil // core process generation changed
	if got := a.buildReport(nil, spec.SystemStatus{}).RenderedConfig.Status; got != "unavailable" {
		t.Fatal("process replacement borrowed old evidence", got)
	}
	// A pre-feature/unknown adapter still supports ordinary configuration
	// receipts; it cannot claim actual rendered evidence.
	a.reg.Replace("singbox", c.lifecycleCounter)
	r := a.buildReport(nil, spec.SystemStatus{})
	if !r.ConfigReceipt.Applied || r.RenderedConfig.Status != "unavailable" {
		t.Fatal("legacy core affected compatibility or borrowed evidence")
	}
}

func TestRenderedEvidenceFrozenReportsDeathAndUnavailableIdentity(t *testing.T) {
	a, p, c := renderedRig(t)
	applyRevision(t, a)
	frozen := a.buildReport(nil, spec.SystemStatus{})
	want := frozen.RenderedConfig.Artifacts[0]
	c.artifact.Digest = "rcf1-" + strings.Repeat("b", 64)
	if frozen.RenderedConfig.Artifacts[0] != want {
		t.Fatal("asynchronous report borrowed mutable adapter state")
	}
	_ = c.Stop(context.Background())
	now := a.buildReport(nil, spec.SystemStatus{})
	if now.RenderedConfig.Status != "unavailable" || len(now.RenderedConfig.Artifacts) != 0 || now.ConfigReceipt.Applied {
		t.Fatal("exited core retained current evidence")
	}
	p.offline = true
	now = a.buildReport(nil, spec.SystemStatus{})
	if now.ConfigReceipt != nil || now.RenderedConfig.Status != "unavailable" || len(now.RenderedConfig.Artifacts) != 0 {
		t.Fatal("offline state borrowed delivery identity")
	}
}

func TestRenderedEvidenceIdleIsExplicitAndMalformedCoreFailsClosed(t *testing.T) {
	a, _, c := renderedRig(t)
	a.node.Inbounds = nil
	applyRevision(t, a)
	r := a.buildReport(nil, spec.SystemStatus{})
	if !r.ConfigReceipt.Applied || r.RenderedConfig.Status != "observed" || len(r.RenderedConfig.Artifacts) != 0 {
		t.Fatal("successfully idle configuration must be explicit", r.RenderedConfig)
	}
	a.node.Inbounds = []spec.Inbound{{Tag: "listener", Protocol: spec.VLESS, Port: 443}}
	applyRevision(t, a)
	c.artifact.Core = "private-path"
	r = a.buildReport(nil, spec.SystemStatus{})
	if r.RenderedConfig.Status != "unavailable" || len(r.RenderedConfig.Artifacts) != 0 {
		t.Fatal("unexpected adapter metadata escaped")
	}
}
