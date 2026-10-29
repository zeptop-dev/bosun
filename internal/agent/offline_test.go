package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/zeptop-dev/bosun/internal/panel"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

type leasePanel struct {
	panel.Driver
	expired bool
	offline bool
}

func (p *leasePanel) ServiceLeaseError() error {
	if p.expired {
		return errors.New("expired test lease")
	}
	return nil
}
func TestOfflineLeaseStopsManagedServicesAndClearsConfirmation(t *testing.T) {
	a, c, _ := checkpointRig(t)
	p := &leasePanel{Driver: a.driver, expired: true}
	a.driver = p
	c.running = true
	a.appliedCoreRevision = "old"
	a.appliedForwardRevision = "old"
	if e := a.expireOfflineLease(context.Background()); e == nil {
		t.Fatal("missing expiry failure")
	}
	if c.running || a.appliedCoreRevision != "" || a.appliedForwardRevision != "" || !a.dirty {
		t.Fatal("expired service or confirmation survived")
	}
	// All local re-entry paths must reject the stale policy too.
	if e := a.apply(context.Background()); e == nil {
		t.Fatal("apply bypassed lease")
	}
	if e := a.applyForwards(context.Background()); e == nil {
		t.Fatal("forward apply bypassed lease")
	}
	p.expired = false
	if e := a.serviceLeaseError(); e != nil {
		t.Fatal(e)
	}
}

func (p *leasePanel) OfflineRecoveryActive() bool { return p.offline }
func TestOfflineRecoveryCannotChangeModeGeneration(t *testing.T) {
	a, c, _ := checkpointRig(t)
	a.driver = &leasePanel{Driver: a.driver, offline: true}
	c.running = true
	a.node.Mode = spec.NodeMonitor
	if err := a.expireOfflineLease(context.Background()); err == nil || c.running {
		t.Fatal("offline mode change was accepted")
	}
}

type leaseUpgradePanel struct{ leasePanel }

func (p *leaseUpgradePanel) UpgradeRequested() string { return "v9.0.0" }

func TestExpiredLeaseAcknowledgesTrafficWithoutStartingLateUpgrade(t *testing.T) {
	a, c, _ := checkpointRig(t)
	p := &leaseUpgradePanel{leasePanel{Driver: a.driver}}
	a.driver = p
	a.Upgrade = func(string) {}
	c.bytes = 100
	full, err := a.prepareDurableReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p.expired = true
	a.finishDurableReport(full, false, nil)
	if a.trafficJournal.Pending != nil {
		t.Fatal("accepted traffic was not acknowledged")
	}
	if a.upgradeAsked != "" {
		t.Fatal("late report started upgrade after lease expiry")
	}
}
