package agent

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/servicecontrol"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestOfflineServiceControlMissingCountersInstallsPauseBeforeStop(t *testing.T) {
	a, c, _ := checkpointRig(t)
	var script string
	fail := false
	a.ServiceControl = &servicecontrol.Manager{Dir: t.TempDir(), Run: serviceControlTestRunner(&script, &fail)}
	now := time.Now()
	a.node.ServiceControl = &spec.ServiceControl{Revision: "offline", Mode: "normal", Offline: &spec.OfflineServiceControl{PolicyID: "policy", Cycle: 1, Action: "limit", LimitMbps: 10, ThresholdPercent: 80, QuotaBytes: 1000, Direction: "sum", AutoResume: true, ManualMode: "normal", PeriodStart: now.Add(-time.Hour).Unix(), PeriodEnds: []int64{now.Add(time.Hour).Unix()}, Anchor: spec.OfflineTrafficAnchor{Epoch: "unavailable", Sequence: 1, At: now.Unix(), Networks: []spec.NetworkResource{{Name: "not-a-real-interface", ID: "boot:1", Included: true}}}}}
	c.statsErr = errors.New("customer counter unavailable")
	if err := a.refreshOfflineServiceControl(context.Background()); err == nil {
		t.Fatal("missing metering evidence was accepted")
	}
	if c.running || !a.serviceControlPaused() {
		t.Fatal("missing evidence left proxy running")
	}
	if got := a.serviceControlReport(); !got.OfflineSupported || got.Offline == nil || got.Offline.State != "error" || got.AppliedRevision != "" {
		t.Fatal(got)
	}
}
func TestOfflineServiceControlTimerRestoresStoppedCore(t *testing.T) {
	a, c, _ := checkpointRig(t)
	ctx := context.Background()
	host := a.SampleHost(ctx)
	if host.Resources == nil {
		t.Skip("host has no resource counters")
	}
	r := host.Resources
	var nets []spec.NetworkResource
	for _, n := range r.Networks {
		if n.Included && n.ID != "" {
			nets = append(nets, n)
		}
	}
	if len(nets) == 0 {
		t.Skip("host has no identified included interface")
	}
	now := time.Now()
	var script string
	fail := false
	a.ServiceControl = &servicecontrol.Manager{Dir: t.TempDir(), Run: serviceControlTestRunner(&script, &fail)}
	a.node.ServiceControl = &spec.ServiceControl{Revision: "resume", Mode: "normal", Offline: &spec.OfflineServiceControl{PolicyID: "fresh-policy", Cycle: 1, Action: "limit", LimitMbps: 10, ThresholdPercent: 100, QuotaBytes: math.MaxInt64, Direction: "sum", AutoResume: true, ManualMode: "normal", PeriodStart: now.Add(-time.Hour).Unix(), PeriodEnds: []int64{now.Add(time.Hour).Unix()}, Anchor: spec.OfflineTrafficAnchor{Epoch: r.Epoch, Sequence: r.Sequence, At: now.Unix(), Networks: nets}}}
	a.resolvedServiceControl = &spec.ServiceControl{Revision: "resume", Mode: "pause"}
	c.running = false
	// Both the independent guard timer and 15-second meter timer take this path.
	if err := a.refreshServiceControl(ctx); err != nil {
		t.Fatal(err)
	}
	if !c.running || a.serviceControlPaused() {
		t.Fatal("guard released but managed process stayed stopped")
	}
	if got := a.serviceControlReport(); got.Offline == nil || got.Offline.State != "ready" || got.AppliedRevision != "resume" {
		t.Fatal(got)
	}
	// Entering and leaving rate control must rebuild relay/core configuration,
	// because SetServiceControl retires the previous relay sockets.
	for _, active := range []bool{true, false} {
		c.applied = nil
		a.node.ServiceControl.Offline.PolicyID = fmt.Sprintf("policy-%t", active)
		a.node.ServiceControl.Offline.Automatic = active
		if err := a.refreshServiceControl(ctx); err != nil {
			t.Fatal(err)
		}
		if a.serviceControlActive() != active || len(c.applied) == 0 {
			t.Fatal("mode transition did not restore managed configuration", active, c.applied)
		}
	}
}

type offlineRecoveryTestPanel struct {
	*lostResponsePanel
	active bool
}

func (p *offlineRecoveryTestPanel) OfflineRecoveryActive() bool { return p.active }
func TestOfflineServiceControlStaleRecoveryCannotDeleteNewerProtection(t *testing.T) {
	for _, withPolicy := range []bool{false, true} {
		t.Run(fmt.Sprint(withPolicy), func(t *testing.T) {
			a, c, p := checkpointRig(t)
			recovery := &offlineRecoveryTestPanel{lostResponsePanel: p, active: true}
			a.driver = recovery
			dir := filepath.Join(a.cfg.DataDir, "offline-service-control")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			journal := []byte(`{"version":1,"policy_id":"newer-policy","command_revision":"newer-command","cycle":1,"period_start":1,"at":2,"epoch":"sampler","sequence":1,"up":800,"down":0,"automatic":true,"networks":[{"name":"eth0","id":"boot:1","included":true,"up":1000,"down":0}]}`)
			path := filepath.Join(dir, "offline-traffic.json")
			if err := os.WriteFile(path, journal, 0600); err != nil {
				t.Fatal(err)
			}
			if withPolicy {
				a.node.ServiceControl = &spec.ServiceControl{Revision: "old", Mode: "normal", Offline: &spec.OfflineServiceControl{PolicyID: "older-policy"}}
			}
			var script string
			fail := false
			a.ServiceControl = &servicecontrol.Manager{Dir: t.TempDir(), Run: serviceControlTestRunner(&script, &fail)}
			if err := a.refreshServiceControl(context.Background()); err == nil {
				t.Fatal("stale recovery accepted")
			}
			if c.running || !a.serviceControlPaused() {
				t.Fatal("stale cache reopened traffic")
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != string(journal) {
				t.Fatal("stale cache deleted newer journal", err)
			}
			// An actual fresh online state can explicitly disable and restore service.
			recovery.active = false
			a.node.ServiceControl = &spec.ServiceControl{Revision: "fresh", Mode: "normal"}
			if err := a.apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := a.applyForwards(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !c.running || a.serviceControlPaused() {
				t.Fatal("fresh authoritative state could not restore service")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("fresh disabled state did not retire journal", err)
			}
		})
	}
}

func TestExpiredLeaseCannotRemoveServiceGuard(t *testing.T) {
	a, c, _ := checkpointRig(t)
	p := &leasePanel{Driver: a.driver}
	a.driver = p
	var script string
	fail := false
	a.ServiceControl = &servicecontrol.Manager{Dir: t.TempDir(), Run: serviceControlTestRunner(&script, &fail)}
	a.node.ServiceControl = &spec.ServiceControl{Revision: "paused", Mode: "pause"}
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	guarded := script
	a.node.ServiceControl = &spec.ServiceControl{Revision: "resume", Mode: "normal"}
	p.expired = true
	if err := a.refreshServiceControl(context.Background()); err == nil {
		t.Fatal("expired lease allowed local resume")
	}
	if script != guarded || c.running {
		t.Fatal("expired lease removed guard or restarted proxy")
	}
}
