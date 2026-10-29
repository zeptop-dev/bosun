package agent

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/zeptop-dev/bosun/internal/runas"
	"github.com/zeptop-dev/bosun/internal/servicecontrol"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func (a *Agent) serviceControlActive() bool {
	c := a.effectiveServiceControl()
	return c != nil && c.Mode != spec.ServiceControlNormal
}
func (a *Agent) serviceControlPaused() bool {
	c := a.effectiveServiceControl()
	return c != nil && c.Mode == spec.ServiceControlPause
}

func (a *Agent) reconcileServiceControl(ctx context.Context) error {
	if a.node == nil {
		return nil
	}
	if a.ServiceControl == nil {
		dir := ""
		if a.cfg != nil && a.cfg.DataDir != "" {
			dir = filepath.Join(a.cfg.DataDir, "service-control")
		}
		a.ServiceControl = &servicecontrol.Manager{Dir: dir}
	}
	uid, _ := runas.IDs()
	if a.ServiceControl.Run != nil && uid <= 0 {
		uid = 65534
	} // injectable nft runner owns the test namespace
	desired := a.node.ServiceControl
	var offlineErr error
	recovering := false
	if source, ok := a.driver.(interface{ OfflineRecoveryActive() bool }); ok {
		recovering = source.OfflineRecoveryActive()
	}
	if a.offlineControl == nil && a.cfg != nil && a.cfg.DataDir != "" {
		a.offlineControl = &servicecontrol.Offline{Dir: filepath.Join(a.cfg.DataDir, "offline-service-control")}
	}
	if recovering && a.offlineControl != nil {
		desired, offlineErr = a.offlineControl.RecoveryGuard(desired)
	}
	a.offlineRecoveryGuard = recovering && offlineErr != nil
	if offlineErr == nil && desired != nil && desired.Offline != nil {
		if a.offlineControl == nil {
			a.offlineControl = &servicecontrol.Offline{}
		}
		desired, offlineErr = a.offlineControl.Resolve(desired, a.SampleHost(ctx).Resources, time.Now())
	}
	// Only a fresh online state can retire an owned offline journal. A stale
	// recovery snapshot is not an authoritative instruction to disable protection.
	if !recovering && (a.node.ServiceControl == nil || a.node.ServiceControl.Offline == nil) && a.offlineControl != nil && a.offlineControl.Dir != "" {
		offlineErr = errors.Join(offlineErr, a.offlineControl.Disable())
	}
	a.resolvedServiceControl = desired
	a.statusMu.Lock()
	a.offlineControlReport = nil
	if a.offlineControl != nil && (a.offlineRecoveryGuard || a.node.ServiceControl != nil && a.node.ServiceControl.Offline != nil) {
		a.offlineControlReport = a.offlineControl.Report()
	}
	a.statusMu.Unlock()
	if a.serviceControlActive() {
		users := append([]spec.User(nil), a.users...)
		for _, ib := range a.node.Inbounds {
			users = append(users, ib.Users...)
		}
		for _, u := range users {
			if spec.SpeedMark(u.ID) == spec.ServiceControlSocketMark {
				return errors.New("service control relay mark collides with a legacy user speed mark")
			}
		}
	}
	scope := servicecontrol.Scope{}
	rules := a.node.Forwards
	if a.cfg != nil {
		rules = append(append([]spec.Forward{}, rules...), a.cfg.ForwardSpecs()...)
	}
	if a.serviceControlActive() {
		var err error
		scope.Forwards, err = a.fwd.ServiceControlScope(ctx, rules)
		if err != nil {
			return fmt.Errorf("service control NAT scope: %w", err)
		}
	}
	for _, l := range a.node.WireGuardLinks {
		scope.Interfaces = append(scope.Interfaces, l.Interface())
	}
	if a.fwd != nil {
		a.fwd.SetServiceControl(a.serviceControlActive())
	}
	return errors.Join(a.ServiceControl.Apply(ctx, desired, uid, a.MonitorOnly(), scope), offlineErr)
}

// Pause installs the independent guard before collecting counters. A failed
// accounting checkpoint cannot keep traffic moving; report the error and stop
// every managed process/link anyway. The guard remains until explicit normal.
func (a *Agent) stopControlledServices(ctx context.Context) error {
	var errs []error
	if err := a.checkpointTraffic(ctx); err != nil {
		errs = append(errs, fmt.Errorf("checkpoint before service control: %w", err))
	}
	for _, name := range a.reg.Names() {
		c, _ := a.reg.Get(name)
		if c.Running() {
			if err := c.Stop(ctx); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if err := a.fwd.Apply(nil); err != nil {
		errs = append(errs, err)
	}
	if err := a.clearWireGuard(ctx); err != nil {
		errs = append(errs, err)
	}
	a.kernelNode = nil
	a.kernelByTag = nil
	a.setStatus(func(s *Status) { s.Inbounds = 0; s.Assign = map[string]string{}; s.CoreInbound = map[string]int{} })
	return errors.Join(errs...)
}

// Recheck independently of panel connectivity. A lost guard must stop managed
// services immediately; waiting for a successful pull could leave traffic
// unprotected indefinitely while the panel is unreachable.
func (a *Agent) refreshServiceControl(ctx context.Context) error {
	wasPaused, wasActive := a.serviceControlPaused(), a.serviceControlActive()
	a.shaperMu.Lock()
	err := a.reconcileServiceControl(ctx)
	offline := a.offlineRecoveryGuard || a.node != nil && a.node.ServiceControl != nil && a.node.ServiceControl.Offline != nil
	resume := err == nil && offline && !a.serviceControlPaused() && (wasPaused || wasActive != a.serviceControlActive() || a.coreDirty || a.forwardDirty)
	if err == nil && offline && a.serviceControlPaused() {
		err = a.stopControlledServices(ctx)
	}
	if err != nil {
		a.coreDirty, a.forwardDirty, a.dirty = true, true, true
		a.serviceControlPending.Store(true)
		a.setAppliedCoreRevision("")
		a.setAppliedForwardRevision("")
		if a.serviceControlActive() {
			err = errors.Join(err, a.stopControlledServices(ctx))
		}
	}
	a.shaperMu.Unlock()
	if resume {
		a.coreDirty, a.forwardDirty, a.dirty = true, true, true
		return errors.Join(a.apply(ctx), a.applyForwards(ctx))
	}
	return err
}

func (a *Agent) serviceControlReport() *agentproto.ServiceControlReport {
	if a.ServiceControl == nil {
		return nil
	}
	s := a.ServiceControl.Status()
	s.OfflineSupported = s.Supported
	a.statusMu.Lock()
	if a.offlineControlReport != nil {
		cp := *a.offlineControlReport
		s.Offline = &cp
	}
	a.statusMu.Unlock()
	if s.Offline != nil && s.Offline.Error != "" {
		s.AppliedRevision = ""
		s.Error = s.Offline.Error
	}
	coreRevision, forwardRevision := a.consumedRevisions()
	a.statusMu.Lock()
	pendingRevision := coreRevision != "" && coreRevision != a.appliedCoreRevision ||
		forwardRevision != "" && forwardRevision != a.appliedForwardRevision
	a.statusMu.Unlock()
	if a.serviceControlPending.Load() || a.modeChanging.Load() || pendingRevision {
		s.AppliedRevision = ""
		if s.Error == "" {
			s.Error = "proxy service reconciliation is incomplete"
		}
	}
	return &s
}

func (a *Agent) effectiveServiceControl() *spec.ServiceControl {
	if a.offlineRecoveryGuard && a.resolvedServiceControl != nil {
		return a.resolvedServiceControl
	}
	if a.node == nil {
		return nil
	}
	if a.node.ServiceControl != nil && a.node.ServiceControl.Offline != nil {
		if a.resolvedServiceControl != nil && a.resolvedServiceControl.Revision == a.node.ServiceControl.Revision {
			return a.resolvedServiceControl
		}
		return &spec.ServiceControl{Revision: a.node.ServiceControl.Revision, Mode: spec.ServiceControlPause}
	}
	return a.node.ServiceControl
}

// Called on the serial local timer, independently of HTTP reporting success.
func (a *Agent) refreshOfflineServiceControl(ctx context.Context) error {
	return a.refreshServiceControl(ctx)
}
