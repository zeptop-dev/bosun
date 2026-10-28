package agent

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/zeptop-dev/bosun/internal/runas"
	"github.com/zeptop-dev/bosun/internal/servicecontrol"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func (a *Agent) serviceControlActive() bool {
	return a.node != nil && a.node.ServiceControl != nil && a.node.ServiceControl.Mode != spec.ServiceControlNormal
}
func (a *Agent) serviceControlPaused() bool {
	return a.node != nil && a.node.ServiceControl != nil && a.node.ServiceControl.Mode == spec.ServiceControlPause
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
	if a.serviceControlActive() {
		for _, u := range a.users {
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
	return a.ServiceControl.Apply(ctx, desired, uid, a.MonitorOnly(), scope)
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

func (a *Agent) serviceControlReport() *agentproto.ServiceControlReport {
	if a.ServiceControl == nil {
		return nil
	}
	s := a.ServiceControl.Status()
	if a.coreDirty || a.forwardDirty || a.modeChanging.Load() {
		s.AppliedRevision = ""
		if s.Error == "" {
			s.Error = "proxy service reconciliation is incomplete"
		}
	}
	return &s
}
