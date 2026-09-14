package agent

import (
	"context"
	"time"

	"github.com/zeptop-dev/bosun/internal/doctor"
	"github.com/zeptop-dev/bosun/internal/panel"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Doctor runs the health checks against the agent's live view.
func (a *Agent) Doctor(ctx context.Context) doctor.Report {
	a.statusMu.Lock()
	node := a.node
	users := a.users
	lastReport, lastErr := a.lastReport, a.lastReportErr
	certs := make([]doctor.CertState, 0, len(a.customCerts))
	for _, c := range a.customCerts {
		certs = append(certs, doctor.CertState{Domain: c.Domain, NotAfter: c.NotAfter, Error: c.Error})
	}
	a.statusMu.Unlock()
	if a.Certs != nil {
		for _, st := range a.Certs.Status() {
			certs = append(certs, doctor.CertState{Domain: st.Domain, NotAfter: st.NotAfter, Error: st.Error})
		}
	}
	var cores []doctor.CoreState
	assigned := map[string]int{}
	if node != nil {
		if byCore, err := a.reg.Assign(node.Inbounds); err == nil {
			for name, ibs := range byCore {
				assigned[name] = len(ibs)
			}
		}
	}
	for _, name := range a.reg.Names() {
		c, _ := a.reg.Get(name)
		cores = append(cores, doctor.CoreState{Name: name, Running: c.Running(), Inbounds: assigned[name]})
	}
	var fwds []doctor.ForwardState
	for _, s := range a.fwd.Snapshot() {
		fwds = append(fwds, doctor.ForwardState{Tag: s.Tag, Protocol: s.Protocol, Port: s.Port, Target: s.Target, Up: s.Up, Error: s.LastError})
	}
	_, managed := a.driver.(panel.Reporter)
	ks := a.komari.Status()
	sctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	host := a.sampler.Sample(sctx)
	cancel()
	var n *spec.Node
	if node != nil {
		cp := *node
		n = &cp
	}
	return doctor.Run(ctx, doctor.Deps{
		Node: n, Users: users, Cores: cores, CoresKnown: true, Forwards: fwds, Certs: certs, Host: host,
		Managed: managed, LastReport: lastReport, LastError: lastErr, PushInterval: a.driver.Intervals().Push,
		KomariEnabled: ks.Enabled, KomariError: ks.LastError,
	})
}

// LastDoctor returns the most recent periodic report, nil before the first.
func (a *Agent) LastDoctor() *doctor.Report {
	a.statusMu.Lock()
	defer a.statusMu.Unlock()
	if a.lastDoctor == nil {
		return nil
	}
	cp := *a.lastDoctor
	return &cp
}

// runDoctor is the periodic run; the result rides on the next report when
// it changed, and at least every 30 minutes.
func (a *Agent) runDoctor(ctx context.Context) {
	rep := a.Doctor(ctx)
	a.statusMu.Lock()
	a.lastDoctor = &rep
	if !rep.Same(a.sentDoctor) || time.Since(a.sentDoctorAt) > 30*time.Minute {
		a.pendingDoctor = &rep
	}
	a.statusMu.Unlock()
}
