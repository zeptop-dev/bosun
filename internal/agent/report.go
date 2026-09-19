package agent

import (
	"context"
	"errors"

	"time"

	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/metrics"
	"github.com/zeptop-dev/bosun/internal/panel"
	"github.com/zeptop-dev/bosun/internal/sysinfo"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// trafficKey is one user's counter on one inbound ("" when the core
// cannot tell the inbound).
type trafficKey struct {
	user int64
	tag  string
}

// report collects per-user traffic from every running core and pushes it
// with a host snapshot. It returns true when the panel signals newer state.
func (a *Agent) report(ctx context.Context) bool {
	if a.pendingTraffic == nil {
		a.pendingTraffic = map[trafficKey]*spec.UserTraffic{}
		a.pendingInbound = map[string]spec.Traffic{}
		a.pendingOutbound = map[string]spec.Traffic{}
	}
	list, perInboundList := a.collectUserTraffic(ctx)
	perInbound := a.collectTagged(ctx, a.pendingInbound, "inbound", func(c core.Core) (map[string]spec.Traffic, error) {
		is, ok := c.(core.InboundStatser)
		if !ok {
			return nil, errSkip
		}
		return is.InboundStats(ctx, true)
	})
	perOutbound := a.collectTagged(ctx, a.pendingOutbound, "outbound", func(c core.Core) (map[string]spec.Traffic, error) {
		os, ok := c.(core.OutboundStatser)
		if !ok {
			return nil, errSkip
		}
		return os.OutboundStats(ctx, true)
	})
	host := sysinfo.Snapshot(ctx)

	if rep, ok := a.driver.(panel.Reporter); ok {
		full := a.buildReport(perInboundList, host)
		full.Jobs = a.takeJobResults()
		if len(perInbound) > 0 {
			full.Inbounds = perInbound
		}
		if len(perOutbound) > 0 {
			full.Outbounds = perOutbound
		}
		a.statusMu.Lock()
		if a.trafficSeq == 0 {
			// Seeded from the clock, not from 1: the number lives in
			// memory, and a series that restarted at 1 after every
			// restart would make the panel see numbers it had already
			// passed. Seconds are plenty — one batch per report.
			a.trafficSeq = uint64(time.Now().Unix())
		}
		if a.trafficSince.IsZero() {
			a.trafficSince = time.Now()
		}
		full.TrafficSeq = a.trafficSeq
		full.TrafficWindowSeconds = int(time.Since(a.trafficSince).Seconds())
		a.statusMu.Unlock()
		changed, err := rep.Report(ctx, full)
		if err != nil {
			// The deltas stay in the pending maps and go out with the next
			// report; job results are requeued the same way.
			a.requeueJobResults(full.Jobs)
			a.reportFailures.Add(1)
			a.log.Error("report failed; traffic deltas kept for the next attempt", "users", len(list), "err", err)
			a.statusMu.Lock()
			a.lastReportErr = err.Error()
			a.statusMu.Unlock()
			return false
		}
		a.pendingTraffic, a.pendingInbound, a.pendingOutbound = map[trafficKey]*spec.UserTraffic{}, map[string]spec.Traffic{}, map[string]spec.Traffic{}
		// The batch was accepted: the next one is a new number over a new
		// window. A failed report keeps both, so the retry carries the
		// same number and the panel applies it once.
		a.statusMu.Lock()
		a.trafficSeq++
		a.trafficSince = time.Now()
		a.statusMu.Unlock()
		a.lastReportOK.Store(time.Now().Unix())
		a.log.Debug("report sent", "users", len(list), "state_changed", changed)
		a.statusMu.Lock()
		a.lastReport, a.lastReportErr = time.Now(), ""
		if a.pendingDoctor != nil {
			a.sentDoctor, a.sentDoctorAt, a.pendingDoctor = a.pendingDoctor, time.Now(), nil
		}
		a.statusMu.Unlock()
		if ur, ok := a.driver.(panel.UpgradeRequester); ok && a.Upgrade != nil {
			if v := ur.UpgradeRequested(); v != "" && v != a.upgradeAsked {
				a.upgradeAsked = v
				a.log.Info("panel requested upgrade", "version", v)
				go a.Upgrade(v)
			}
		}
		return changed
	}
	if len(list) > 0 {
		if err := a.driver.PushTraffic(ctx, list); err != nil {
			a.log.Error("push traffic failed", "users", len(list), "err", err)
		} else {
			a.log.Debug("traffic pushed", "users", len(list))
		}
	}
	if err := a.driver.PushStatus(ctx, host); err != nil {
		a.log.Warn("push status failed", "err", err)
	}
	return false
}

// errSkip marks a core without the requested counters.
var errSkip = errors.New("no such counters")

// collectUserTraffic reads every running core's per-user counters into the
// pending map (deltas the panel never acknowledged stay there) and returns
// them summed per user (for drivers that only know users) and per user and
// inbound (for the Captain report).
func (a *Agent) collectUserTraffic(ctx context.Context) (perUser, perInbound []spec.UserTraffic) {
	totals := a.pendingTraffic
	for _, name := range a.reg.Names() {
		c, _ := a.reg.Get(name)
		if !c.Running() {
			continue
		}
		stats, err := c.Stats(ctx, true)
		if err != nil {
			a.log.Warn("stats failed", "core", name, "err", err)
			continue
		}
		for key, t := range stats {
			if t.Up == 0 && t.Down == 0 {
				continue
			}
			// Cores count per inbound ("name|tag") where they can.
			userName, tag := spec.SplitInboundUser(key)
			id, ok := a.userIDs[userName]
			if !ok {
				continue
			}
			k := trafficKey{id, tag}
			ut := totals[k]
			if ut == nil {
				ut = &spec.UserTraffic{UserID: id, Inbound: tag}
				totals[k] = ut
			}
			ut.Up += t.Up
			ut.Down += t.Down
		}
	}
	sums := map[int64]*spec.UserTraffic{}
	perInbound = make([]spec.UserTraffic, 0, len(totals))
	for _, t := range totals {
		perInbound = append(perInbound, *t)
		ut := sums[t.UserID]
		if ut == nil {
			ut = &spec.UserTraffic{UserID: t.UserID}
			sums[t.UserID] = ut
		}
		ut.Up += t.Up
		ut.Down += t.Down
	}
	perUser = make([]spec.UserTraffic, 0, len(sums))
	for _, t := range sums {
		perUser = append(perUser, *t)
	}
	return perUser, perInbound
}

// collectTagged adds every running core's per-tag counters (inbound or
// outbound totals) into pending, skipping cores without them and the
// internal api/block tags.
func (a *Agent) collectTagged(ctx context.Context, pending map[string]spec.Traffic, kind string, read func(core.Core) (map[string]spec.Traffic, error)) map[string]spec.Traffic {
	for _, name := range a.reg.Names() {
		c, _ := a.reg.Get(name)
		if !c.Running() {
			continue
		}
		stats, err := read(c)
		if errors.Is(err, errSkip) {
			continue
		}
		if err != nil {
			a.log.Debug(kind+" stats failed", "core", name, "err", err)
			continue
		}
		for tag, t := range stats {
			if t.Up == 0 && t.Down == 0 || tag == "api" || tag == "block" {
				continue
			}
			cur := pending[tag]
			cur.Up += t.Up
			cur.Down += t.Down
			pending[tag] = cur
		}
	}
	return pending
}

// buildReport assembles the combined report for Reporter drivers.
func (a *Agent) buildReport(traffic []spec.UserTraffic, host spec.SystemStatus) agentproto.Report {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rep := agentproto.Report{Traffic: traffic, Host: host, Cores: map[string]agentproto.CoreStatus{}, Online: map[string][]string{}}
	a.statusMu.Lock()
	rep.Doctor = a.pendingDoctor
	a.statusMu.Unlock()
	for _, name := range a.reg.Names() {
		c, _ := a.reg.Get(name)
		rep.Cores[name] = agentproto.CoreStatus{Running: c.Running()}
		if tr, ok := c.(core.OnlineTracker); ok && c.Running() {
			online, err := tr.Online(ctx)
			if err != nil {
				a.log.Warn("online lookup failed", "core", name, "err", err)
				continue
			}
			for key, ips := range online {
				user, _ := spec.SplitInboundUser(key)
				rep.Online[user] = append(rep.Online[user], ips...)
			}
		}
	}
	if len(rep.Online) == 0 {
		rep.Online = nil
	}
	if a.Conn != nil {
		rep.Connections, rep.ConnDropped = a.Conn.Drain()
	}
	if a.Audit != nil {
		rep.Audits, rep.AuditDropped = a.Audit.Drain()
	}
	if a.Certs != nil {
		for _, st := range a.Certs.Status() {
			rep.Certs = append(rep.Certs, agentproto.CertStatus{Domain: st.Domain, Method: st.Method, NotAfter: st.NotAfter, Error: st.Error})
		}
	}
	a.statusMu.Lock()
	for _, st := range a.customCerts {
		rep.Certs = append(rep.Certs, st)
	}
	a.statusMu.Unlock()
	for _, s := range a.fwd.Snapshot() {
		rep.Forwards = append(rep.Forwards, s.Status())
	}
	return rep
}

func (a *Agent) registerMetrics() {
	m := a.metrics
	m.Describe("bosun_apply_errors_total", "counter", "applies that failed (a core rejected or could not start its config)")
	m.Describe("bosun_report_failures_total", "counter", "reports the panel did not accept")
	m.Describe("bosun_last_apply_success_timestamp_seconds", "gauge", "unix time of the last successful apply (0 = never)")
	m.Describe("bosun_last_report_success_timestamp_seconds", "gauge", "unix time of the last accepted report (0 = never or standalone)")
	m.Describe("bosun_apply_dirty", "gauge", "1 while the last apply failed and a retry is pending")
	m.Add(func() []metrics.Sample {
		dirty := 0.0
		if a.dirty {
			dirty = 1
		}
		return []metrics.Sample{
			{Name: "bosun_apply_errors_total", Value: float64(a.applyErrors.Load())},
			{Name: "bosun_report_failures_total", Value: float64(a.reportFailures.Load())},
			{Name: "bosun_last_apply_success_timestamp_seconds", Value: float64(a.lastApplyOK.Load())},
			{Name: "bosun_last_report_success_timestamp_seconds", Value: float64(a.lastReportOK.Load())},
			{Name: "bosun_apply_dirty", Value: dirty},
		}
	})
	m.Describe("bosun_core_running", "gauge", "1 if the core process is running")
	m.Describe("bosun_users", "gauge", "users currently provisioned")
	m.Describe("bosun_forward_up", "gauge", "1 if the forward target answered the last probe")
	m.Describe("bosun_forward_probe_rtt_seconds", "gauge", "last probe round trip to the forward target")
	m.Describe("bosun_forward_connections_active", "gauge", "open relayed connections or udp sessions")
	m.Describe("bosun_forward_connections_total", "counter", "relayed connections or udp sessions since start")
	m.Describe("bosun_forward_bytes_total", "counter", "relayed bytes by direction (in = client to target)")
	m.Describe("bosun_probe_latency_seconds", "gauge", "last latency of a carrier probe or panel task (-1 = lost)")
	m.Describe("bosun_probe_loss_ratio", "gauge", "recent loss ratio of a carrier probe")
	m.Add(func() []metrics.Sample {
		var out []metrics.Sample
		for _, p := range a.probes.Results() {
			l := map[string]string{"name": p.Name}
			lat := p.LatencyMs / 1000
			if p.LatencyMs < 0 {
				lat = -1
			}
			out = append(out, metrics.Sample{Name: "bosun_probe_latency_seconds", Labels: l, Value: lat})
			if p.TaskID == 0 {
				out = append(out, metrics.Sample{Name: "bosun_probe_loss_ratio", Labels: l, Value: p.Loss / 100})
			}
		}
		for _, name := range a.reg.Names() {
			c, _ := a.reg.Get(name)
			v := 0.0
			if c.Running() {
				v = 1
			}
			out = append(out, metrics.Sample{Name: "bosun_core_running", Labels: map[string]string{"core": name}, Value: v})
		}
		out = append(out, metrics.Sample{Name: "bosun_users", Value: float64(len(a.users))})
		for _, s := range a.fwd.Snapshot() {
			l := map[string]string{"tag": s.Tag, "target": s.Target, "protocol": s.Protocol}
			up := 0.0
			if s.Up {
				up = 1
			}
			out = append(out,
				metrics.Sample{Name: "bosun_forward_up", Labels: l, Value: up},
				metrics.Sample{Name: "bosun_forward_probe_rtt_seconds", Labels: l, Value: s.RTT.Seconds()},
				metrics.Sample{Name: "bosun_forward_connections_active", Labels: l, Value: float64(s.ActiveConn)},
				metrics.Sample{Name: "bosun_forward_connections_total", Labels: l, Value: float64(s.TotalConn)},
				metrics.Sample{Name: "bosun_forward_bytes_total", Labels: with(l, "dir", "in"), Value: float64(s.BytesIn)},
				metrics.Sample{Name: "bosun_forward_bytes_total", Labels: with(l, "dir", "out"), Value: float64(s.BytesOut)},
			)
		}
		return out
	})
}
