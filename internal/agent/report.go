package agent

import (
	"context"
	"errors"

	"time"

	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/metrics"
	"github.com/zeptop-dev/bosun/internal/panel"
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
	if rep, ok := a.driver.(panel.Reporter); ok {
		return a.reportDurable(ctx, rep)
	}
	if a.pendingTraffic == nil {
		a.pendingTraffic = map[trafficKey]*spec.UserTraffic{}
	}
	list, _ := a.collectUserTraffic(ctx)
	if len(list) > 0 {
		if err := a.driver.PushTraffic(ctx, list); err != nil {
			a.log.Error("push traffic failed", "err", err)
		} else {
			a.pendingTraffic = map[trafficKey]*spec.UserTraffic{}
		}
	}
	if err := a.driver.PushStatus(ctx, a.SampleHost(ctx)); err != nil {
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
	a.statsCollectionErr = nil
	totals := a.pendingTraffic
	for _, name := range a.reg.Names() {
		c, _ := a.reg.Get(name)
		if !c.Running() {
			continue
		}
		stats, err := c.Stats(ctx, true)
		if err != nil {
			a.statsCollectionErr = errors.Join(a.statsCollectionErr, err)
			a.log.Warn("stats failed", "core", name, "err", err)
			continue
		}
		ids := a.coreUserIDs[name]
		if ids == nil {
			ids = a.userIDs
		}
		for key, t := range stats {
			if t.Up == 0 && t.Down == 0 {
				continue
			}
			// Cores count per inbound ("name|tag") where they can.
			userName, tag := spec.SplitInboundUser(key)
			id, ok := ids[userName]
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
			a.statsCollectionErr = errors.Join(a.statsCollectionErr, err)
			a.log.Debug(kind+" stats failed", "core", name, "err", err)
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
	rep := agentproto.Report{ServiceControl: a.serviceControlReport(), WireGuard: a.wireGuardReport(ctx), NodeMode: a.cfg.NodeMode.Effective(), NodeModeRevision: a.modeRevision(), CoreInventory: a.CoreInventory(), Traffic: traffic, Host: host, Cores: a.CoreStatus(), Online: map[string][]string{}}
	a.statusMu.Lock()
	if a.appliedCoreRevision != "" && a.appliedCoreRevision == a.appliedForwardRevision {
		rep.AppliedRevision = a.appliedCoreRevision
	}
	rep.Doctor = a.pendingDoctor
	if a.MonitorOnly() || (a.node != nil && ((a.node.Mode != "" && a.node.Mode != a.cfg.NodeMode.Effective()) || a.node.ModeRevision != a.modeRevision())) {
		rep.NodeModeError = a.status.LastError
	}
	a.statusMu.Unlock()
	rep.ConfigReceipt = a.configReceipt(rep.AppliedRevision)
	for _, name := range a.reg.Names() {
		c, _ := a.reg.Get(name)
		if rc, ok := c.(interface {
			ReverseStatus(context.Context) map[string]*bool
		}); ok && c.Running() {
			st := rep.Cores[name]
			st.Reverse = rc.ReverseStatus(ctx)
			rep.Cores[name] = st
		}
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
	m.Describe("bosun_traffic_pending_bytes", "gauge", "collected user bytes awaiting panel acknowledgement, excluding unread core counters")
	m.Describe("bosun_traffic_buffered_bytes", "gauge", "lifecycle checkpoint user bytes waiting behind the current batch")
	m.Describe("bosun_traffic_oldest_timestamp_seconds", "gauge", "oldest known pending sample start; 0 means empty or legacy unknown")
	m.Describe("bosun_traffic_journal_bytes", "gauge", "last observed size of the durable accounting journal")
	m.Add(func() []metrics.Sample {
		a.statusMu.Lock()
		delivery := a.status.Delivery
		a.statusMu.Unlock()
		oldest := float64(0)
		if delivery.OldestAt != nil {
			oldest = float64(delivery.OldestAt.Unix())
		}
		return []metrics.Sample{
			{Name: "bosun_traffic_pending_bytes", Value: float64(delivery.PendingBytes)},
			{Name: "bosun_traffic_buffered_bytes", Value: float64(delivery.BufferedBytes)},
			{Name: "bosun_traffic_oldest_timestamp_seconds", Value: oldest},
			{Name: "bosun_traffic_journal_bytes", Value: float64(delivery.JournalBytes)},
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
			if p.Family != "" {
				l["family"] = p.Family
			}
			if p.Series != "" {
				l["series"] = p.Series
			}
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
