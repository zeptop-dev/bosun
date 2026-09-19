package forward

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// failoverDialTimeout bounds a dial that still has another hop to fall back
// on, so a dead first hop the probe has not caught yet costs the client a
// few seconds rather than dialTimeout.
const failoverDialTimeout = 4 * time.Second

// hop is one next hop of a rule, with its own probe state and counters.
type hop struct {
	target string
	weight int

	mu        sync.Mutex
	up        bool
	rtt       time.Duration
	lastError string

	current int // smooth weighted round-robin state, guarded by rule.pickMu

	active atomic.Int64
	total  atomic.Int64
}

func newHops(f spec.Forward) []*hop {
	var out []*hop
	for _, t := range f.Hops() {
		out = append(out, &hop{target: t.Target, weight: t.Weight, up: true})
	}
	return out
}

// set records a probe or dial outcome and reports whether the hop changed
// between up and down.
func (h *hop) set(up bool, rtt time.Duration, err error) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	changed := h.up != up
	h.up = up
	if up {
		h.rtt, h.lastError = rtt, ""
	} else {
		h.rtt = 0
		if err != nil {
			h.lastError = err.Error()
		}
	}
	return changed
}

func (h *hop) state() (up bool, rtt time.Duration, lastError string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.up, h.rtt, h.lastError
}

func (h *hop) isUp() bool {
	up, _, _ := h.state()
	return up
}

// candidates is the order a new connection tries the hops in. Failover:
// the hops that are up in declared order, then the rest as a last resort.
// Roundrobin: one hop chosen by smooth weighted round-robin among those up
// (among all when none is), then the other up hops, then the rest.
func (r *rule) candidates() []*hop {
	if len(r.hops) == 1 {
		return r.hops
	}
	var up, down []*hop
	for _, h := range r.hops {
		if h.isUp() {
			up = append(up, h)
		} else {
			down = append(down, h)
		}
	}
	if r.spec.BalanceMode() == spec.BalanceRoundRobin {
		pool := up
		if len(pool) == 0 {
			pool = r.hops
		}
		first := r.nextWeighted(pool)
		out := []*hop{first}
		for _, h := range append(up, down...) {
			if h != first {
				out = append(out, h)
			}
		}
		return out
	}
	return append(up, down...)
}

// nextWeighted is nginx's smooth weighted round-robin: every pick adds each
// weight to its hop's counter, takes the largest and subtracts the total,
// which interleaves 3:1 as a,a,b,a rather than a,a,a,b.
func (r *rule) nextWeighted(pool []*hop) *hop {
	r.pickMu.Lock()
	defer r.pickMu.Unlock()
	total := 0
	var best *hop
	for _, h := range pool {
		h.current += h.weight
		total += h.weight
		if best == nil || h.current > best.current {
			best = h
		}
	}
	best.current -= total
	return best
}

// dialTCP connects to the first candidate that answers. With several hops a
// failed dial marks that hop down at once, before its next probe.
func (r *rule) dialTCP(ctx context.Context) (net.Conn, *hop) {
	cands := r.candidates()
	for i, h := range cands {
		timeout := dialTimeout
		if i < len(cands)-1 {
			timeout = failoverDialTimeout
		}
		dctx, cancel := context.WithTimeout(ctx, timeout)
		var d net.Dialer
		c, err := d.DialContext(dctx, "tcp", h.target)
		cancel()
		if err == nil {
			return c, h
		}
		r.log.Debug("dial target failed", "target", h.target, "err", err)
		if len(r.hops) > 1 && h.set(false, 0, err) {
			r.log.Warn("target down", "target", h.target, "err", err)
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, nil
}

// TargetStats is one hop of a rule with several targets.
type TargetStats struct {
	Target     string
	Up         bool
	RTT        time.Duration
	LastError  string
	ActiveConn int64
	TotalConn  int64
}

// Status converts a snapshot to the report shape the panels read.
func (s Stats) Status() agentproto.ForwardStatus {
	out := agentproto.ForwardStatus{
		Tag: s.Tag, Up: s.Up, RTTMillis: s.RTT.Milliseconds(), LastError: s.LastError,
		ActiveConn: s.ActiveConn, TotalConn: s.TotalConn, BytesIn: s.BytesIn, BytesOut: s.BytesOut,
	}
	for _, t := range s.Targets {
		out.Targets = append(out.Targets, agentproto.ForwardTargetStatus{
			Target: t.Target, Up: t.Up, RTTMillis: t.RTT.Milliseconds(), LastError: t.LastError,
			ActiveConn: t.ActiveConn, TotalConn: t.TotalConn,
		})
	}
	return out
}
