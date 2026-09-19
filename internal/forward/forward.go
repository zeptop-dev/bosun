// Package forward implements bosun's built-in TCP/UDP relay: each rule
// accepts on a local port and forwards to the next hop. It also probes each
// TCP target so the panel can see whether a chain is healthy.
package forward

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

const (
	dialTimeout       = 10 * time.Second
	udpIdle           = 60 * time.Second
	probeInterval     = 30 * time.Second // while the target answers
	probeRetry        = 5 * time.Second  // while it does not
	probeInitialDelay = 2 * time.Second  // let a co-located target bind first
	probeTimeout      = 5 * time.Second
)

// Stats is a snapshot of one rule's counters.
type Stats struct {
	Tag        string
	Protocol   string
	Port       int
	Target     string
	Backend    string
	Up         bool // last probe succeeded (tcp targets only; udp reports true)
	RTT        time.Duration
	LastError  string
	ActiveConn int64
	TotalConn  int64
	BytesIn    int64 // client -> target
	BytesOut   int64 // target -> client
	// Targets is per-hop state when the rule has further targets; Up and
	// RTT above are then "some hop is up" and the preferred hop's RTT.
	Targets []TargetStats
}

// rule is one running forward with its listeners.
type rule struct {
	spec   spec.Forward
	cancel context.CancelFunc
	wg     sync.WaitGroup
	log    *slog.Logger

	active   atomic.Int64
	total    atomic.Int64
	bytesIn  atomic.Int64
	bytesOut atomic.Int64

	// hops is Target followed by Targets, each with its own probe state.
	hops   []*hop
	pickMu sync.Mutex

	probeMu sync.Mutex
	// nftBroken marks an nft or realm rule whose backend could not be
	// installed; the target probe then never reports it up.
	nftBroken bool
}

// Manager owns the set of running rules and reconciles it against a spec.
type Manager struct {
	log   *slog.Logger
	mu    sync.Mutex
	rules map[string]*rule
	// nftApplied is the nft script currently installed ("" = no table).
	nftApplied string
	// Realm runs the rules with Backend "realm"; nil rejects them.
	Realm *Realm
}

// NewManager returns an empty manager.
func NewManager(log *slog.Logger) *Manager {
	return &Manager{log: log.With("component", "forward"), rules: map[string]*rule{}}
}

func key(f spec.Forward) string {
	return fmt.Sprintf("%s|%s|%d|%s|%s|%s|%t|%t|%v|%s", f.Tag, f.Listen, f.Port, f.Protocol, f.Target, f.Backend, f.PreserveSource, f.ProxyProtocol, f.Hops(), f.BalanceMode())
}

// Apply makes the running set match forwards: unchanged rules keep their
// connections, changed or removed ones are stopped, new ones started.
func (m *Manager) Apply(forwards []spec.Forward) error {
	if err := validate(forwards); err != nil {
		return err
	}
	want := map[string]spec.Forward{}
	for _, f := range forwards {
		want[key(f)] = f
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, r := range m.rules {
		if _, keep := want[k]; !keep {
			m.log.Info("forward stopped", "tag", r.spec.Tag)
			r.stop()
			delete(m.rules, k)
		}
	}
	var firstErr error
	nftChanged := false
	var nftRules, realmRules []spec.Forward
	for k, f := range want {
		switch f.Backend {
		case "nft":
			nftRules = append(nftRules, f)
		case "realm":
			realmRules = append(realmRules, f)
		}
		if _, running := m.rules[k]; running {
			continue
		}
		if f.Backend == "nft" {
			// The kernel does the relaying; bosun only keeps the target probe.
			m.rules[k] = startProbeOnly(f, m.log)
			nftChanged = true
			m.log.Info("nft forward added", "tag", f.Tag, "port", f.Port, "protocol", f.Protocol, "target", f.Target, "preserve_source", f.PreserveSource)
			continue
		}
		if f.Backend == "realm" {
			// realm does the relaying; bosun keeps the target probe.
			m.rules[k] = startProbeOnly(f, m.log)
			m.log.Info("realm forward added", "tag", f.Tag, "port", f.Port, "protocol", f.Protocol, "target", f.Target)
			continue
		}
		r, err := start(f, m.log)
		if err != nil {
			m.log.Error("forward failed to start", "tag", f.Tag, "err", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		m.rules[k] = r
		m.log.Info("forward started", "tag", f.Tag, "listen", f.Listen, "port", f.Port, "protocol", f.Protocol, "target", f.Target)
	}
	if nftChanged || (len(nftRules) == 0 && m.nftApplied != "") || (len(nftRules) > 0 && m.nftApplied == "") {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		m.applyNFT(ctx, nftRules)
		cancel()
	}
	if len(realmRules) > 0 || (m.Realm != nil && m.Realm.applied != "") {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := m.Realm.apply(ctx, realmRules); err != nil {
			m.log.Error("realm", "err", err)
			for _, f := range realmRules {
				if r, ok := m.rules[key(f)]; ok {
					r.setProbe(false, 0, err)
					r.nftBroken = true
				}
			}
			if firstErr == nil {
				firstErr = err
			}
		}
		cancel()
	}
	return firstErr
}

// startProbeOnly builds a rule that opens no listener (the kernel forwards)
// but still probes the target so the panel sees its health.
func startProbeOnly(f spec.Forward, log *slog.Logger) *rule {
	ctx, cancel := context.WithCancel(context.Background())
	r := &rule{spec: f, cancel: cancel, log: log.With("tag", f.Tag), hops: newHops(f)}
	r.wg.Add(1)
	go r.probeLoop(ctx)
	return r
}

// Stop tears down every rule.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, r := range m.rules {
		r.stop()
		delete(m.rules, k)
	}
	if m.nftApplied != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		m.applyNFT(ctx, nil)
		cancel()
	}
	if m.Realm != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		m.Realm.stop(ctx)
		cancel()
	}
}

// Snapshot returns current stats for every rule, sorted by tag.
func (m *Manager) Snapshot() []Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Stats, 0, len(m.rules))
	for _, r := range m.rules {
		s := Stats{
			Tag: r.spec.Tag, Protocol: r.spec.Protocol, Port: r.spec.Port, Target: r.spec.Target, Backend: r.spec.Backend,
			ActiveConn: r.active.Load(), TotalConn: r.total.Load(),
			BytesIn: r.bytesIn.Load(), BytesOut: r.bytesOut.Load(),
		}
		for i, h := range r.hops {
			up, rtt, lastErr := h.state()
			if up && !s.Up {
				s.Up, s.RTT = true, rtt
			}
			if i == 0 {
				s.LastError = lastErr
			}
			if len(r.hops) > 1 {
				s.Targets = append(s.Targets, TargetStats{Target: h.target, Up: up, RTT: rtt, LastError: lastErr,
					ActiveConn: h.active.Load(), TotalConn: h.total.Load()})
			}
		}
		if s.Up {
			s.LastError = ""
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tag < out[j].Tag })
	return out
}

func validate(forwards []spec.Forward) error {
	seen := map[string]string{}
	for _, f := range forwards {
		if f.Tag == "" {
			return fmt.Errorf("forward: tag is required")
		}
		if !spec.ValidTag(f.Tag) {
			return fmt.Errorf("forward %q: tag may only contain letters, digits, . _ : - (max 64)", f.Tag)
		}
		if !spec.ValidListen(f.Listen) {
			return fmt.Errorf("forward %q: listen must be an IP address", f.Tag)
		}
		if !spec.Plain(f.Target) || strings.ContainsAny(f.Target, "\"' ") {
			return fmt.Errorf("forward %q: target contains invalid characters", f.Tag)
		}
		if f.Port <= 0 || f.Port > 65535 {
			return fmt.Errorf("forward %q: invalid port %d", f.Tag, f.Port)
		}
		switch f.Protocol {
		case "tcp", "udp", "both":
		default:
			return fmt.Errorf("forward %q: protocol must be tcp, udp or both", f.Tag)
		}
		switch f.Backend {
		case "", "nft", "realm":
		default:
			return fmt.Errorf("forward %q: backend must be empty (relay), nft or realm", f.Tag)
		}
		if f.PreserveSource && f.Backend != "nft" {
			return fmt.Errorf("forward %q: preserve_source needs the nft backend", f.Tag)
		}
		if f.ProxyProtocol && f.Backend == "nft" {
			return fmt.Errorf("forward %q: proxy_protocol needs the built-in relay or realm (nft keeps the source with preserve_source)", f.Tag)
		}
		if _, _, err := net.SplitHostPort(f.Target); err != nil {
			return fmt.Errorf("forward %q: target must be host:port: %w", f.Tag, err)
		}
		if err := f.ValidateTargets(); err != nil {
			return fmt.Errorf("forward %q: %w", f.Tag, err)
		}
		for _, p := range protocols(f) {
			k := p + ":" + f.Listen + ":" + strconv.Itoa(f.Port)
			if other, dup := seen[k]; dup {
				return fmt.Errorf("forward %q: %s port %d already used by %q", f.Tag, p, f.Port, other)
			}
			seen[k] = f.Tag
		}
	}
	return nil
}

func protocols(f spec.Forward) []string {
	if f.Protocol == "both" {
		return []string{"tcp", "udp"}
	}
	return []string{f.Protocol}
}

func start(f spec.Forward, log *slog.Logger) (*rule, error) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &rule{spec: f, cancel: cancel, log: log.With("tag", f.Tag), hops: newHops(f)}
	addr := net.JoinHostPort(f.Listen, strconv.Itoa(f.Port))
	var closers []func()
	for _, p := range protocols(f) {
		switch p {
		case "tcp":
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				cancel()
				for _, c := range closers {
					c()
				}
				return nil, err
			}
			closers = append(closers, func() { ln.Close() })
			r.wg.Add(1)
			go r.serveTCP(ctx, ln)
			r.wg.Add(1)
			go r.probeLoop(ctx)
		case "udp":
			pc, err := net.ListenPacket("udp", addr)
			if err != nil {
				cancel()
				for _, c := range closers {
					c()
				}
				return nil, err
			}
			closers = append(closers, func() { pc.Close() })
			r.wg.Add(1)
			go r.serveUDP(ctx, pc)
		}
	}
	go func() {
		<-ctx.Done()
		for _, c := range closers {
			c()
		}
	}()
	return r, nil
}

func (r *rule) stop() {
	r.cancel()
	r.wg.Wait()
}

// setProbe puts every hop in one state (a backend that failed to install
// takes all of them down).
func (r *rule) setProbe(up bool, rtt time.Duration, err error) {
	for _, h := range r.hops {
		h.set(up, rtt, err)
	}
}

// probeLoop measures a TCP connect to the target periodically, retrying
// faster while the target is down so recovery is noticed quickly.
func (r *rule) probeLoop(ctx context.Context) {
	defer r.wg.Done()
	delay := probeInitialDelay
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if r.probe(ctx) {
			delay = probeInterval
		} else {
			delay = probeRetry
		}
	}
}

// probe measures a TCP connect to every hop, concurrently, and reports
// whether all of them answered.
func (r *rule) probe(ctx context.Context) bool {
	r.probeMu.Lock()
	broken := r.nftBroken
	r.probeMu.Unlock()
	if broken {
		// The ruleset is not installed; keep the apply error visible.
		return false
	}
	var wg sync.WaitGroup
	var down atomic.Int32
	for _, h := range r.hops {
		wg.Add(1)
		go func(h *hop) {
			defer wg.Done()
			dctx, cancel := context.WithTimeout(ctx, probeTimeout)
			defer cancel()
			start := time.Now()
			var d net.Dialer
			c, err := d.DialContext(dctx, "tcp", h.target)
			rtt := time.Since(start)
			if err != nil {
				down.Add(1)
				if h.set(false, 0, err) {
					r.log.Warn("target down", "target", h.target, "err", err)
				}
				return
			}
			c.Close()
			if h.set(true, rtt, nil) {
				r.log.Info("target up", "target", h.target, "rtt", rtt.Round(time.Millisecond))
			}
		}(h)
	}
	wg.Wait()
	return down.Load() == 0
}

// isUp says whether some hop is up.
func (r *rule) isUp() bool {
	for _, h := range r.hops {
		if h.isUp() {
			return true
		}
	}
	return false
}
