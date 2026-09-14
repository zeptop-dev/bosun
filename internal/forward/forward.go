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
	Up         bool // last probe succeeded (tcp targets only; udp reports true)
	RTT        time.Duration
	LastError  string
	ActiveConn int64
	TotalConn  int64
	BytesIn    int64 // client -> target
	BytesOut   int64 // target -> client
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

	probeMu   sync.Mutex
	up        bool
	rtt       time.Duration
	lastError string
	// nftBroken marks an nft rule whose ruleset could not be installed; the
	// target probe then never reports it up.
	nftBroken bool
}

// Manager owns the set of running rules and reconciles it against a spec.
type Manager struct {
	log   *slog.Logger
	mu    sync.Mutex
	rules map[string]*rule
	// nftApplied is the nft script currently installed ("" = no table).
	nftApplied string
}

// NewManager returns an empty manager.
func NewManager(log *slog.Logger) *Manager {
	return &Manager{log: log.With("component", "forward"), rules: map[string]*rule{}}
}

func key(f spec.Forward) string {
	return fmt.Sprintf("%s|%s|%d|%s|%s|%s|%t", f.Tag, f.Listen, f.Port, f.Protocol, f.Target, f.Backend, f.PreserveSource)
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
	var nftRules []spec.Forward
	for k, f := range want {
		if f.Backend == "nft" {
			nftRules = append(nftRules, f)
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
	return firstErr
}

// startProbeOnly builds a rule that opens no listener (the kernel forwards)
// but still probes the target so the panel sees its health.
func startProbeOnly(f spec.Forward, log *slog.Logger) *rule {
	ctx, cancel := context.WithCancel(context.Background())
	r := &rule{spec: f, cancel: cancel, log: log.With("tag", f.Tag), up: true}
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
}

// Snapshot returns current stats for every rule, sorted by tag.
func (m *Manager) Snapshot() []Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Stats, 0, len(m.rules))
	for _, r := range m.rules {
		r.probeMu.Lock()
		s := Stats{
			Tag: r.spec.Tag, Protocol: r.spec.Protocol, Port: r.spec.Port, Target: r.spec.Target,
			Up: r.up, RTT: r.rtt, LastError: r.lastError,
			ActiveConn: r.active.Load(), TotalConn: r.total.Load(),
			BytesIn: r.bytesIn.Load(), BytesOut: r.bytesOut.Load(),
		}
		r.probeMu.Unlock()
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
		if f.Port <= 0 || f.Port > 65535 {
			return fmt.Errorf("forward %q: invalid port %d", f.Tag, f.Port)
		}
		switch f.Protocol {
		case "tcp", "udp", "both":
		default:
			return fmt.Errorf("forward %q: protocol must be tcp, udp or both", f.Tag)
		}
		switch f.Backend {
		case "", "nft":
		default:
			return fmt.Errorf("forward %q: backend must be empty (relay) or nft", f.Tag)
		}
		if f.PreserveSource && f.Backend != "nft" {
			return fmt.Errorf("forward %q: preserve_source needs the nft backend", f.Tag)
		}
		if _, _, err := net.SplitHostPort(f.Target); err != nil {
			return fmt.Errorf("forward %q: target must be host:port: %w", f.Tag, err)
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
	r := &rule{spec: f, cancel: cancel, log: log.With("tag", f.Tag), up: true}
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

func (r *rule) setProbe(up bool, rtt time.Duration, err error) {
	r.probeMu.Lock()
	r.up, r.rtt = up, rtt
	if err != nil {
		r.lastError = err.Error()
	} else {
		r.lastError = ""
	}
	r.probeMu.Unlock()
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

func (r *rule) probe(ctx context.Context) bool {
	r.probeMu.Lock()
	broken := r.nftBroken
	r.probeMu.Unlock()
	if broken {
		// The ruleset is not installed; keep the apply error visible.
		return false
	}
	dctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	start := time.Now()
	var d net.Dialer
	c, err := d.DialContext(dctx, "tcp", r.spec.Target)
	rtt := time.Since(start)
	wasUp := r.isUp()
	if err != nil {
		r.setProbe(false, 0, err)
		if wasUp {
			r.log.Warn("target down", "target", r.spec.Target, "err", err)
		}
		return false
	}
	c.Close()
	r.setProbe(true, rtt, nil)
	if !wasUp {
		r.log.Info("target up", "target", r.spec.Target, "rtt", rtt.Round(time.Millisecond))
	}
	return true
}

func (r *rule) isUp() bool {
	r.probeMu.Lock()
	defer r.probeMu.Unlock()
	return r.up
}
