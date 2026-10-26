// Package probe measures carrier latency using explicit TCP/ICMP and IP-family
// choices, plus panel-defined tasks. Results are attached to every beat.
package probe

import (
	"context"
	"crypto/rand"
	"net"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	probing "github.com/prometheus-community/pro-bing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Carrier probe points are spec.DefaultCarriers unless the config names
// its own; they answer on :80 and a refused connection still
// proves reachability (ServerStatus counts ECONNREFUSED as success).
func carriersOf(cfg spec.Probe) []spec.Carrier {
	if len(cfg.Carriers) > 0 {
		return cfg.Carriers
	}
	return spec.DefaultCarriers()
}

// New configurations suppress the legacy switches even when invalid. Never
// silently measure TCP/IPv4 when the caller explicitly requested another mode.
func carrierTasks(cfg spec.Probe) []spec.PingTask {
	if cfg.CarrierProbe != nil {
		return cfg.CarrierProbe.Tasks()
	}
	if !cfg.CarrierPing {
		return nil
	}
	out := []spec.PingTask{}
	for _, c := range carriersOf(cfg) {
		family := "ipv4"
		host, _, _ := net.SplitHostPort(c.Addr)
		if spec.IsIPv6(host) {
			family = "ipv6"
		}
		out = append(out, spec.PingTask{Name: c.Name, Type: "tcp", Target: c.Addr, Family: family, Series: spec.CarrierSeries("tcp", family, c.Name, c.Addr), IntervalSeconds: 10, TCPReachability: true})
	}
	return out
}

const (
	ringSize       = 30 // 5 minutes of carrier samples
	dialTimeout    = 3 * time.Second
	downloadWindow = 8 * time.Second // like the speed-test tools: ~8s of transfer
)

// Runner owns the probe goroutines.
type Runner struct {
	// LookupIP and ICMP are injectable transports for protocol/family tests.
	LookupIP func(context.Context, string, string) ([]net.IP, error)
	ICMP     func(context.Context, string, string) (time.Duration, error)
	// Dial overrides TCP dialing (tests).
	Dial func(ctx context.Context, addr string) (time.Duration, error)
	// DialFrom is Dial with a bound source address (tests).
	DialFrom func(ctx context.Context, src, addr string) (time.Duration, error)
	// Download overrides the throughput test (tests).
	Download func(ctx context.Context, url string) (ttfbMs, mbps float64)

	// HTTPTransport is optional for local tests (e.g. a trusted test TLS CA).
	HTTPTransport *http.Transport
	epoch         string
	records       map[probeKey]*probeRecord
	mu            sync.Mutex
	cfg           spec.Probe
	cancel        context.CancelFunc
}

// Configure applies a new probe config, restarting goroutines when it
// changed. A nil or disabled config stops everything.
func (r *Runner) Configure(parent context.Context, cfg *spec.Probe) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var next spec.Probe
	if cfg != nil {
		next = *cfg
		next.Tasks = append([]spec.PingTask(nil), cfg.Tasks...)
		next.Carriers = append([]spec.Carrier(nil), cfg.Carriers...)
		next.CarrierProbe = cfg.CarrierProbe.Clone()
	}
	if sameConfig(r.cfg, next) && (r.cancel != nil || !next.Enabled) {
		return
	}
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	r.cfg = next
	r.epoch = rand.Text()
	r.records = map[probeKey]*probeRecord{}
	if !next.Enabled {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	r.cancel = cancel
	for _, t := range carrierTasks(next) {
		go r.qualityLoop(ctx, t, t.TCPReachability, r.epoch)
	}
	for _, t := range next.Tasks {
		// Older Captains identify automatic line checks by negative ingress ID.
		// Keep their reachability policy until both peers support the new flag.
		reachability := t.TCPReachability || (t.ID < 0 && t.SourceIP != "" && strings.EqualFold(t.Type, "tcp"))
		go r.qualityLoop(ctx, t, reachability, r.epoch)
	}
}

func sameConfig(a, b spec.Probe) bool {
	if !reflect.DeepEqual(a.CarrierProbe, b.CarrierProbe) || a.Enabled != b.Enabled || a.CarrierPing != b.CarrierPing || len(a.Tasks) != len(b.Tasks) || len(a.Carriers) != len(b.Carriers) {
		return false
	}
	for i := range a.Carriers {
		if a.Carriers[i] != b.Carriers[i] {
			return false
		}
	}
	for i := range a.Tasks {
		if a.Tasks[i] != b.Tasks[i] {
			return false
		}
	}
	return true
}

// Stop ends all probing.
func (r *Runner) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	r.cfg = spec.Probe{}
	r.records = nil
	r.epoch = ""
}

type probeKey struct {
	id     int64
	name   string
	series string
}
type probeRecord struct {
	result       spec.PingResult
	samples      []spec.ProbeMeasurement
	acknowledged uint64
}

func (r *Runner) qualityLoop(ctx context.Context, t spec.PingTask, reachability bool, epoch string) {
	iv := time.Duration(t.IntervalSeconds) * time.Second
	if iv < 5*time.Second {
		iv = 30 * time.Second
	}
	if t.Type == "download" && iv < 10*time.Minute {
		iv = 10 * time.Minute
	}
	tk := time.NewTicker(iv)
	defer tk.Stop()
	var sequence uint64
	for {
		if ctx.Err() != nil {
			return
		}
		m := r.scheduled(ctx, t, reachability)
		sequence++
		m.Sequence = sequence
		r.mu.Lock()
		if ctx.Err() != nil || r.epoch != epoch {
			r.mu.Unlock()
			return
		}
		key := probeKey{t.ID, t.Name, t.Series}
		rec := r.records[key]
		if rec == nil {
			rec = &probeRecord{}
			r.records[key] = rec
		}
		rec.samples = append(rec.samples, m)
		if len(rec.samples) > 60 {
			rec.samples = append([]spec.ProbeMeasurement(nil), rec.samples[len(rec.samples)-60:]...)
		}
		kind := strings.ToLower(t.Type)
		if reachability {
			kind = "tcp_reachability"
		}
		w := windowStats(rec.samples)
		rec.result = spec.PingResult{TaskID: t.ID, Name: t.Name, Family: t.Family, Series: t.Series, At: m.At, LatencyMs: m.LatencyMs, Mbps: m.Mbps, Loss: float64(w.Failed) * 100 / float64(w.Attempts), Quality: &spec.PingQuality{ProbeMeasurement: m, Epoch: epoch, Type: kind, IntervalSeconds: int(iv / time.Second), Window: w}}
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
	}
}

// measure runs one task: DNS is resolved before timing, a result
// above one second is retried up to three times, -1 means lost.

func (r *Runner) measure(ctx context.Context, t spec.PingTask) float64 {
	var best float64 = -1
	for attempt := 0; attempt < 3; attempt++ {
		var ms float64
		switch strings.ToLower(t.Type) {
		case "tcp":
			addr := t.Target
			if _, _, err := net.SplitHostPort(addr); err != nil {
				addr = net.JoinHostPort(addr, "80")
			}
			ms = r.tcpMsFrom(ctx, t.SourceIP, addr)
		case "http":
			ms = httpMs(ctx, t.Target)
		default:
			ms = icmpMs(ctx, t.Target, t.SourceIP)
		}
		if ms >= 0 && (best < 0 || ms < best) {
			best = ms
		}
		if ms >= 0 && ms < 1000 {
			break
		}
	}
	return best
}

// tcpMs times a TCP connect to a pre-resolved address; a refused
// connection counts as reachable.
func (r *Runner) tcpMs(ctx context.Context, addr string) float64 { return r.tcpMsFrom(ctx, "", addr) }

// tcpMsFrom is tcpMs with an optional bound source address.
func (r *Runner) tcpMsFrom(ctx context.Context, src, addr string) float64 {
	if src != "" && r.DialFrom != nil {
		d, err := r.DialFrom(ctx, src, addr)
		if err != nil {
			return -1
		}
		return float64(d.Microseconds()) / 1000
	}
	if r.Dial != nil {
		d, err := r.Dial(ctx, addr)
		if err != nil {
			return -1
		}
		return float64(d.Microseconds()) / 1000
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return -1
	}
	rctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(rctx, host)
	if err != nil || len(ips) == 0 {
		return -1
	}
	target := net.JoinHostPort(ips[0].IP.String(), port)
	dialer := &net.Dialer{Timeout: dialTimeout}
	if ip := net.ParseIP(src); ip != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: ip}
	}
	start := time.Now()
	c, err := dialer.DialContext(rctx, "tcp", target)
	elapsed := time.Since(start)
	if err == nil {
		c.Close()
		return float64(elapsed.Microseconds()) / 1000
	}
	if strings.Contains(err.Error(), "connection refused") {
		return float64(elapsed.Microseconds()) / 1000
	}
	return -1
}

func httpMs(ctx context.Context, url string) float64 {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}
	rctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, url, nil)
	if err != nil {
		return -1
	}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: dialTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return -1
	}
	resp.Body.Close()
	return float64(time.Since(start).Microseconds()) / 1000
}

func icmpMs(ctx context.Context, target, src string) float64 {
	p, err := probing.NewPinger(target)
	if err != nil {
		return -1
	}
	if src != "" {
		p.Source = src
	}
	p.Count = 1
	p.Timeout = dialTimeout
	p.SetPrivileged(true)
	if err := p.RunWithContext(ctx); err != nil {
		// Without CAP_NET_RAW fall back to an unprivileged UDP ping.
		p.SetPrivileged(false)
		if err := p.RunWithContext(ctx); err != nil {
			return -1
		}
	}
	st := p.Statistics()
	if st == nil || st.PacketsRecv == 0 {
		return -1
	}
	return float64(st.AvgRtt.Microseconds()) / 1000
}

// Results exposes only the latest measurement and its rolling window.
func (r *Runner) Results() []spec.PingResult { return r.results(false) }

// Batch includes outstanding attempts. Other readers cannot consume the queue.
func (r *Runner) Batch() []spec.PingResult { return r.results(true) }
func (r *Runner) results(batch bool) []spec.PingResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []spec.PingResult{}
	keys := []probeKey{}
	for k := range r.records {
		if k.id != 0 {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].id != keys[j].id {
			return keys[i].id < keys[j].id
		}
		return keys[i].name < keys[j].name
	})
	carriers := []probeKey{}
	for _, t := range carrierTasks(r.cfg) {
		carriers = append(carriers, probeKey{0, t.Name, t.Series})
	}
	keys = append(carriers, keys...)
	for _, key := range keys {
		rec := r.records[key]
		if rec == nil {
			continue
		}
		p := rec.result
		q := *p.Quality
		p.Quality = &q
		if batch {
			for _, m := range rec.samples {
				if m.Sequence > rec.acknowledged {
					q.Recent = append(q.Recent, m)
				}
			}
		}
		out = append(out, p)
	}
	return out
}

// Acknowledge only the batch that Captain accepted, including when a newer
// local measurement arrived while the network request was in flight.
func (r *Runner) Acknowledge(batch []spec.PingResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range batch {
		if p.Quality == nil || p.Quality.Epoch != r.epoch {
			continue
		}
		if rec := r.records[probeKey{p.TaskID, p.Name, p.Series}]; rec != nil {
			rec.acknowledged = max(rec.acknowledged, p.Quality.Sequence)
		}
	}
}
