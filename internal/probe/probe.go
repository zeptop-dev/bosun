// Package probe measures latency for the panel's status page: TCP-connect
// checks against the three Chinese carriers' probe points (the ServerStatus
// technique: unprivileged, ICMP-free) and panel-defined tasks (icmp, tcp,
// http). Results are kept in memory and attached to every beat.
package probe

import (
	"context"
	"net"
	"net/http"
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

const (
	carrierInterval = 10 * time.Second
	ringSize        = 30 // 5 minutes of carrier samples
	dialTimeout     = 3 * time.Second
	downloadWindow  = 8 * time.Second // like the speed-test tools: ~8s of transfer
)

// Runner owns the probe goroutines.
type Runner struct {
	// Dial overrides TCP dialing (tests).
	Dial func(ctx context.Context, addr string) (time.Duration, error)
	// DialFrom is Dial with a bound source address (tests).
	DialFrom func(ctx context.Context, src, addr string) (time.Duration, error)
	// Download overrides the throughput test (tests).
	Download func(ctx context.Context, url string) (ttfbMs, mbps float64)

	mu      sync.Mutex
	cfg     spec.Probe
	cancel  context.CancelFunc
	carrier map[string]*ring
	tasks   map[int64]spec.PingResult
}

type ring struct {
	samples []float64 // latency ms, -1 = lost
	next    int
	full    bool
}

func (r *ring) add(v float64) {
	if len(r.samples) < ringSize {
		r.samples = append(r.samples, v)
		return
	}
	r.samples[r.next] = v
	r.next = (r.next + 1) % ringSize
	r.full = true
}

func (r *ring) loss() float64 {
	if len(r.samples) < 3 {
		return 0
	}
	lost := 0
	for _, v := range r.samples {
		if v < 0 {
			lost++
		}
	}
	return float64(lost) * 100 / float64(len(r.samples))
}

func (r *ring) last() float64 {
	if len(r.samples) == 0 {
		return -1
	}
	i := r.next - 1
	if i < 0 {
		i = len(r.samples) - 1
	}
	return r.samples[i]
}

// Configure applies a new probe config, restarting goroutines when it
// changed. A nil or disabled config stops everything.
func (r *Runner) Configure(parent context.Context, cfg *spec.Probe) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var next spec.Probe
	if cfg != nil {
		next = *cfg
	}
	if sameConfig(r.cfg, next) && (r.cancel != nil || !next.Enabled) {
		return
	}
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	r.cfg = next
	r.tasks = map[int64]spec.PingResult{}
	if r.carrier == nil {
		r.carrier = map[string]*ring{}
	}
	if !next.Enabled {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	r.cancel = cancel
	if next.CarrierPing {
		for _, c := range carriersOf(next) {
			if r.carrier[c.Name] == nil {
				r.carrier[c.Name] = &ring{}
			}
			go r.carrierLoop(ctx, c.Name, c.Addr)
		}
	}
	for _, t := range next.Tasks {
		go r.taskLoop(ctx, t)
	}
}

func sameConfig(a, b spec.Probe) bool {
	if a.Enabled != b.Enabled || a.CarrierPing != b.CarrierPing || len(a.Tasks) != len(b.Tasks) || len(a.Carriers) != len(b.Carriers) {
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
}

func (r *Runner) carrierLoop(ctx context.Context, name, addr string) {
	t := time.NewTicker(carrierInterval)
	defer t.Stop()
	for {
		ms := r.tcpMs(ctx, addr)
		r.mu.Lock()
		if rg := r.carrier[name]; rg != nil {
			rg.add(ms)
		}
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (r *Runner) taskLoop(ctx context.Context, t spec.PingTask) {
	iv := time.Duration(t.IntervalSeconds) * time.Second
	if iv < 5*time.Second {
		iv = 30 * time.Second
	}
	if strings.EqualFold(t.Type, "download") && iv < 10*time.Minute {
		iv = 10 * time.Minute // throughput tests cost real traffic
	}
	tk := time.NewTicker(iv)
	defer tk.Stop()
	for {
		res := spec.PingResult{TaskID: t.ID, Name: t.Name, At: time.Now().Unix()}
		if strings.EqualFold(t.Type, "download") {
			res.LatencyMs, res.Mbps = r.download(ctx, t.Target)
		} else {
			res.LatencyMs = r.measure(ctx, t)
		}
		r.mu.Lock()
		r.tasks[t.ID] = res
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
	}
}

// measure runs one task: DNS is resolved before timing (Komari), a result
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

// Results returns the latest carrier and task measurements.
func (r *Runner) Results() []spec.PingResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []spec.PingResult
	if r.cfg.CarrierPing {
		for _, c := range carriersOf(r.cfg) {
			if rg := r.carrier[c.Name]; rg != nil && len(rg.samples) > 0 {
				out = append(out, spec.PingResult{Name: c.Name, LatencyMs: rg.last(), Loss: rg.loss(), At: time.Now().Unix()})
			}
		}
	}
	ids := make([]int64, 0, len(r.tasks))
	for id := range r.tasks {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		out = append(out, r.tasks[id])
	}
	return out
}

// download fetches url for up to downloadWindow and reports time to first
// byte and the average throughput in Mbps; -1/0 when it failed.
func (r *Runner) download(ctx context.Context, url string) (ttfbMs, mbps float64) {
	if r.Download != nil {
		return r.Download(ctx, url)
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}
	dctx, cancel := context.WithTimeout(ctx, downloadWindow+5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(dctx, http.MethodGet, url, nil)
	if err != nil {
		return -1, 0
	}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return -1, 0
	}
	defer resp.Body.Close()
	ttfb := time.Since(start)
	buf := make([]byte, 64<<10)
	var n int64
	deadline := time.Now().Add(downloadWindow)
	for time.Now().Before(deadline) {
		k, err := resp.Body.Read(buf)
		n += int64(k)
		if err != nil {
			break
		}
	}
	elapsed := time.Since(start) - ttfb
	if elapsed <= 0 || n == 0 {
		return float64(ttfb.Microseconds()) / 1000, 0
	}
	return float64(ttfb.Microseconds()) / 1000, float64(n) * 8 / elapsed.Seconds() / 1e6
}
