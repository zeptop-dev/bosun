// Package dstatus makes the node a DStatus agent without DStatus' own
// agent on the box. Two directions, matching the panel's 通讯模式 switch:
//
//   - passive (被动, the default): the node serves "GET /stat" and the
//     panel scrapes it with the key in a "key" header, answered with
//     {"success":true,"data":{…}} in neko-status' shape;
//   - active (主动): the node posts {"sid","data"} to the panel's
//     /stats/update every few seconds with the same header, and does not
//     listen at all — for hosts the panel cannot reach.
//
// Either way the sample is the whole surface: no terminal, files or exec.
package dstatus

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Sampler provides the host sample (the agent's own probe sampler).
type Sampler interface {
	Sample(ctx context.Context) spec.SystemStatus
}

// Status is what the UI and the doctor show.
type Status struct {
	Enabled  bool   `json:"enabled"`
	Mode     string `json:"mode,omitempty"`     // "passive" or "active"
	Listen   string `json:"listen,omitempty"`   // passive: the address actually bound
	Server   string `json:"server,omitempty"`   // active: the panel reported to
	Interval int    `json:"interval,omitempty"` // active: seconds between reports
	// LastError is why the endpoint is not up or the last report failed.
	LastError string `json:"last_error,omitempty"`
	// LastScrape (passive) is when a panel last read the endpoint with the
	// right key: the difference between "configured" and "actually used".
	LastScrape time.Time `json:"last_scrape,omitempty"`
	// Denied (passive) counts scrapes turned away for a bad key.
	Denied int `json:"denied,omitempty"`
	// LastReport and Reports (active) say whether the panel takes them.
	LastReport time.Time `json:"last_report,omitempty"`
	Reports    int       `json:"reports,omitempty"`
}

// Exporter serves or reports while it is configured.
type Exporter struct {
	Sampler Sampler
	Log     *slog.Logger
	// Client is used for active-mode reports; nil means a 10 s timeout.
	Client *http.Client
	// Version goes into the User-Agent of reports.
	Version string

	mu       sync.Mutex
	cfg      spec.DStatus
	srv      *http.Server       // passive
	cancel   context.CancelFunc // active
	status   Status
	scraped  time.Time
	reported time.Time
	denied   int
	reports  int
	// bound is the address the listener actually got, which differs from
	// the configured one when the port is left to the kernel.
	bound string
}

func (e *Exporter) log() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.Default()
}

func (e *Exporter) client() *http.Client {
	if e.Client != nil {
		return e.Client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// Configure starts, restarts or stops whichever direction cfg asks for. A
// nil or disabled config stops everything.
func (e *Exporter) Configure(cfg *spec.DStatus) {
	want := spec.DStatus{}
	if cfg != nil {
		want = *cfg
	}
	if want.Listen == "" {
		want.Listen = spec.DStatusListen
	}
	if want.Interval <= 0 {
		want.Interval = 3
	}
	want.Server = strings.TrimRight(strings.TrimSpace(want.Server), "/")
	want.SID = strings.TrimSpace(want.SID)
	e.mu.Lock()
	same := (e.srv != nil || e.cancel != nil) && want == e.cfg
	e.mu.Unlock()
	if same {
		return
	}
	e.Stop()
	if !want.Enabled {
		e.setStatus(Status{})
		return
	}
	if want.Key == "" {
		e.setStatus(Status{Enabled: true, Mode: modeOf(want), Listen: want.Listen, Server: want.Server, LastError: "no key set: the endpoint would be open to anyone"})
		return
	}
	if want.Active() {
		e.startActive(want)
		return
	}
	e.startPassive(want)
}

func modeOf(d spec.DStatus) string {
	if d.Active() {
		return spec.DStatusActive
	}
	return "passive"
}

func (e *Exporter) startPassive(want spec.DStatus) {
	ln, err := net.Listen("tcp", want.Listen)
	if err != nil {
		e.setStatus(Status{Enabled: true, Mode: "passive", Listen: want.Listen, LastError: err.Error()})
		e.log().Error("dstatus listener", "listen", want.Listen, "err", err)
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /stat", e.stat)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10}
	e.mu.Lock()
	e.cfg, e.srv, e.bound = want, srv, ln.Addr().String()
	e.status = Status{Enabled: true, Mode: "passive", Listen: e.bound}
	e.mu.Unlock()
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			e.setStatus(Status{Enabled: true, Mode: "passive", Listen: want.Listen, LastError: err.Error()})
		}
	}()
	e.log().Info("dstatus endpoint", "listen", want.Listen)
}

func (e *Exporter) startActive(want spec.DStatus) {
	switch {
	case want.Server == "" || want.SID == "":
		e.setStatus(Status{Enabled: true, Mode: spec.DStatusActive, Server: want.Server, Interval: want.Interval, LastError: "active mode needs the panel URL and this node's server id (SID)"})
		return
	case !strings.HasPrefix(want.Server, "http://") && !strings.HasPrefix(want.Server, "https://"):
		e.setStatus(Status{Enabled: true, Mode: spec.DStatusActive, Server: want.Server, Interval: want.Interval, LastError: "the panel URL must start with http:// or https://"})
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.mu.Lock()
	e.cfg, e.cancel = want, cancel
	e.status = Status{Enabled: true, Mode: spec.DStatusActive, Server: want.Server, Interval: want.Interval}
	e.mu.Unlock()
	go e.run(ctx, want)
	e.log().Info("dstatus reporting", "server", want.Server, "sid", want.SID, "interval", want.Interval)
}

// Stop ends whichever direction is running.
func (e *Exporter) Stop() {
	e.mu.Lock()
	srv, cancel := e.srv, e.cancel
	e.srv, e.cancel, e.cfg, e.bound = nil, nil, spec.DStatus{}, ""
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if srv != nil {
		ctx, c := context.WithTimeout(context.Background(), 3*time.Second)
		_ = srv.Shutdown(ctx)
		c()
	}
}

// Status returns the current state.
func (e *Exporter) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.status
	st.LastScrape, st.Denied = e.scraped, e.denied
	st.LastReport, st.Reports = e.reported, e.reports
	return st
}

func (e *Exporter) setStatus(st Status) {
	e.mu.Lock()
	e.status = st
	e.mu.Unlock()
}

func (e *Exporter) setErr(msg string) {
	e.mu.Lock()
	e.status.LastError = msg
	e.mu.Unlock()
}

// ---- passive -----------------------------------------------------------------

// stat answers the one endpoint neko-status serves.
func (e *Exporter) stat(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	key := e.cfg.Key
	e.mu.Unlock()
	if key == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("key")), []byte(key)) != 1 {
		e.mu.Lock()
		e.denied++
		e.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "msg": "bad key"})
		return
	}
	s := e.sample(r.Context())
	e.mu.Lock()
	e.scraped = time.Now()
	e.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": Payload(s)})
}

// ---- active ------------------------------------------------------------------

// run reports on the interval until the context ends; the first report
// goes out at once so the panel sees the node without waiting a cycle.
func (e *Exporter) run(ctx context.Context, cfg spec.DStatus) {
	t := time.NewTicker(time.Duration(cfg.Interval) * time.Second)
	defer t.Stop()
	for {
		e.report(ctx, cfg)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// report is one POST /stats/update: the path the open-source panel serves
// and the official one aliases as /api/report, so one URL fits both.
func (e *Exporter) report(ctx context.Context, cfg spec.DStatus) {
	s := e.sample(ctx)
	body, err := json.Marshal(map[string]any{"sid": cfg.SID, "data": Payload(s)})
	if err != nil {
		e.setErr(err.Error())
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Server+"/stats/update", bytes.NewReader(body))
	if err != nil {
		e.setErr(err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("key", cfg.Key)
	req.Header.Set("User-Agent", "bosun/"+e.Version)
	resp, err := e.client().Do(req)
	if err != nil {
		if ctx.Err() == nil {
			e.setErr(err.Error())
		}
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		e.setErr(fmt.Sprintf("panel answered %d: %s", resp.StatusCode, clip(raw)))
		return
	}
	if msg, refused := refused(raw); refused {
		e.setErr("panel refused the report: " + msg)
		return
	}
	e.mu.Lock()
	e.reported, e.reports = time.Now(), e.reports+1
	e.status.LastError = ""
	e.mu.Unlock()
}

// refused reads the panel's verdict. The official panel answers
// {"status":1,"data":"update success","success":1} and, when it will not
// have the report, the same with 0 and a message; the open-source one only
// has "status". Anything not clearly a refusal counts as accepted.
func refused(raw []byte) (string, bool) {
	var ans struct {
		Success any    `json:"success"`
		Status  any    `json:"status"`
		Data    any    `json:"data"`
		Msg     string `json:"msg"`
	}
	if err := json.Unmarshal(raw, &ans); err != nil {
		return "", false
	}
	no := func(v any) bool {
		switch x := v.(type) {
		case bool:
			return !x
		case float64:
			return x == 0
		}
		return false
	}
	if !no(ans.Success) && !no(ans.Status) {
		return "", false
	}
	if ans.Success != nil && !no(ans.Success) {
		return "", false
	}
	msg := ans.Msg
	if str, ok := ans.Data.(string); ok && msg == "" {
		msg = str
	}
	if msg == "" {
		msg = clip(raw)
	}
	return msg, true
}

func clip(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

func (e *Exporter) sample(ctx context.Context) spec.SystemStatus {
	if e.Sampler == nil {
		return spec.SystemStatus{}
	}
	sctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	return e.Sampler.Sample(sctx)
}

// ---- payload -----------------------------------------------------------------

// Payload renders bosun's sample in neko-status' shape. Fields bosun does
// not measure are left empty rather than invented: per-core percentages
// and per-interface counters come back as an empty list and an empty
// object, which the panel renders as "nothing to show" instead of wrong
// numbers. hostname is repeated at the top because the official panel's
// report validator looks there first.
func Payload(s spec.SystemStatus) map[string]any {
	host, _ := os.Hostname()
	info := s.Info
	if info == nil {
		info = &spec.HostInfo{}
	}
	return map[string]any{
		"hostname": host,
		"cpu": map[string]any{
			"multi":  s.CPUPercent,
			"single": []float64{},
		},
		"mem": map[string]any{
			"virtual": usage(s.MemTotal, s.MemUsed),
			"swap":    usage(s.SwapTotal, s.SwapUsed),
		},
		"disk":  usage(s.DiskTotal, s.DiskUsed),
		"disks": disks(s),
		"host": map[string]any{
			"hostname":             host,
			"uptime":               s.Uptime,
			"bootTime":             info.BootTime,
			"procs":                s.Processes,
			"os":                   "linux",
			"platform":             info.OS,
			"platformVersion":      info.OS,
			"kernelVersion":        info.Kernel,
			"kernelArch":           info.Arch,
			"virtualizationSystem": info.Virt,
			"virtualizationRole":   virtRole(info.Virt),
		},
		"net": map[string]any{
			// in/out are the panel's words for down/up.
			"delta":   map[string]any{"in": s.NetDown, "out": s.NetUp},
			"total":   map[string]any{"in": s.NetTotalDown, "out": s.NetTotalUp},
			"devices": map[string]any{},
		},
	}
}

func usage(total, used uint64) map[string]any {
	var free uint64
	if total > used {
		free = total - used
	}
	pct := 0.0
	if total > 0 {
		pct = float64(used) / float64(total) * 100
	}
	return map[string]any{"total": total, "used": used, "free": free, "available": free, "usedPercent": pct}
}

// disks carries the one filesystem bosun measures, the root.
func disks(s spec.SystemStatus) []map[string]any {
	if s.DiskTotal == 0 {
		return []map[string]any{}
	}
	d := usage(s.DiskTotal, s.DiskUsed)
	d["mount"] = "/"
	d["percent"] = d["usedPercent"]
	return []map[string]any{d}
}

func virtRole(virt string) string {
	if virt == "" {
		return ""
	}
	return "guest"
}
