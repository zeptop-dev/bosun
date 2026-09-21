// Package dstatus answers a DStatus panel's scrapes as a neko-status
// agent: the panel fetches "GET /stat" with a "key" header and expects
// {"success":true,"data":{…}} carrying a gopsutil-shaped snapshot of the
// host. It is a pull, unlike Komari's push, so this serves a listener
// rather than dialing out — and only ever answers that one path, with no
// terminal, file or exec surface of any kind.
package dstatus

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
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
	Enabled bool   `json:"enabled"`
	Listen  string `json:"listen,omitempty"`
	// LastError is the reason the listener is not up, if it is not.
	LastError string `json:"last_error,omitempty"`
	// LastScrape is when a panel last read the endpoint with the right
	// key: the difference between "configured" and "actually used".
	LastScrape time.Time `json:"last_scrape,omitempty"`
	// Denied counts scrapes turned away for a bad key, so a
	// misconfiguration looks different from silence.
	Denied int `json:"denied,omitempty"`
}

// Exporter serves the endpoint while it is configured.
type Exporter struct {
	Sampler Sampler
	Log     *slog.Logger

	mu      sync.Mutex
	cfg     spec.DStatus
	srv     *http.Server
	status  Status
	scraped time.Time
	denied  int
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

// Configure starts, restarts or stops the listener to match cfg. A nil or
// disabled config stops it.
func (e *Exporter) Configure(cfg *spec.DStatus) {
	want := spec.DStatus{}
	if cfg != nil {
		want = *cfg
	}
	if want.Listen == "" {
		want.Listen = spec.DStatusListen
	}
	e.mu.Lock()
	same := e.srv != nil && want == e.cfg
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
		e.setStatus(Status{Enabled: true, Listen: want.Listen, LastError: "no key set: the endpoint would be open to anyone"})
		return
	}
	ln, err := net.Listen("tcp", want.Listen)
	if err != nil {
		e.setStatus(Status{Enabled: true, Listen: want.Listen, LastError: err.Error()})
		e.log().Error("dstatus listener", "listen", want.Listen, "err", err)
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /stat", e.stat)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10}
	e.mu.Lock()
	e.cfg, e.srv, e.bound = want, srv, ln.Addr().String()
	e.status = Status{Enabled: true, Listen: e.bound}
	e.mu.Unlock()
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			e.setStatus(Status{Enabled: true, Listen: want.Listen, LastError: err.Error()})
		}
	}()
	e.log().Info("dstatus endpoint", "listen", want.Listen)
}

// Stop shuts the listener down.
func (e *Exporter) Stop() {
	e.mu.Lock()
	srv := e.srv
	e.srv, e.cfg, e.bound = nil, spec.DStatus{}, ""
	e.mu.Unlock()
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = srv.Shutdown(ctx)
		cancel()
	}
}

// Status returns the current state.
func (e *Exporter) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.status
	st.LastScrape, st.Denied = e.scraped, e.denied
	return st
}

func (e *Exporter) setStatus(st Status) {
	e.mu.Lock()
	e.status = st
	e.mu.Unlock()
}

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
	var s spec.SystemStatus
	if e.Sampler != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		s = e.Sampler.Sample(ctx)
		cancel()
	}
	e.mu.Lock()
	e.scraped = time.Now()
	e.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": Payload(s)})
}

// Payload renders bosun's sample in neko-status' shape. Fields bosun does
// not measure are left empty rather than invented: per-core percentages
// and per-interface counters come back as an empty list and an empty
// object, which the panel renders as "nothing to show" instead of wrong
// numbers.
func Payload(s spec.SystemStatus) map[string]any {
	host, _ := os.Hostname()
	info := s.Info
	if info == nil {
		info = &spec.HostInfo{}
	}
	return map[string]any{
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
