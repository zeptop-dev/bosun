// Package komari reports this node to a Komari monitoring server as a v2
// agent: auto-discovery registration once, then JSON-RPC over plain HTTP
// POST: agent.basicInfo, agent.report every few seconds, agent.pull for
// events and agent.pingResult for the ping tasks Komari hands out. Only the
// "ping" capability is advertised; terminal, files and exec are never
// offered.
package komari

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Sampler provides the host sample; Prober answers ping tasks.
type Sampler interface {
	Sample(ctx context.Context) spec.SystemStatus
}
type Prober interface {
	Measure(ctx context.Context, t spec.PingTask) float64
}

// Status is what the UI shows.
type Status struct {
	Enabled    bool      `json:"enabled"`
	Server     string    `json:"server"`
	UUID       string    `json:"uuid"`
	Registered bool      `json:"registered"`
	LastReport time.Time `json:"last_report"`
	LastError  string    `json:"last_error"`
	Reports    int64     `json:"reports"`
}

type creds struct {
	Server string `json:"server"`
	UUID   string `json:"uuid"`
	Token  string `json:"token"`
}

// Exporter runs one reporting loop for the current configuration.
type Exporter struct {
	CredFile string // <data_dir>/komari.json keeps the registration
	Sampler  Sampler
	Prober   Prober
	Log      *slog.Logger
	Version  string
	Client   *http.Client

	mu     sync.Mutex
	cfg    spec.Komari
	cancel context.CancelFunc
	status Status
}

func (e *Exporter) client() *http.Client {
	if e.Client != nil {
		return e.Client
	}
	return &http.Client{Timeout: 40 * time.Second}
}

func (e *Exporter) log() *slog.Logger {
	if e.Log == nil {
		return slog.Default()
	}
	return e.Log.With("component", "komari")
}

// Configure starts, restarts or stops the loop to match cfg.
func (e *Exporter) Configure(parent context.Context, cfg *spec.Komari) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var next spec.Komari
	if cfg != nil {
		next = *cfg
	}
	next.Server = strings.TrimRight(strings.TrimSpace(next.Server), "/")
	if next == e.cfg && (e.cancel != nil || !next.Enabled) {
		return
	}
	if e.cancel != nil {
		e.cancel()
		e.cancel = nil
	}
	e.cfg = next
	e.status = Status{Enabled: next.Enabled && next.Server != "", Server: next.Server}
	if !next.Enabled || next.Server == "" {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	e.cancel = cancel
	go e.run(ctx, next)
}

// Stop ends reporting.
func (e *Exporter) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cancel != nil {
		e.cancel()
		e.cancel = nil
	}
}

// Status returns a copy of the current state.
func (e *Exporter) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.status
}

func (e *Exporter) setErr(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err != nil {
		e.status.LastError = err.Error()
	} else {
		e.status.LastError = ""
	}
}

func (e *Exporter) loadCreds() (creds, bool) {
	if e.CredFile == "" {
		return creds{}, false
	}
	b, err := os.ReadFile(e.CredFile)
	if err != nil {
		return creds{}, false
	}
	var c creds
	if json.Unmarshal(b, &c) != nil || c.Token == "" {
		return creds{}, false
	}
	return c, true
}

func (e *Exporter) saveCreds(c creds) {
	if e.CredFile == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(e.CredFile), 0o750)
	b, _ := json.MarshalIndent(c, "", "  ")
	_ = os.WriteFile(e.CredFile, b, 0o600)
}

// Register creates the client on the server through the auto-discovery key.
func (e *Exporter) register(ctx context.Context, cfg spec.Komari) (creds, error) {
	if cfg.Key == "" {
		return creds{}, errors.New("no auto-discovery key and no saved registration")
	}
	name := cfg.Name
	if name == "" {
		name, _ = os.Hostname()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Server+"/api/clients/register?name="+url.QueryEscape(name), strings.NewReader("{}"))
	if err != nil {
		return creds{}, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client().Do(req)
	if err != nil {
		return creds{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var out struct {
		Status string `json:"status"`
		Data   struct {
			UUID  string `json:"uuid"`
			Token string `json:"token"`
		} `json:"data"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Status != "success" || out.Data.Token == "" {
		msg := strings.TrimSpace(string(body))
		if out.Message != "" {
			msg = out.Message
		}
		return creds{}, fmt.Errorf("register: %s %s", resp.Status, msg)
	}
	return creds{Server: cfg.Server, UUID: out.Data.UUID, Token: out.Data.Token}, nil
}

type rpcResult struct {
	Events []struct {
		ID     string          `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	} `json:"events"`
}

// rpc posts one JSON-RPC call and returns the result's events.
func (e *Exporter) rpc(ctx context.Context, c creds, method string, params any, id string) (*rpcResult, error) {
	payload := map[string]any{"jsonrpc": "2.0", "method": method, "params": params}
	if id != "" {
		payload["id"] = id
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Server+"/api/clients/v2/rpc?token="+url.QueryEscape(c.Token), bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, errUnauthorized
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%s: %s", method, resp.Status)
	}
	var out struct {
		Result rpcResult `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("%s: bad response", method)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("%s: %s", method, out.Error.Message)
	}
	return &out.Result, nil
}

var errUnauthorized = errors.New("token rejected")

func (e *Exporter) run(ctx context.Context, cfg spec.Komari) {
	log := e.log()
	c, have := e.loadCreds()
	if !have || c.Server != cfg.Server {
		nc, err := e.register(ctx, cfg)
		for err != nil {
			e.setErr(err)
			log.Warn("registration failed", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
			}
			nc, err = e.register(ctx, cfg)
		}
		c = nc
		e.saveCreds(c)
		log.Info("registered", "server", c.Server, "uuid", c.UUID)
	}
	e.mu.Lock()
	e.status.UUID, e.status.Registered = c.UUID, true
	e.mu.Unlock()

	interval := time.Duration(cfg.Interval) * time.Second
	if interval < time.Second {
		interval = 3 * time.Second
	}
	var ackMu sync.Mutex
	var acks []string
	takeAcks := func() []string {
		ackMu.Lock()
		defer ackMu.Unlock()
		out := acks
		acks = nil
		if out == nil {
			out = []string{}
		}
		return out
	}
	handle := func(res *rpcResult) {
		if res == nil {
			return
		}
		for _, ev := range res.Events {
			if ev.Method != "agent.ping" {
				continue
			}
			var p struct {
				TaskID   int64  `json:"ping_task_id"`
				PingType string `json:"ping_type"`
				Target   string `json:"target"`
			}
			_ = json.Unmarshal(ev.Params, &p)
			if p.TaskID <= 0 || e.Prober == nil {
				continue
			}
			go func(evID string, p struct {
				TaskID   int64  `json:"ping_task_id"`
				PingType string `json:"ping_type"`
				Target   string `json:"target"`
			}) {
				typ := strings.ToLower(p.PingType)
				if typ == "" {
					typ = "icmp"
				}
				mctx, cancel := context.WithTimeout(ctx, 20*time.Second)
				ms := e.Prober.Measure(mctx, spec.PingTask{ID: p.TaskID, Name: "komari", Type: typ, Target: p.Target})
				cancel()
				value := int(ms)
				if ms < 0 {
					value = -1
				}
				if _, err := e.rpc(ctx, c, "agent.pingResult", map[string]any{"task_id": p.TaskID, "ping_type": typ, "value": value, "finished_at": time.Now().UTC().Format(time.RFC3339)}, fmt.Sprintf("ping-%d-%d", p.TaskID, time.Now().UnixNano())); err == nil && evID != "" {
					ackMu.Lock()
					acks = append(acks, evID)
					ackMu.Unlock()
				}
			}(ev.ID, p)
		}
	}

	// Static facts once (retried until accepted).
	sendInfo := func() error {
		s := e.Sampler.Sample(ctx)
		info := map[string]any{"cpu_name": "", "cpu_cores": 0, "cpu_physical_cores": 0, "arch": "", "os": "", "kernel_version": "", "ipv4": "", "ipv6": "", "mem_total": s.MemTotal, "swap_total": s.SwapTotal, "disk_total": s.DiskTotal, "gpu_name": "", "virtualization": "", "version": "bosun/" + e.Version}
		if h := s.Info; h != nil {
			info["cpu_name"], info["cpu_cores"], info["cpu_physical_cores"], info["arch"], info["os"], info["kernel_version"], info["virtualization"] = h.CPUModel, h.CPUCores, h.CPUCores, h.Arch, h.OS, h.Kernel, h.Virt
		}
		res, err := e.rpc(ctx, c, "agent.basicInfo", map[string]any{"info": info}, "basic-info")
		handle(res)
		return err
	}
	infoSent := false

	// Event pull in its own goroutine (the server may long-poll).
	go func() {
		for {
			res, err := e.rpc(ctx, c, "agent.pull", map[string]any{"capabilities": []string{"ping"}, "ack_event_ids": takeAcks()}, fmt.Sprintf("pull-%d", time.Now().UnixNano()))
			if err == nil {
				handle(res)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
		}
	}()

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if !infoSent {
			if err := sendInfo(); err != nil {
				e.setErr(err)
				if errors.Is(err, errUnauthorized) {
					// The client was deleted on the server: register again next time.
					_ = os.Remove(e.CredFile)
					log.Warn("token rejected; will re-register")
					go e.reconfigureLater(ctx, cfg)
					return
				}
			} else {
				infoSent = true
			}
		}
		if infoSent {
			s := e.Sampler.Sample(ctx)
			report := map[string]any{
				"cpu":         map[string]any{"name": cpuName(s), "cores": cpuCores(s), "arch": arch(s), "usage": s.CPUPercent},
				"ram":         map[string]any{"total": s.MemTotal, "used": s.MemUsed},
				"swap":        map[string]any{"total": s.SwapTotal, "used": s.SwapUsed},
				"load":        map[string]any{"load1": s.Load1, "load5": s.Load5, "load15": s.Load15},
				"disk":        map[string]any{"total": s.DiskTotal, "used": s.DiskUsed},
				"network":     map[string]any{"up": s.NetUp, "down": s.NetDown, "totalUp": s.NetTotalUp, "totalDown": s.NetTotalDown},
				"connections": map[string]any{"tcp": s.TCP, "udp": s.UDP},
				"uptime":      s.Uptime,
				"process":     s.Processes,
				"message":     "",
			}
			res, err := e.rpc(ctx, c, "agent.report", map[string]any{"report": report, "ack_event_ids": takeAcks()}, fmt.Sprintf("report-%d", time.Now().UnixNano()))
			if err != nil {
				e.setErr(err)
				if errors.Is(err, errUnauthorized) {
					_ = os.Remove(e.CredFile)
					log.Warn("token rejected; will re-register")
					go e.reconfigureLater(ctx, cfg)
					return
				}
			} else {
				handle(res)
				e.mu.Lock()
				e.status.LastReport, e.status.LastError = time.Now(), ""
				e.status.Reports++
				e.mu.Unlock()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// reconfigureLater restarts the loop (which re-registers) after a pause.
func (e *Exporter) reconfigureLater(parent context.Context, cfg spec.Komari) {
	select {
	case <-parent.Done():
		return
	case <-time.After(30 * time.Second):
	}
	e.mu.Lock()
	if e.cfg != cfg {
		e.mu.Unlock()
		return
	}
	e.cfg = spec.Komari{}
	e.mu.Unlock()
	e.Configure(parent, &cfg)
}

func cpuName(s spec.SystemStatus) string {
	if s.Info != nil {
		return s.Info.CPUModel
	}
	return ""
}
func cpuCores(s spec.SystemStatus) int {
	if s.Info != nil {
		return s.Info.CPUCores
	}
	return 0
}
func arch(s spec.SystemStatus) string {
	if s.Info != nil {
		return s.Info.Arch
	}
	return ""
}
