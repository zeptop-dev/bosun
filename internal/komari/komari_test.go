package komari

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

type fakeSampler struct{}

func (fakeSampler) Sample(context.Context) spec.SystemStatus {
	return spec.SystemStatus{CPUPercent: 12.5, MemTotal: 1000, MemUsed: 400, DiskTotal: 100, DiskUsed: 10, Load1: 0.5, NetUp: 10, NetDown: 20, NetTotalUp: 1000, NetTotalDown: 2000, TCP: 3, UDP: 1, Processes: 42, Uptime: 99, Info: &spec.HostInfo{CPUModel: "cpu", CPUCores: 2, Arch: "amd64", OS: "Debian 13", Kernel: "6.1", Virt: "kvm"}}
}

type fakeProber struct{}

func (fakeProber) Measure(context.Context, spec.PingTask) float64 { return 28 }

type fakeKomari struct {
	mu        sync.Mutex
	registers int
	names     []string
	methods   []string
	pings     []map[string]any
	sentPing  bool
}

func (f *fakeKomari) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/api/clients/register":
		if r.Header.Get("Authorization") != "Bearer adkey-1234567890" {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"status":"error","message":"Invalid AutoDiscovery Key"}`))
			return
		}
		f.registers++
		f.names = append(f.names, r.URL.Query().Get("name"))
		_, _ = w.Write([]byte(`{"status":"success","data":{"uuid":"u-1","token":"tok-1"}}`))
	case r.URL.Path == "/api/clients/v2/rpc":
		if r.URL.Query().Get("token") != "tok-1" {
			w.WriteHeader(401)
			return
		}
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.methods = append(f.methods, req.Method)
		events := []any{}
		if req.Method == "agent.pull" && !f.sentPing {
			f.sentPing = true
			events = append(events, map[string]any{"id": "ev-1", "method": "agent.ping", "params": map[string]any{"ping_task_id": 7, "ping_type": "tcp", "target": "192.0.2.10:443"}})
		}
		if req.Method == "agent.pingResult" {
			f.pings = append(f.pings, req.Params)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "result": map[string]any{"events": events}})
	default:
		w.WriteHeader(404)
	}
}

func TestExporterRegistersReportsAndPings(t *testing.T) {
	fk := &fakeKomari{}
	srv := httptest.NewServer(fk)
	defer srv.Close()
	e := &Exporter{CredFile: filepath.Join(t.TempDir(), "komari.json"), Sampler: fakeSampler{}, Prober: fakeProber{}, Version: "test"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.Configure(ctx, &spec.Komari{Enabled: true, Server: srv.URL + "/", Key: "adkey-1234567890", Name: "jp1", Interval: 1})
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		fk.mu.Lock()
		done := len(fk.pings) > 0 && strings.Contains(strings.Join(fk.methods, ","), "agent.report")
		fk.mu.Unlock()
		if done {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	fk.mu.Lock()
	defer fk.mu.Unlock()
	if fk.registers != 1 || fk.names[0] != "jp1" {
		t.Fatalf("registers=%d names=%v", fk.registers, fk.names)
	}
	joined := strings.Join(fk.methods, ",")
	if !strings.Contains(joined, "agent.basicInfo") || !strings.Contains(joined, "agent.report") || !strings.Contains(joined, "agent.pull") {
		t.Fatalf("methods: %s", joined)
	}
	if len(fk.pings) == 0 || fk.pings[0]["task_id"].(float64) != 7 || fk.pings[0]["value"].(float64) != 28 {
		t.Fatalf("pings: %v", fk.pings)
	}
	st := e.Status()
	if !st.Registered || st.UUID != "u-1" || st.Reports == 0 || st.LastError != "" {
		t.Fatalf("status: %+v", st)
	}
	// Reconfiguring with the same server reuses the saved registration.
	e.Configure(ctx, &spec.Komari{Enabled: false})
	e.Configure(ctx, &spec.Komari{Enabled: true, Server: srv.URL, Interval: 1})
	time.Sleep(1500 * time.Millisecond)
	if fk.registers != 1 {
		t.Fatalf("re-registered: %d", fk.registers)
	}
}

func TestExporterBadKey(t *testing.T) {
	fk := &fakeKomari{}
	srv := httptest.NewServer(fk)
	defer srv.Close()
	e := &Exporter{CredFile: filepath.Join(t.TempDir(), "komari.json"), Sampler: fakeSampler{}, Prober: fakeProber{}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.Configure(ctx, &spec.Komari{Enabled: true, Server: srv.URL, Key: "wrong-key-123456"})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && e.Status().LastError == "" {
		time.Sleep(50 * time.Millisecond)
	}
	if st := e.Status(); !strings.Contains(st.LastError, "AutoDiscovery") || st.Registered {
		t.Fatalf("status: %+v", st)
	}
}
