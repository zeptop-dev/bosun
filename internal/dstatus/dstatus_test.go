package dstatus

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

type fakeSampler struct{ s spec.SystemStatus }

func (f fakeSampler) Sample(context.Context) spec.SystemStatus { return f.s }

func sample() spec.SystemStatus {
	return spec.SystemStatus{
		CPUPercent: 12.5,
		MemTotal:   2 << 30, MemUsed: 1 << 30,
		SwapTotal: 1 << 30, SwapUsed: 1 << 28,
		DiskTotal: 40 << 30, DiskUsed: 10 << 30,
		NetUp: 2040, NetDown: 1500, NetTotalUp: 880030157, NetTotalDown: 2303374903,
		Uptime: 521673, Processes: 112,
		Info: &spec.HostInfo{OS: "Alpine 3.23", Kernel: "6.1.0", Arch: "x86_64", Virt: "lxc", BootTime: 1742116089},
	}
}

// The endpoint is the one a DStatus panel scrapes: GET /stat with the key
// in a header, answered with {"success":true,"data":{…}}.
func TestServesWhatThePanelScrapes(t *testing.T) {
	e := &Exporter{Sampler: fakeSampler{sample()}}
	e.Configure(&spec.DStatus{Enabled: true, Listen: "127.0.0.1:0", Key: "s3cret"})
	defer e.Stop()
	addr := e.Status().Listen
	if addr == "" || e.Status().LastError != "" {
		t.Fatalf("listener did not come up: %+v", e.Status())
	}
	// Listen ":0" means the kernel picked the port; ask the server.
	url := "http://" + listenAddr(t, e) + "/stat"

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("key", "s3cret")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var body struct {
		Success bool           `json:"success"`
		Data    map[string]any `json:"data"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil || !body.Success {
		t.Fatalf("decode: %v %+v", err, body)
	}
	cpu := body.Data["cpu"].(map[string]any)
	if cpu["multi"].(float64) != 12.5 {
		t.Errorf("cpu.multi: %v", cpu["multi"])
	}
	net := body.Data["net"].(map[string]any)
	if d := net["delta"].(map[string]any); d["in"].(float64) != 1500 || d["out"].(float64) != 2040 {
		t.Errorf("net.delta is down/up: %v", d)
	}
	if tot := net["total"].(map[string]any); tot["in"].(float64) != 2303374903 {
		t.Errorf("net.total: %v", tot)
	}
	mem := body.Data["mem"].(map[string]any)
	if v := mem["virtual"].(map[string]any); v["usedPercent"].(float64) != 50 {
		t.Errorf("mem.virtual.usedPercent: %v", v)
	}
	if _, ok := mem["swap"].(map[string]any)["usedPercent"]; !ok {
		t.Error("the panel reads mem.swap.usedPercent")
	}
	// The panel calls .map on cpu.single, so it must be a list even when
	// we have no per-core figures.
	if _, ok := cpu["single"].([]any); !ok {
		t.Errorf("cpu.single must be a list: %T", cpu["single"])
	}
	if st := e.Status(); st.LastScrape.IsZero() {
		t.Error("a successful scrape should be recorded")
	}
}

// A wrong key gets nothing, and the count makes a misconfigured panel
// look different from a silent one.
func TestRefusesAWrongKey(t *testing.T) {
	e := &Exporter{Sampler: fakeSampler{sample()}}
	e.Configure(&spec.DStatus{Enabled: true, Listen: "127.0.0.1:0", Key: "right"})
	defer e.Stop()
	req, _ := http.NewRequest("GET", "http://"+listenAddr(t, e)+"/stat", nil)
	req.Header.Set("key", "wrong")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", res.StatusCode)
	}
	if st := e.Status(); st.Denied != 1 || !st.LastScrape.IsZero() {
		t.Fatalf("status %+v", st)
	}
}

// Without a key the endpoint would be open to anyone, so it does not come
// up at all; disabling takes the listener away again.
func TestRefusesToServeWithoutAKeyAndStops(t *testing.T) {
	e := &Exporter{Sampler: fakeSampler{sample()}}
	e.Configure(&spec.DStatus{Enabled: true, Listen: "127.0.0.1:0"})
	if st := e.Status(); st.LastError == "" {
		t.Fatalf("a keyless endpoint must not serve: %+v", st)
	}
	e.Configure(&spec.DStatus{Enabled: true, Listen: "127.0.0.1:0", Key: "k"})
	addr := listenAddr(t, e)
	e.Configure(nil)
	if st := e.Status(); st.Enabled {
		t.Fatalf("disabled: %+v", st)
	}
	c := http.Client{Timeout: 2 * time.Second}
	if _, err := c.Get("http://" + addr + "/stat"); err == nil {
		t.Fatal("the listener is still up after being disabled")
	}
}

// listenAddr reads the address the server actually bound.
func listenAddr(t *testing.T, e *Exporter) string {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.bound == "" {
		t.Fatal("no bound address")
	}
	return e.bound
}

// officialPanel is what the official DStatus server does with a report,
// read out of its /stats/update handler: the key must arrive in a "key"
// header, the body is {sid, data}, and validateReportData wants a
// hostname, a numeric cpu.multi, mem.virtual.used and the four net
// counters. It answers 200 either way, with success 1 or 0.
func officialPanel(t *testing.T, key, sid string, hits *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/stats/update" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		refuse := func(msg string) {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": 0, "data": msg, "success": 0})
		}
		if r.Header.Get("key") != key {
			refuse("API 密钥无效")
			return
		}
		var body struct {
			SID  string         `json:"sid"`
			Data map[string]any `json:"data"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.SID != sid || body.Data == nil {
			refuse("无效的上报数据")
			return
		}
		d := body.Data
		host, _ := d["host"].(map[string]any)
		if _, ok := d["hostname"].(string); !ok {
			if _, ok := host["hostname"].(string); !ok {
				refuse("缺少 hostname")
				return
			}
		}
		if _, ok := d["cpu"].(map[string]any)["multi"].(float64); !ok {
			refuse("cpu.multi")
			return
		}
		if _, ok := d["mem"].(map[string]any)["virtual"].(map[string]any)["used"].(float64); !ok {
			refuse("mem.virtual.used")
			return
		}
		net := d["net"].(map[string]any)
		for _, k := range []string{"delta", "total"} {
			m, _ := net[k].(map[string]any)
			if _, ok := m["in"].(float64); !ok {
				refuse("net." + k)
				return
			}
			if _, ok := m["out"].(float64); !ok {
				refuse("net." + k)
				return
			}
		}
		atomic.AddInt32(hits, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": 1, "data": "update success", "success": 1})
	}))
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timed out waiting for " + what)
}

// Active mode posts what the official panel's validator accepts, with the
// key in the header, and listens on nothing.
func TestActiveModeReportsWhatTheOfficialPanelAccepts(t *testing.T) {
	var hits int32
	panel := officialPanel(t, "s3cret", "42", &hits)
	defer panel.Close()
	e := &Exporter{Sampler: fakeSampler{sample()}}
	e.Configure(&spec.DStatus{Enabled: true, Mode: spec.DStatusActive, Server: panel.URL + "/", SID: "42", Key: "s3cret", Interval: 1})
	defer e.Stop()
	waitFor(t, "a report", func() bool { return atomic.LoadInt32(&hits) > 0 })
	st := e.Status()
	if st.Mode != "active" || st.LastError != "" || st.Reports == 0 || st.LastReport.IsZero() {
		t.Fatalf("status %+v", st)
	}
	if st.Listen != "" || listenAddrOrEmpty(e) != "" {
		t.Fatalf("active mode must not listen: %+v", st)
	}
	// Reports keep coming on the interval.
	n := atomic.LoadInt32(&hits)
	waitFor(t, "another report", func() bool { return atomic.LoadInt32(&hits) > n })
}

// The panel's refusal — a wrong key, here — is surfaced with its reason,
// and stops counting as accepted.
func TestActiveModeSurfacesThePanelsRefusal(t *testing.T) {
	var hits int32
	panel := officialPanel(t, "right", "42", &hits)
	defer panel.Close()
	e := &Exporter{Sampler: fakeSampler{sample()}}
	e.Configure(&spec.DStatus{Enabled: true, Mode: spec.DStatusActive, Server: panel.URL, SID: "42", Key: "wrong", Interval: 1})
	defer e.Stop()
	waitFor(t, "a refusal", func() bool { return e.Status().LastError != "" })
	st := e.Status()
	if !strings.Contains(st.LastError, "refused") || !strings.Contains(st.LastError, "密钥") || st.Reports != 0 {
		t.Fatalf("status %+v", st)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatal("the panel should not have accepted anything")
	}
}

// Active mode without a panel URL or a SID cannot work and says so.
func TestActiveModeNeedsServerAndSID(t *testing.T) {
	e := &Exporter{Sampler: fakeSampler{sample()}}
	for _, cfg := range []spec.DStatus{
		{Enabled: true, Mode: spec.DStatusActive, Key: "k", SID: "42"},
		{Enabled: true, Mode: spec.DStatusActive, Key: "k", Server: "http://panel.example.com"},
		{Enabled: true, Mode: spec.DStatusActive, Key: "k", Server: "panel.example.com", SID: "42"},
	} {
		e.Configure(&cfg)
		if st := e.Status(); st.LastError == "" || st.Reports != 0 {
			t.Fatalf("%+v: %+v", cfg, st)
		}
	}
	e.Configure(nil)
	if st := e.Status(); st.Enabled {
		t.Fatalf("disabled: %+v", st)
	}
}

// refused reads both panels' answers.
func TestRefusedReadsBothPanelsAnswers(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		refused bool
	}{
		{`{"status":1,"data":"update success","success":1}`, false}, // official, accepted
		{`{"status":0,"data":"API 密钥无效","success":0}`, true},        // official, refused
		{`{"status":1,"data":"update success"}`, false},             // open-source
		{`{"status":0,"data":"no"}`, true},
		{`{"success":true}`, false},
		{`{"success":false,"msg":"nope"}`, true},
		{`not json`, false},
	} {
		if _, got := refused([]byte(tc.raw)); got != tc.refused {
			t.Errorf("%s: refused=%v", tc.raw, got)
		}
	}
}

func listenAddrOrEmpty(e *Exporter) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.bound
}
