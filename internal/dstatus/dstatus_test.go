package dstatus

import (
	"context"
	"encoding/json"
	"net/http"
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
