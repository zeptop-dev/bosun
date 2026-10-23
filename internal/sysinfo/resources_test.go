package sysinfo

import (
	"context"
	"encoding/json"
	"github.com/zeptop-dev/bosun/internal/core/subprocess"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestIndependentResourceDeltas(t *testing.T) {
	base := time.Unix(100, 0)
	makeRaw := func(at time.Time, sent uint64) rawResources {
		return rawResources{
			at: at, cpus: []cpu.TimesStat{{CPU: "cpu0", User: 10, Idle: 90}},
			networks: []gnet.IOCountersStat{{Name: "eth0", BytesSent: sent, BytesRecv: sent}}, networkIDs: map[string]string{"eth0": "boot:1"},
			disks: map[string]disk.IOCountersStat{"sda": {ReadBytes: sent, WriteBytes: sent}},
		}
	}
	first := makeRaw(base, 100)
	r, _, _, _, _, _, cpuOK, netOK := reduceResources(first, rawResources{}, spec.ResourceOptions{})
	if cpuOK || netOK || r.CPUs[0].Percent != nil || r.Networks[0].UpRate != nil || r.Disks[0].ReadRate != nil {
		t.Fatal("first sample fabricated a rate")
	}
	next := makeRaw(base.Add(10*time.Second), 200)
	next.cpus[0].User = 15
	next.cpus[0].Idle = 95
	r, pct, up, down, _, _, cpuOK, netOK := reduceResources(next, first, spec.ResourceOptions{})
	if !cpuOK || !netOK || pct != 50 || up != 10 || down != 10 || *r.Disks[0].ReadRate != 10 {
		t.Fatalf("bad delta %+v cpu=%f net=%d/%d", r, pct, up, down)
	}
	// Adding a high-counter interface must not become an enormous host rate.
	added := makeRaw(base.Add(20*time.Second), 300)
	added.networks = append(added.networks, gnet.IOCountersStat{Name: "eth1", BytesSent: 1 << 40})
	added.networkIDs["eth1"] = "boot:2"
	r, _, up, _, _, _, _, netOK = reduceResources(added, next, spec.ResourceOptions{})
	if netOK || up != 0 || r.Networks[0].UpRate == nil || *r.Networks[0].UpRate != 10 || r.Networks[1].UpRate != nil {
		t.Fatal("new NIC corrupted existing NIC rate")
	}
	// A reset, failed collection or changed interface identity needs a baseline.
	for _, tc := range []string{"reset", "missing", "replacement"} {
		t.Run(tc, func(t *testing.T) {
			current := makeRaw(base.Add(20*time.Second), 300)
			previous := next
			switch tc {
			case "reset":
				current.networks[0].BytesSent = 1
			case "missing":
				previous.networks = nil
			case "replacement":
				current.networkIDs["eth0"] = "boot:3"
			}
			r, _, _, _, _, _, _, ok := reduceResources(current, previous, spec.ResourceOptions{})
			if ok || r.Networks[0].UpRate != nil {
				t.Fatal("invalid baseline used")
			}
		})
	}
	// Measured zero is present, including in JSON. Null is reserved for missing.
	idle := makeRaw(base.Add(20*time.Second), 200)
	idle.cpus[0].User = 15
	idle.cpus[0].Idle = 105
	r, pct, _, _, _, _, cpuOK, netOK = reduceResources(idle, next, spec.ResourceOptions{})
	if !cpuOK || !netOK || pct != 0 || r.Networks[0].UpRate == nil || *r.Networks[0].UpRate != 0 {
		t.Fatal("zero discarded")
	}
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), `"up_rate":0`) {
		t.Fatal(string(b))
	}
}

func TestManagedProcessRestartAndNICSelection(t *testing.T) {
	a, b := 2.0, 4.0
	old := rawResources{at: time.Unix(100, 0), processes: map[int32]processSample{42: {name: "xray", started: 1, seconds: &a}}}
	next := rawResources{at: time.Unix(101, 0), processes: map[int32]processSample{42: {name: "xray", started: 1, seconds: &b}}}
	r, _, _, _, _, _, _, _ := reduceResources(next, old, spec.ResourceOptions{})
	if r.Processes[0].CPU == nil || *r.Processes[0].CPU != 200 {
		t.Fatal("process CPU must allow multiple cores")
	}
	next.processes[42] = processSample{name: "xray", started: 2, seconds: &b}
	r, _, _, _, _, _, _, _ = reduceResources(next, old, spec.ResourceOptions{})
	if r.Processes[0].CPU != nil {
		t.Fatal("reused PID inherited CPU baseline")
	}
	options := spec.ResourceOptions{}
	for _, n := range []string{"lo", "lo0", "docker0", "br-123", "veth123", "virbr0"} {
		if options.Includes(n) {
			t.Fatalf("included %s", n)
		}
	}
	if !options.Includes("eth0") {
		t.Fatal("eth0 excluded")
	}
	options.IncludeInterfaces = []string{"docker0", "eth0"}
	options.ExcludeInterfaces = []string{"eth0"}
	if !options.Includes("docker0") || options.Includes("eth0") || options.Includes("eth1") {
		t.Fatal("explicit selection ignored")
	}
}

func TestManagedNetworkLayersDoNotInflateHostTraffic(t *testing.T) {
	previous := rawResources{
		at: time.Unix(100, 0),
		networks: []gnet.IOCountersStat{
			{Name: "eth0", BytesSent: 1000, BytesRecv: 2000},
			{Name: "bwg2", BytesSent: 10000, BytesRecv: 20000},
			{Name: "ifb-bosun", BytesSent: 30000, BytesRecv: 40000},
			{Name: "ifb-bosun-up", BytesSent: 50000, BytesRecv: 60000},
		},
		networkIDs: map[string]string{"eth0": "boot:1", "bwg2": "boot:2", "ifb-bosun": "boot:3", "ifb-bosun-up": "boot:4"},
	}
	current := rawResources{
		at: time.Unix(110, 0),
		networks: []gnet.IOCountersStat{
			{Name: "eth0", BytesSent: 1200, BytesRecv: 2400},
			{Name: "bwg2", BytesSent: 11000, BytesRecv: 22000},
			{Name: "ifb-bosun", BytesSent: 33000, BytesRecv: 44000},
			{Name: "ifb-bosun-up", BytesSent: 55000, BytesRecv: 66000},
		},
		networkIDs: previous.networkIDs,
	}
	for _, tc := range []struct {
		name      string
		options   spec.ResourceOptions
		included  string
		up, down  uint64
		totalUp   uint64
		totalDown uint64
	}{
		{name: "default", included: "eth0", up: 20, down: 40, totalUp: 1200, totalDown: 2400},
		{name: "explicit tunnel", options: spec.ResourceOptions{IncludeInterfaces: []string{"bwg2"}}, included: "bwg2", up: 100, down: 200, totalUp: 11000, totalDown: 22000},
		{name: "explicit exclusion", options: spec.ResourceOptions{IncludeInterfaces: []string{"eth0", "bwg2"}, ExcludeInterfaces: []string{"bwg2"}}, included: "eth0", up: 20, down: 40, totalUp: 1200, totalDown: 2400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _, up, down, totalUp, totalDown, _, valid := reduceResources(current, previous, tc.options)
			if !valid || up != tc.up || down != tc.down || totalUp != tc.totalUp || totalDown != tc.totalDown {
				t.Fatalf("host traffic valid=%v rates=%d/%d totals=%d/%d", valid, up, down, totalUp, totalDown)
			}
			if len(r.Networks) != 4 {
				t.Fatalf("lost interface details: %+v", r.Networks)
			}
			for _, n := range r.Networks {
				if n.Included != (n.Name == tc.included) || n.UpRate == nil || n.DownRate == nil || *n.UpRate <= 0 || *n.DownRate <= 0 {
					t.Fatalf("interface details must retain measured traffic: %+v", n)
				}
			}
		})
	}
	// A newly created tunnel has no rate yet, but must not invalidate the
	// physical interface's established host-rate baseline.
	previous.networks = previous.networks[:1]
	_, _, up, down, _, _, _, valid := reduceResources(current, previous, spec.ResourceOptions{})
	if !valid || up != 20 || down != 40 {
		t.Fatalf("new managed interfaces invalidated host traffic: valid=%v rates=%d/%d", valid, up, down)
	}
}

func TestSamplerSharesCachedSnapshot(t *testing.T) {
	p := Sampler{Dial: func(context.Context, string, string) error { return nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first := p.Sample(ctx)
	second := p.Sample(ctx)
	if first.Resources == nil || first.Resources.Epoch == "" || first.Resources.Sequence != second.Resources.Sequence {
		t.Fatal("exporters did not share the sample")
	}
	if first.Valid == nil || first.Valid.CPU {
		t.Fatal("initial CPU is not yet measurable")
	}
	for _, proc := range first.Resources.Processes {
		if proc.Name == "bosun" && proc.RSS != nil && *proc.RSS > 0 {
			return
		}
	}
	t.Fatal("sampler did not report its own memory")
}

// Also run as a standalone Linux test binary on the test hosts. This checks
// platform collectors with real counters; network dialing is intentionally off.
func TestSamplerLiveResources(t *testing.T) {
	p := Sampler{Dial: func(context.Context, string, string) error { return nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	started := time.Now()
	first := p.Sample(ctx)
	collection := time.Since(started)
	time.Sleep(1100 * time.Millisecond)
	second := p.Sample(ctx)
	if second.Resources.Sequence <= first.Resources.Sequence || !second.Valid.CPU || !second.Valid.Memory {
		t.Fatalf("live sample has no CPU/memory validity: %+v", second.Valid)
	}
	if len(second.Resources.CPUs) == 0 || len(second.Resources.Filesystems) == 0 || len(second.Resources.Processes) == 0 {
		t.Fatal("live resource detail empty")
	}
	t.Logf("collection=%s logical_cpus=%d interfaces=%d filesystems=%d disks=%d managed_processes=%d network_rate_valid=%t", collection.Round(time.Microsecond), len(second.Resources.CPUs), len(second.Resources.Networks), len(second.Resources.Filesystems), len(second.Resources.Disks), len(second.Resources.Processes), second.Valid.Network)
}

func TestSamplerTracksSupervisedProcess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	child := subprocess.New("resource-test", "/bin/sleep", []string{"10"}, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := child.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer child.Stop(context.Background())
	p := Sampler{Dial: func(context.Context, string, string) error { return nil }}
	sample := p.Sample(ctx)
	found := false
	for _, proc := range sample.Resources.Processes {
		if proc.Name == "resource-test" {
			found = true
			if proc.RSS == nil || *proc.RSS == 0 {
				t.Fatal("managed child memory unavailable")
			}
		}
	}
	if !found {
		t.Fatal("managed child missing from resource snapshot")
	}
	if err := child.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range subprocess.ActiveProcesses() {
		if name == "resource-test" {
			t.Fatal("stopped child stayed in registry")
		}
	}
}
