package captain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

type diagnosticFixture struct {
	at    time.Time
	raw   diagnosticSnapshot
	calls int
}

func diagnosticTestSampler() (*diagnosticSampler, *diagnosticFixture) {
	f := &diagnosticFixture{
		at: time.Now(), // Add preserves the monotonic component used by Sample.
		raw: diagnosticSnapshot{
			cpus:     []cpu.TimesStat{{CPU: "cpu-total", User: 100, Idle: 900}},
			memory:   &mem.VirtualMemoryStat{Total: 1024, Used: 512},
			networks: []gnet.IOCountersStat{{Name: "eth0", BytesRecv: 100, BytesSent: 200}},
		},
	}
	s := &diagnosticSampler{collect: func(context.Context) diagnosticSnapshot { f.calls++; return f.raw }, now: func() time.Time { return f.at }}
	return s, f
}

func diagnosticWantRate(t *testing.T, value *float64, want float64) {
	t.Helper()
	if value == nil || math.Abs(*value-want) > math.Max(1, math.Abs(want))*1e-12 {
		t.Fatalf("rate %v, want %v", value, want)
	}
}

func diagnosticWantMissingRates(t *testing.T, value agentproto.DiagnosticsSample) {
	t.Helper()
	if value.CPUPercent != nil || value.NetUpBytesPerSecond != nil || value.NetDownBytesPerSecond != nil {
		t.Fatalf("expected missing rates: %+v", value)
	}
	for _, nic := range value.Interfaces {
		if nic.RXBytesPerSecond != nil || nic.TXBytesPerSecond != nil {
			t.Fatalf("expected missing NIC rates: %+v", nic)
		}
	}
}

func TestDiagnosticSamplerDeltasAndMeasuredZero(t *testing.T) {
	s, f := diagnosticTestSampler()
	f.raw.cpus[0].Guest, f.raw.cpus[0].GuestNice = 200, 300
	f.raw.networks = append(f.raw.networks, gnet.IOCountersStat{Name: "lo", BytesRecv: 1, BytesSent: 1})
	first := s.Sample(context.Background())
	diagnosticWantMissingRates(t, first)
	if first.ElapsedMS != 0 || !first.SampledAt.Equal(f.at) || first.Interfaces == nil {
		t.Fatalf("bad first observation: %+v", first)
	}
	f.at = f.at.Add(1500 * time.Millisecond)
	f.raw.cpus[0] = cpu.TimesStat{CPU: "cpu-total", User: 102, System: 1, Idle: 907, Iowait: 2, Guest: 9999, GuestNice: 9999}
	f.raw.networks[0].BytesRecv, f.raw.networks[0].BytesSent = 250, 500
	f.raw.networks[1].BytesRecv, f.raw.networks[1].BytesSent = 900000, 900000
	f.raw.memory = &mem.VirtualMemoryStat{Total: 1024, Used: 0}
	got := s.Sample(context.Background())
	diagnosticWantRate(t, got.CPUPercent, 25) // 3 busy / (3 busy + 7 idle + 2 iowait)
	diagnosticWantRate(t, got.NetDownBytesPerSecond, 100)
	diagnosticWantRate(t, got.NetUpBytesPerSecond, 200)
	diagnosticWantRate(t, got.Interfaces[0].RXBytesPerSecond, 100)
	if got.ElapsedMS != 1500 || got.MemoryUsed == nil || *got.MemoryUsed != 0 || got.MemoryTotal == nil || *got.MemoryTotal != 1024 {
		t.Fatalf("missing measured memory/interval: %+v", got)
	}
	f.at = f.at.Add(time.Second)
	f.raw.cpus[0].Idle++
	zero := s.Sample(context.Background())
	diagnosticWantRate(t, zero.CPUPercent, 0)
	diagnosticWantRate(t, zero.NetUpBytesPerSecond, 0)
	diagnosticWantRate(t, zero.NetDownBytesPerSecond, 0)
	raw, err := json.Marshal(zero)
	if err != nil || !strings.Contains(string(raw), `"cpu_percent":0`) || !strings.Contains(string(raw), `"net_up_bytes_per_second":0`) {
		t.Fatalf("measured zero lost: %s, %v", raw, err)
	}
}

func TestDiagnosticSamplerResetAndGap(t *testing.T) {
	for _, tc := range []struct {
		name  string
		gap   time.Duration
		reset bool
	}{{"reset", time.Second, true}, {"long-gap", 4 * time.Second, false}, {"same-time", 0, false}, {"sub-millisecond", time.Microsecond, false}, {"backward-clock", -time.Second, false}} {
		t.Run(tc.name, func(t *testing.T) {
			s, f := diagnosticTestSampler()
			s.Sample(context.Background())
			if tc.reset {
				s.Reset()
			}
			f.at = f.at.Add(tc.gap)
			f.raw.cpus[0].User++
			f.raw.networks[0].BytesRecv++
			got := s.Sample(context.Background())
			diagnosticWantMissingRates(t, got)
			if tc.name == "long-gap" && got.ElapsedMS != 4000 {
				t.Fatalf("gap was relabeled: %d", got.ElapsedMS)
			}
			f.at = f.at.Add(time.Second)
			f.raw.cpus[0].Idle++
			f.raw.networks[0].BytesRecv += 20
			got = s.Sample(context.Background())
			diagnosticWantRate(t, got.CPUPercent, 0)
			diagnosticWantRate(t, got.NetDownBytesPerSecond, 20)
		})
	}
}

func TestDiagnosticSamplerCollectionFailuresAreIndependent(t *testing.T) {
	for _, resource := range []string{"cpu", "memory", "network"} {
		t.Run(resource, func(t *testing.T) {
			s, f := diagnosticTestSampler()
			s.Sample(context.Background())
			f.at = f.at.Add(time.Second)
			f.raw.cpus[0].User++
			f.raw.networks[0].BytesRecv += 10
			err := errors.New("unavailable")
			switch resource {
			case "cpu":
				f.raw.cpuErr = err
			case "memory":
				f.raw.memoryErr = err
			case "network":
				f.raw.networkErr = err
			}
			got := s.Sample(context.Background())
			if resource == "cpu" {
				if got.CPUPercent != nil {
					t.Fatal("failed CPU collection retained rate")
				}
			} else {
				diagnosticWantRate(t, got.CPUPercent, 100)
			}
			if resource == "memory" {
				if got.MemoryUsed != nil || got.MemoryTotal != nil {
					t.Fatal("failed memory collection reused values")
				}
			} else if got.MemoryUsed == nil || got.MemoryTotal == nil {
				t.Fatal("unrelated failure hid memory")
			}
			if resource == "network" {
				if got.NetDownBytesPerSecond != nil || len(got.Interfaces) != 0 {
					t.Fatal("failed network collection retained rates")
				}
			} else {
				diagnosticWantRate(t, got.NetDownBytesPerSecond, 10)
			}
			f.raw.cpuErr, f.raw.memoryErr, f.raw.networkErr = nil, nil, nil
			f.at = f.at.Add(time.Second)
			f.raw.cpus[0].User++
			f.raw.networks[0].BytesRecv += 10
			got = s.Sample(context.Background())
			if resource == "cpu" && got.CPUPercent != nil || resource == "network" && got.NetDownBytesPerSecond != nil {
				t.Fatal("rates bridged a failed collection")
			}
			f.at = f.at.Add(time.Second)
			f.raw.cpus[0].User++
			f.raw.networks[0].BytesRecv += 10
			got = s.Sample(context.Background())
			diagnosticWantRate(t, got.CPUPercent, 100)
			diagnosticWantRate(t, got.NetDownBytesPerSecond, 10)
		})
	}
}

func TestDiagnosticSamplerRejectsInvalidCPUAndMemory(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value cpu.TimesStat
	}{
		{"nan", cpu.TimesStat{User: math.NaN()}},
		{"infinity", cpu.TimesStat{Idle: math.Inf(1)}},
		{"negative", cpu.TimesStat{User: -1}},
		{"sum-overflow", cpu.TimesStat{User: math.MaxFloat64, Idle: math.MaxFloat64}},
		{"counter-reset", cpu.TimesStat{User: 1, Idle: 1000}},
		{"no-delta", cpu.TimesStat{User: 100, Idle: 900}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, f := diagnosticTestSampler()
			s.Sample(context.Background())
			f.at = f.at.Add(time.Second)
			tc.value.CPU = "cpu-total"
			f.raw.cpus = []cpu.TimesStat{tc.value}
			got := s.Sample(context.Background())
			if got.CPUPercent != nil {
				t.Fatalf("invalid CPU became a rate: %+v", got)
			}
			if _, err := json.Marshal(got); err != nil {
				t.Fatal("sample cannot be encoded", err)
			}
		})
	}
	for _, value := range []*mem.VirtualMemoryStat{nil, {}, {Total: 1, Used: 2}} {
		s, f := diagnosticTestSampler()
		f.raw.memory = value
		got := s.Sample(context.Background())
		if got.MemoryUsed != nil || got.MemoryTotal != nil {
			t.Fatalf("invalid memory retained: %+v", got)
		}
	}
}

func TestDiagnosticSamplerNetworkInventoryAndReset(t *testing.T) {
	for _, event := range []string{"add", "remove", "reset-rx", "reset-tx", "duplicate"} {
		t.Run(event, func(t *testing.T) {
			s, f := diagnosticTestSampler()
			f.raw.networks = append(f.raw.networks, gnet.IOCountersStat{Name: "eth1", BytesRecv: 100, BytesSent: 100})
			s.Sample(context.Background())
			f.at = f.at.Add(time.Second)
			f.raw.networks[0].BytesRecv += 10
			f.raw.networks[1].BytesRecv += 20
			switch event {
			case "add":
				f.raw.networks = append(f.raw.networks, gnet.IOCountersStat{Name: "eth2", BytesRecv: 100})
			case "remove":
				f.raw.networks = f.raw.networks[:1]
			case "reset-rx":
				f.raw.networks[1].BytesRecv = 1
			case "reset-tx":
				f.raw.networks[1].BytesSent = 1
			case "duplicate":
				f.raw.networks = append(f.raw.networks, f.raw.networks[1])
			}
			got := s.Sample(context.Background())
			if got.NetDownBytesPerSecond != nil || got.NetUpBytesPerSecond != nil {
				t.Fatal("partial inventory became aggregate")
			}
			diagnosticWantRate(t, got.Interfaces[0].RXBytesPerSecond, 10)
			if event == "reset-rx" || event == "reset-tx" || event == "duplicate" {
				if got.Interfaces[1].RXBytesPerSecond != nil || got.Interfaces[1].TXBytesPerSecond != nil {
					t.Fatal("reset/ambiguous NIC kept a rate")
				}
			}
		})
	}
}

func TestDiagnosticSamplerBoundedInterfacesAndCompleteTotals(t *testing.T) {
	s, f := diagnosticTestSampler()
	f.raw.networks = nil
	for i := 19; i >= 0; i-- {
		f.raw.networks = append(f.raw.networks, gnet.IOCountersStat{Name: fmt.Sprintf("eth%02d", i), BytesRecv: 100})
	}
	s.Sample(context.Background())
	f.at = f.at.Add(time.Second)
	for i := range f.raw.networks {
		f.raw.networks[i].BytesRecv += 10
	}
	got := s.Sample(context.Background())
	if !got.Truncated || len(got.Interfaces) != agentproto.DiagnosticsMaxInterfaces || got.Interfaces[0].Name != "eth00" || got.Interfaces[15].Name != "eth15" {
		t.Fatalf("unstable interface truncation: %+v", got)
	}
	diagnosticWantRate(t, got.NetDownBytesPerSecond, 200) // All 20 NICs, not just 16 displayed.
	f.at = f.at.Add(time.Second)
	f.raw.networks[0].BytesRecv = 1 // eth19 is outside the displayed slice.
	got = s.Sample(context.Background())
	if got.NetDownBytesPerSecond != nil || got.NetUpBytesPerSecond != nil {
		t.Fatal("hidden NIC reset did not invalidate aggregate")
	}

	// Bound encoded names as well as their byte count, including HTML escaping.
	s.Reset()
	f.raw.networks = nil
	for i := 0; i < 16; i++ {
		f.raw.networks = append(f.raw.networks, gnet.IOCountersStat{Name: fmt.Sprintf("%02d%s", i, strings.Repeat("<", 20))})
	}
	f.raw.networks = append(f.raw.networks,
		gnet.IOCountersStat{Name: ""}, gnet.IOCountersStat{Name: "bad\nname"},
		gnet.IOCountersStat{Name: strings.Repeat("x", 65)}, gnet.IOCountersStat{Name: string([]byte{0xff})},
		gnet.IOCountersStat{Name: strings.Repeat("<", 64)},
	)
	s.Sample(context.Background())
	f.at = f.at.Add(time.Millisecond)
	for i := range f.raw.networks {
		f.raw.networks[i].BytesRecv, f.raw.networks[i].BytesSent = math.MaxUint64, math.MaxUint64
	}
	got = s.Sample(context.Background())
	got.Session, got.Epoch, got.Sequence = strings.Repeat("s", 128), strings.Repeat("e", 128), math.MaxUint64
	raw, err := json.Marshal(got)
	if err != nil || len(raw) > agentproto.DiagnosticsMaxSampleBytes || !got.Truncated || len(got.Interfaces) != 16 {
		t.Fatalf("unbounded response: bytes=%d interfaces=%d truncated=%v err=%v", len(raw), len(got.Interfaces), got.Truncated, err)
	}
	if got.NetDownBytesPerSecond != nil {
		t.Fatal("omitted invalid names became a complete aggregate")
	}
}

func TestDiagnosticSamplerCancellationClearsBaseline(t *testing.T) {
	s, f := diagnosticTestSampler()
	s.Sample(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := s.Sample(ctx)
	diagnosticWantMissingRates(t, got)
	if f.calls != 1 || got.MemoryUsed != nil {
		t.Fatal("canceled sample collected or retained memory")
	}
	f.at = f.at.Add(time.Second)
	f.raw.cpus[0].User++
	f.raw.networks[0].BytesRecv++
	diagnosticWantMissingRates(t, s.Sample(context.Background()))
	// Cancellation during collection must not retain the just-read baseline.
	ctx, cancel = context.WithCancel(context.Background())
	s.collect = func(context.Context) diagnosticSnapshot { cancel(); return f.raw }
	diagnosticWantMissingRates(t, s.Sample(ctx))
	if !s.previous.at.IsZero() {
		t.Fatal("canceled collection established a baseline")
	}
}

func TestDiagnosticSamplerTotalsAvoidIntegerOverflowAndLoopback(t *testing.T) {
	s, f := diagnosticTestSampler()
	f.raw.networks = []gnet.IOCountersStat{{Name: "eth0"}, {Name: "eth1"}, {Name: "lo0"}}
	s.Sample(context.Background())
	f.at = f.at.Add(time.Second)
	for i := range f.raw.networks {
		f.raw.networks[i].BytesRecv, f.raw.networks[i].BytesSent = math.MaxUint64, math.MaxUint64
	}
	got := s.Sample(context.Background())
	diagnosticWantRate(t, got.NetDownBytesPerSecond, 2*float64(math.MaxUint64))
	diagnosticWantRate(t, got.NetUpBytesPerSecond, 2*float64(math.MaxUint64))
	// Loopback disappearance does not invalidate a non-loopback aggregate.
	f.at = f.at.Add(time.Second)
	f.raw.networks = f.raw.networks[:2]
	got = s.Sample(context.Background())
	diagnosticWantRate(t, got.NetDownBytesPerSecond, 0)
	diagnosticWantRate(t, got.NetUpBytesPerSecond, 0)
}

func TestDiagnosticSamplerConcurrentReset(t *testing.T) {
	s := &diagnosticSampler{collect: func(context.Context) diagnosticSnapshot {
		return diagnosticSnapshot{cpus: []cpu.TimesStat{{CPU: "cpu-total", User: 1}}, networks: []gnet.IOCountersStat{{Name: "eth0"}}}
	}}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				s.Sample(context.Background())
				s.Reset()
			}
		}()
	}
	wg.Wait()
	diagnosticWantMissingRates(t, s.Sample(context.Background()))
}
