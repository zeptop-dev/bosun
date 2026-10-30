package captain

import (
	"context"
	"encoding/json"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

const diagnosticMaxSampleGap = 3 * time.Second

// diagnosticSnapshot deliberately excludes disks, processes, subprocesses,
// active probes and the regular resource/traffic collectors.
type diagnosticSnapshot struct {
	cpus       []cpu.TimesStat
	memory     *mem.VirtualMemoryStat
	networks   []gnet.IOCountersStat
	cpuErr     error
	memoryErr  error
	networkErr error
}

func collectDiagnosticSnapshot(ctx context.Context) diagnosticSnapshot {
	var v diagnosticSnapshot
	v.cpus, v.cpuErr = cpu.TimesWithContext(ctx, false)
	v.memory, v.memoryErr = mem.VirtualMemoryWithContext(ctx)
	v.networks, v.networkErr = gnet.IOCountersWithContext(ctx, true)
	return v
}

type diagnosticNetworkCounter struct {
	rx, tx uint64
	valid  bool
}

type diagnosticBaseline struct {
	at         time.Time
	cpu        *cpu.TimesStat
	networks   map[string]diagnosticNetworkCounter
	networksOK bool
}

// diagnosticSampler is usable as a zero value. Rates use time.Time's monotonic
// component; wall time is only the observation label. Sample and Reset are
// serialized so cancellation or a new lease cannot retain the old baseline.
type diagnosticSampler struct {
	mu       sync.Mutex
	collect  func(context.Context) diagnosticSnapshot
	now      func() time.Time
	previous diagnosticBaseline
}

func (s *diagnosticSampler) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.previous = diagnosticBaseline{}
}

func (s *diagnosticSampler) Sample(ctx context.Context) agentproto.DiagnosticsSample {
	s.mu.Lock()
	defer s.mu.Unlock()
	collect, now := s.collect, s.now
	if collect == nil {
		collect = collectDiagnosticSnapshot
	}
	if now == nil {
		now = time.Now
	}
	var raw diagnosticSnapshot
	if ctx.Err() == nil {
		raw = collect(ctx)
	}
	at := now()
	out := agentproto.DiagnosticsSample{SampledAt: at, Interfaces: []agentproto.DiagnosticsInterface{}}
	if ctx.Err() != nil {
		s.previous = diagnosticBaseline{}
		return out
	}
	previous := s.previous
	next := diagnosticBaseline{at: at}
	elapsed := at.Sub(previous.at)
	// Do not attach a rate to an interval rounded to zero on the wire.
	intervalOK := !previous.at.IsZero() && elapsed >= time.Millisecond && elapsed <= diagnosticMaxSampleGap
	if !previous.at.IsZero() && elapsed > 0 {
		out.ElapsedMS = elapsed.Milliseconds()
	}
	if raw.cpuErr == nil && len(raw.cpus) == 1 && diagnosticCPUValid(raw.cpus[0]) {
		current := raw.cpus[0]
		next.cpu = &current
		if intervalOK && previous.cpu != nil && current.CPU == previous.cpu.CPU {
			out.CPUPercent = diagnosticCPUPercent(current, *previous.cpu)
		}
	}
	if raw.memoryErr == nil && raw.memory != nil && raw.memory.Total > 0 && raw.memory.Used <= raw.memory.Total {
		used, total := raw.memory.Used, raw.memory.Total
		out.MemoryUsed, out.MemoryTotal = &used, &total
	}
	if raw.networkErr == nil {
		next.networks = make(map[string]diagnosticNetworkCounter, len(raw.networks))
		next.networksOK = true
		for _, nic := range raw.networks {
			if !diagnosticInterfaceName(nic.Name) {
				out.Truncated, next.networksOK = true, false
				continue
			}
			if _, exists := next.networks[nic.Name]; exists {
				// An ambiguous counter cannot establish a baseline.
				next.networks[nic.Name] = diagnosticNetworkCounter{}
				next.networksOK = false
				continue
			}
			next.networks[nic.Name] = diagnosticNetworkCounter{rx: nic.BytesRecv, tx: nic.BytesSent, valid: true}
		}
		names := make([]string, 0, len(next.networks))
		for name := range next.networks {
			names = append(names, name)
		}
		sort.Strings(names)
		if len(names) > agentproto.DiagnosticsMaxInterfaces {
			names = names[:agentproto.DiagnosticsMaxInterfaces]
			out.Truncated = true
		}
		for _, name := range names {
			nic := agentproto.DiagnosticsInterface{Name: name}
			if intervalOK {
				nic.RXBytesPerSecond, nic.TXBytesPerSecond = diagnosticNetworkRates(next.networks[name], previous.networks[name], elapsed)
			}
			out.Interfaces = append(out.Interfaces, nic)
		}
		if intervalOK && next.networksOK && previous.networksOK {
			out.NetDownBytesPerSecond, out.NetUpBytesPerSecond = diagnosticNetworkTotals(next.networks, previous.networks, elapsed)
		}
	}
	s.previous = next
	return out
}

func diagnosticCPUFields(v cpu.TimesStat) [8]float64 {
	// Linux guest/guest_nice are already included in user/nice.
	return [8]float64{v.User, v.System, v.Nice, v.Idle, v.Iowait, v.Irq, v.Softirq, v.Steal}
}

func diagnosticCPUValid(v cpu.TimesStat) bool {
	for _, n := range diagnosticCPUFields(v) {
		if !diagnosticFinite(n) || n < 0 {
			return false
		}
	}
	return true
}

func diagnosticCPUPercent(current, previous cpu.TimesStat) *float64 {
	a, b := diagnosticCPUFields(current), diagnosticCPUFields(previous)
	var busy, total float64
	for i := range a {
		if a[i] < b[i] {
			return nil
		}
		delta := a[i] - b[i]
		total += delta
		if i != 3 && i != 4 { // idle and iowait are not busy CPU time
			busy += delta
		}
	}
	if total <= 0 || !diagnosticFinite(total) || !diagnosticFinite(busy) {
		return nil
	}
	pct := busy / total * 100
	if !diagnosticFinite(pct) || pct < 0 || pct > 100 {
		return nil
	}
	return &pct
}

func diagnosticInterfaceName(name string) bool {
	if name == "" || len(name) > 64 || !utf8.ValidString(name) || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return false
	}
	// Bound encoded bytes too: HTML-sensitive names expand under encoding/json.
	// This leaves ample room for 16 NICs, numbers and driver identity metadata.
	encoded, _ := json.Marshal(name)
	return len(encoded) <= 128
}

func diagnosticNetworkRates(current, previous diagnosticNetworkCounter, elapsed time.Duration) (*float64, *float64) {
	if !current.valid || !previous.valid || current.rx < previous.rx || current.tx < previous.tx || elapsed <= 0 {
		return nil, nil
	}
	rx := float64(current.rx-previous.rx) / elapsed.Seconds()
	tx := float64(current.tx-previous.tx) / elapsed.Seconds()
	if !diagnosticFinite(rx) || !diagnosticFinite(tx) {
		return nil, nil
	}
	return &rx, &tx
}

// Totals include every observed non-loopback interface, including NICs omitted
// by the display limit. Conventional loopback names lo/lo0/lo1... are excluded.
// Virtual interfaces can observe the same packet more than once: these are
// host diagnosis rates, never billable traffic or a physical-uplink estimate.
func diagnosticNetworkTotals(current, previous map[string]diagnosticNetworkCounter, elapsed time.Duration) (*float64, *float64) {
	var rx, tx float64
	count := 0
	names := make([]string, 0, len(current))
	for name := range current {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if diagnosticLoopback(name) {
			continue
		}
		r, t := diagnosticNetworkRates(current[name], previous[name], elapsed)
		if r == nil || t == nil {
			return nil, nil
		}
		rx, tx, count = rx+*r, tx+*t, count+1
	}
	for name := range previous {
		if !diagnosticLoopback(name) {
			if _, exists := current[name]; !exists {
				return nil, nil
			}
		}
	}
	if count == 0 || !diagnosticFinite(rx) || !diagnosticFinite(tx) {
		return nil, nil
	}
	return &rx, &tx
}

func diagnosticLoopback(name string) bool {
	if !strings.HasPrefix(name, "lo") {
		return false
	}
	for _, c := range strings.TrimPrefix(name, "lo") {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func diagnosticFinite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
