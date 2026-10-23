package sysinfo

import (
	"context"
	"fmt"
	"math"
	"net"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
	"github.com/zeptop-dev/bosun/internal/core/subprocess"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

type processSample struct {
	name    string
	started int64
	seconds *float64
	rss     *uint64
}

type rawResources struct {
	at          time.Time
	cpus        []cpu.TimesStat
	networks    []gnet.IOCountersStat
	networkIDs  map[string]string
	disks       map[string]disk.IOCountersStat
	filesystems []spec.FilesystemResource
	processes   map[int32]processSample
}

func collectResources(ctx context.Context, boot uint64) rawResources {
	r := rawResources{at: time.Now(), networkIDs: map[string]string{}}
	r.cpus, _ = cpu.TimesWithContext(ctx, true)
	r.networks, _ = gnet.IOCountersWithContext(ctx, true)
	// Interface index changes when a device is recreated. The boot component
	// prevents counting a reboot as traffic even if its new counters are larger.
	if interfaces, err := net.Interfaces(); err == nil && boot > 0 {
		for _, nic := range interfaces {
			r.networkIDs[nic.Name] = fmt.Sprintf("%d:%d", boot, nic.Index)
		}
	}
	r.disks, _ = disk.IOCountersWithContext(ctx)
	pids := subprocess.ActiveProcesses()
	pids[int32(os.Getpid())] = "bosun"
	r.processes = make(map[int32]processSample, len(pids))
	for pid, name := range pids {
		item := processSample{name: name}
		if proc, err := process.NewProcessWithContext(ctx, pid); err == nil {
			item.started, _ = proc.CreateTimeWithContext(ctx)
			if times, err := proc.TimesWithContext(ctx); err == nil {
				seconds := times.User + times.System
				item.seconds = &seconds
			}
			if mem, err := proc.MemoryInfoWithContext(ctx); err == nil {
				item.rss = &mem.RSS
			}
		}
		r.processes[pid] = item
	}
	return r
}

func rate(current, previous uint64, secs float64) *float64 {
	if secs <= 0 || current < previous {
		return nil
	}
	v := float64(current-previous) / secs
	return &v
}

func cpuDelta(current, previous cpu.TimesStat) (busy, total float64, ok bool) {
	// Guest time is already included in user/nice on Linux; do not count twice.
	a := []float64{current.User, current.System, current.Nice, current.Idle, current.Iowait, current.Irq, current.Softirq, current.Steal}
	b := []float64{previous.User, previous.System, previous.Nice, previous.Idle, previous.Iowait, previous.Irq, previous.Softirq, previous.Steal}
	for i := range a {
		if a[i] < b[i] {
			return 0, 0, false
		}
		d := a[i] - b[i]
		total += d
		if i != 3 && i != 4 {
			busy += d
		}
	}
	return busy, total, total > 0
}

func reduceResources(r, prev rawResources, options spec.ResourceOptions) (*spec.Resources, float64, uint64, uint64, uint64, uint64, bool, bool) {
	out := &spec.Resources{At: r.at.UnixMilli(), Filesystems: r.filesystems}
	secs := r.at.Sub(prev.at).Seconds()
	var cpuPct, busySum, totalSum float64
	var upRate, downRate, up, down uint64
	cpuValid, networkValid := len(r.cpus) > 0, r.networks != nil
	oldCPUs := map[string]cpu.TimesStat{}
	for _, c := range prev.cpus {
		oldCPUs[c.CPU] = c
	}
	if r.cpus != nil {
		out.CPUs = []spec.CPUResource{}
	}
	for _, c := range r.cpus {
		v := spec.CPUResource{Name: c.CPU}
		if old, ok := oldCPUs[c.CPU]; ok && secs > 0 {
			if busy, total, ok := cpuDelta(c, old); ok {
				pct := 100 * busy / total
				v.Percent = &pct
				busySum += busy
				totalSum += total
			}
		}
		if v.Percent == nil {
			cpuValid = false
		}
		out.CPUs = append(out.CPUs, v)
	}
	if cpuValid && totalSum > 0 {
		cpuPct = 100 * busySum / totalSum
	}
	oldNets := map[string]gnet.IOCountersStat{}
	for _, n := range prev.networks {
		oldNets[n.Name] = n
	}
	if r.networks != nil {
		out.Networks = []spec.NetworkResource{}
	}
	included := 0
	for _, n := range r.networks {
		v := spec.NetworkResource{Name: n.Name, ID: r.networkIDs[n.Name], Included: options.Includes(n.Name), Up: n.BytesSent, Down: n.BytesRecv}
		if old, ok := oldNets[n.Name]; ok && v.ID != "" && v.ID == prev.networkIDs[n.Name] {
			v.UpRate, v.DownRate = rate(v.Up, old.BytesSent, secs), rate(v.Down, old.BytesRecv, secs)
		}
		if v.Included {
			included++
			up += v.Up
			down += v.Down
			if v.UpRate == nil || v.DownRate == nil {
				networkValid = false
			} else {
				upRate += uint64(*v.UpRate)
				downRate += uint64(*v.DownRate)
			}
		}
		out.Networks = append(out.Networks, v)
	}
	if included == 0 {
		networkValid = false
	}
	if !networkValid {
		upRate, downRate = 0, 0
	}
	sort.Slice(out.Networks, func(i, j int) bool { return out.Networks[i].Name < out.Networks[j].Name })
	if r.disks != nil {
		out.Disks = []spec.DiskResource{}
	}
	for name, d := range r.disks {
		v := spec.DiskResource{Name: name}
		if old, ok := prev.disks[name]; ok && d.SerialNumber == old.SerialNumber {
			v.ReadRate, v.WriteRate = rate(d.ReadBytes, old.ReadBytes, secs), rate(d.WriteBytes, old.WriteBytes, secs)
			v.ReadIOPS, v.WriteIOPS = rate(d.ReadCount, old.ReadCount, secs), rate(d.WriteCount, old.WriteCount, secs)
		}
		out.Disks = append(out.Disks, v)
	}
	sort.Slice(out.Disks, func(i, j int) bool { return out.Disks[i].Name < out.Disks[j].Name })
	if r.processes != nil {
		out.Processes = []spec.ProcessResource{}
	}
	for pid, p := range r.processes {
		v := spec.ProcessResource{Name: p.name, PID: pid, RSS: p.rss}
		if old, ok := prev.processes[pid]; ok && p.started > 0 && old.started == p.started && old.name == p.name && old.seconds != nil && p.seconds != nil && secs > 0 && *p.seconds >= *old.seconds {
			pct := 100 * (*p.seconds - *old.seconds) / secs
			if !math.IsNaN(pct) && !math.IsInf(pct, 0) {
				v.CPU = &pct
			}
		}
		out.Processes = append(out.Processes, v)
	}
	sort.Slice(out.Processes, func(i, j int) bool {
		a, b := out.Processes[i], out.Processes[j]
		return a.Name+strconv.Itoa(int(a.PID)) < b.Name+strconv.Itoa(int(b.PID))
	})
	return out, cpuPct, upRate, downRate, up, down, cpuValid, networkValid
}
