// Package sysinfo samples host resource usage for status reports and probe
// beats.
package sysinfo

import (
	"bufio"
	"context"
	"crypto/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Snapshot uses a persistent sampler so repeated calls have a CPU/rate baseline.
var snapshots Sampler

func Snapshot(ctx context.Context) spec.SystemStatus { return snapshots.Sample(ctx) }

// Sampler owns its baselines: other exporters cannot perturb CPU percentages.
// Calls are serialized and a one-second cache bounds collection work when the
// panel, reports and external monitoring all ask for the same host sample.
type Sampler struct {
	gpu         gpuSampler
	filesystems filesystemSampler
	epoch       string
	sequence    uint64
	mu          sync.Mutex
	sampleMu    sync.Mutex
	options     spec.ResourceOptions
	cached      spec.SystemStatus
	sampled     time.Time
	previous    rawResources
	info        *spec.HostInfo
	infoRetryAt time.Time
	ipCheckAt   time.Time
	ipv4, ipv6  bool
	Dial        func(ctx context.Context, network, addr string) error
}

func (p *Sampler) Configure(options *spec.ResourceOptions) {
	var next spec.ResourceOptions
	if options != nil && options.Validate() == nil {
		next.GPU = options.GPU
		next.IncludeInterfaces = append([]string(nil), options.IncludeInterfaces...)
		next.ExcludeInterfaces = append([]string(nil), options.ExcludeInterfaces...)
	}
	p.mu.Lock()
	p.options = next
	p.gpu.configure(next.GPU)
	p.mu.Unlock()
}

func (p *Sampler) Sample(ctx context.Context) spec.SystemStatus {
	p.sampleMu.Lock()
	defer p.sampleMu.Unlock()
	if !p.sampled.IsZero() && time.Since(p.sampled) < time.Second {
		s := p.cached
		if s.Resources != nil {
			r := *s.Resources
			r.GPU = p.gpu.snapshot()
			s.Resources = &r
		}
		return s
	}
	p.mu.Lock()
	options := p.options
	p.mu.Unlock()
	s := spec.SystemStatus{Valid: &spec.MetricValidity{}}
	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		s.MemTotal, s.MemUsed = vm.Total, vm.Used
		s.Valid.Memory = true
	}
	if sw, err := mem.SwapMemoryWithContext(ctx); err == nil {
		s.SwapTotal, s.SwapUsed = sw.Total, sw.Used
		s.Valid.Swap = true
	}
	if l, err := load.AvgWithContext(ctx); err == nil {
		s.Load1, s.Load5, s.Load15 = l.Load1, l.Load5, l.Load15
		s.Valid.Load = true
	}
	s.TCP, s.UDP, s.Valid.Connections = connCounts(ctx)
	if pids, err := process.PidsWithContext(ctx); err == nil {
		s.Processes = len(pids)
		s.Valid.Processes = true
	}
	if u, err := host.UptimeWithContext(ctx); err == nil {
		s.Uptime = u
		s.Valid.Uptime = true
	}
	s.Info = p.hostInfo(ctx)
	raw := collectResources(ctx, s.Info.BootTime)
	raw.filesystems = p.filesystems.snapshot(time.Now())
	// Async samples copied above must not appear newer than their enclosing
	// snapshot merely because the other resource collectors took longer.
	raw.at = time.Now()
	for _, fs := range raw.filesystems {
		if fs.Mount == "/" && fs.Total != nil && fs.Used != nil {
			s.DiskTotal, s.DiskUsed = *fs.Total, *fs.Used
			s.Valid.Disk = true
			break
		}
	}
	s.Resources, s.CPUPercent, s.NetUp, s.NetDown, s.NetTotalUp, s.NetTotalDown, s.Valid.CPU, s.Valid.Network = reduceResources(raw, p.previous, options)
	if p.epoch == "" {
		p.epoch = rand.Text()
	}
	p.sequence++
	s.Resources.Epoch, s.Resources.Sequence = p.epoch, p.sequence
	s.Resources.GPU = p.gpu.snapshot()
	p.previous = raw
	s.IPv4, s.IPv6 = p.reachability(ctx)
	p.cached, p.sampled = s, time.Now()
	return s
}

func (p *Sampler) hostInfo(ctx context.Context) *spec.HostInfo {
	return p.cachedHostInfo(ctx, time.Now(), collectHostInfo)
}

// Host facts are immutable once published in a snapshot. Failed optional
// topology collection is retried at most once per five minutes, and a refresh
// replaces the pointer instead of changing facts held by an earlier report.
func (p *Sampler) cachedHostInfo(ctx context.Context, now time.Time, collect func(context.Context) (*spec.HostInfo, bool)) *spec.HostInfo {
	const retryInterval = 5 * time.Minute
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.info != nil && (p.infoRetryAt.IsZero() || now.Before(p.infoRetryAt)) {
		return p.info
	}
	info, retry := collect(ctx)
	if info.BootTime > 0 && info.CPUCores > 0 {
		p.info = info
		p.infoRetryAt = time.Time{}
		if retry {
			p.infoRetryAt = now.Add(retryInterval)
		}
	} else {
		// A failed retry must not replace useful cached facts or turn the
		// optional detector into a command executed for every probe beat.
		// Cache even the first partial result so initial failures are bounded.
		if p.info == nil {
			p.info = info
		}
		p.infoRetryAt = now.Add(retryInterval)
		return p.info
	}
	return info
}

func collectHostInfo(ctx context.Context) (*spec.HostInfo, bool) {
	info := &spec.HostInfo{Arch: runtime.GOARCH}
	var virtualizationRole string
	if hi, err := host.InfoWithContext(ctx); err == nil {
		info.OS = strings.TrimSpace(hi.Platform + " " + hi.PlatformVersion)
		info.Kernel = hi.KernelVersion
		info.Virt = hi.VirtualizationSystem
		virtualizationRole = hi.VirtualizationRole
		info.BootTime = hi.BootTime
		if hi.KernelArch != "" {
			info.Arch = hi.KernelArch
		}
	}
	if cs, err := cpu.InfoWithContext(ctx); err == nil && len(cs) > 0 {
		info.CPUModel = strings.TrimSpace(cs[0].ModelName)
	}
	if n, err := cpu.CountsWithContext(ctx, true); err == nil {
		info.CPUCores = n
	}
	if runtime.GOOS == "linux" {
		collectCPUTopology(ctx, info, virtualizationRole)
	} else if virtualizationRole == "guest" {
		info.VirtualizationRole = "guest"
	}
	return info, runtime.GOOS == "linux" && cpuTopologyIncomplete(info)
}

// reachability dials well-known v4/v6 endpoints every ten minutes.
func (p *Sampler) reachability(ctx context.Context) (bool, bool) {
	p.mu.Lock()
	if time.Since(p.ipCheckAt) < 10*time.Minute {
		v4, v6 := p.ipv4, p.ipv6
		p.mu.Unlock()
		return v4, v6
	}
	p.mu.Unlock()
	dial := p.Dial
	if dial == nil {
		dial = func(ctx context.Context, network, addr string) error {
			d := net.Dialer{Timeout: 3 * time.Second}
			c, err := d.DialContext(ctx, network, addr)
			if err == nil {
				c.Close()
			}
			return err
		}
	}
	v4 := dial(ctx, "tcp4", "1.1.1.1:443") == nil || dial(ctx, "tcp4", "223.5.5.5:443") == nil
	v6 := dial(ctx, "tcp6", "[2606:4700:4700::1111]:443") == nil || dial(ctx, "tcp6", "[2400:3200::1]:443") == nil
	p.mu.Lock()
	p.ipCheckAt, p.ipv4, p.ipv6 = time.Now(), v4, v6
	p.mu.Unlock()
	return v4, v6
}

// connCounts reads /proc/net/sockstat{,6} on Linux (cheap) and falls back
// to gopsutil elsewhere.
func connCounts(ctx context.Context) (tcp, udp int, valid bool) {
	if runtime.GOOS == "linux" {
		for _, f := range []string{"/proc/net/sockstat", "/proc/net/sockstat6"} {
			t, u, ok := parseSockstat(f)
			if ok {
				valid = true
				tcp += t
				udp += u
			}
		}
		return tcp, udp, valid
	}
	tcpOK, udpOK := false, false
	if cs, err := gnet.ConnectionsWithContext(ctx, "tcp"); err == nil {
		tcpOK = true
		tcp = len(cs)
	}
	if cs, err := gnet.ConnectionsWithContext(ctx, "udp"); err == nil {
		udpOK = true
		udp = len(cs)
	}
	return tcp, udp, tcpOK && udpOK
}

func parseSockstat(path string) (tcp, udp int, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		// "TCP: inuse 12 orphan 0 tw 3 ..." / "TCP6: inuse 4"
		if fields[0] == "TCP:" || fields[0] == "TCP6:" {
			if fields[1] == "inuse" {
				tcp, _ = strconv.Atoi(fields[2])
			}
		}
		if fields[0] == "UDP:" || fields[0] == "UDP6:" {
			if fields[1] == "inuse" {
				udp, _ = strconv.Atoi(fields[2])
			}
		}
	}
	return tcp, udp, true
}
