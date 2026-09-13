// Package sysinfo samples host resource usage for status reports and probe
// beats.
package sysinfo

import (
	"bufio"
	"context"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Snapshot returns current CPU, memory, swap and root disk usage. Fields that
// cannot be read are left zero rather than failing the whole snapshot.
func Snapshot(ctx context.Context) spec.SystemStatus {
	var s spec.SystemStatus
	if pct, err := cpu.PercentWithContext(ctx, 0, false); err == nil && len(pct) > 0 {
		s.CPUPercent = pct[0]
	}
	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		s.MemTotal, s.MemUsed = vm.Total, vm.Used
	}
	if sw, err := mem.SwapMemoryWithContext(ctx); err == nil {
		s.SwapTotal, s.SwapUsed = sw.Total, sw.Used
	}
	if du, err := disk.UsageWithContext(ctx, "/"); err == nil {
		s.DiskTotal, s.DiskUsed = du.Total, du.Used
	}
	return s
}

// Sampler produces the richer probe snapshot: rates need the previous
// sample, static facts are read once and reachability is re-checked
// occasionally.
type Sampler struct {
	mu        sync.Mutex
	lastAt    time.Time
	lastUp    uint64
	lastDown  uint64
	info      *spec.HostInfo
	ipCheckAt time.Time
	ipv4      bool
	ipv6      bool
	// Dial overrides the reachability dialer (tests).
	Dial func(ctx context.Context, network, addr string) error
}

// Sample extends Snapshot with load, network rates and totals, connection
// and process counts, uptime, reachability and static host info.
func (p *Sampler) Sample(ctx context.Context) spec.SystemStatus {
	s := Snapshot(ctx)
	if l, err := load.AvgWithContext(ctx); err == nil {
		s.Load1, s.Load5, s.Load15 = l.Load1, l.Load5, l.Load15
	}
	if up, down, ok := netTotals(ctx); ok {
		s.NetTotalUp, s.NetTotalDown = up, down
		now := time.Now()
		p.mu.Lock()
		if !p.lastAt.IsZero() && up >= p.lastUp && down >= p.lastDown {
			if secs := now.Sub(p.lastAt).Seconds(); secs > 0 {
				s.NetUp = uint64(float64(up-p.lastUp) / secs)
				s.NetDown = uint64(float64(down-p.lastDown) / secs)
			}
		}
		p.lastAt, p.lastUp, p.lastDown = now, up, down
		p.mu.Unlock()
	}
	s.TCP, s.UDP = connCounts(ctx)
	if pids, err := process.PidsWithContext(ctx); err == nil {
		s.Processes = len(pids)
	}
	if u, err := host.UptimeWithContext(ctx); err == nil {
		s.Uptime = u
	}
	s.Info = p.hostInfo(ctx)
	s.IPv4, s.IPv6 = p.reachability(ctx)
	return s
}

func (p *Sampler) hostInfo(ctx context.Context) *spec.HostInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.info != nil {
		return p.info
	}
	info := &spec.HostInfo{Arch: runtime.GOARCH}
	if hi, err := host.InfoWithContext(ctx); err == nil {
		info.OS = strings.TrimSpace(hi.Platform + " " + hi.PlatformVersion)
		info.Kernel = hi.KernelVersion
		info.Virt = hi.VirtualizationSystem
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
	p.info = info
	return info
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

// netTotals sums bytes over every non-loopback, non-virtual interface.
func netTotals(ctx context.Context) (up, down uint64, ok bool) {
	ios, err := gnet.IOCountersWithContext(ctx, true)
	if err != nil {
		return 0, 0, false
	}
	for _, io := range ios {
		n := io.Name
		if n == "lo" || strings.HasPrefix(n, "docker") || strings.HasPrefix(n, "br-") || strings.HasPrefix(n, "veth") || strings.HasPrefix(n, "virbr") {
			continue
		}
		up += io.BytesSent
		down += io.BytesRecv
	}
	return up, down, true
}

// connCounts reads /proc/net/sockstat{,6} on Linux (cheap) and falls back
// to gopsutil elsewhere.
func connCounts(ctx context.Context) (tcp, udp int) {
	if runtime.GOOS == "linux" {
		for _, f := range []string{"/proc/net/sockstat", "/proc/net/sockstat6"} {
			t, u, ok := parseSockstat(f)
			if ok {
				tcp += t
				udp += u
			}
		}
		return tcp, udp
	}
	if cs, err := gnet.ConnectionsWithContext(ctx, "tcp"); err == nil {
		tcp = len(cs)
	}
	if cs, err := gnet.ConnectionsWithContext(ctx, "udp"); err == nil {
		udp = len(cs)
	}
	return tcp, udp
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
