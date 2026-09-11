// Package sysinfo samples host resource usage for status reports.
package sysinfo

import (
	"context"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"

	"gitlab.com/zeptop-group/bosun/internal/spec"
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
