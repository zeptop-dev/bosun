package sysinfo

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// collectCPUTopology runs only on Linux. A hypervisor module can be present in
// a nested VM, so gopsutil's "host" result alone cannot establish that the
// reported topology belongs to physical hardware. The optional systemd tool
// checks both VM and container virtualization; missing/failed detection stays
// unknown. Nothing is installed and no elevated privilege is required.
func collectCPUTopology(ctx context.Context, info *spec.HostInfo, role string) {
	if role == "guest" {
		info.VirtualizationRole = "guest"
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemd-detect-virt")
	cmd.WaitDelay = 100 * time.Millisecond
	output, err := cmd.Output()
	exitCode := -1
	if err == nil {
		exitCode = 0
	} else {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			exitCode = exitError.ExitCode()
		}
	}
	if ctx.Err() != nil {
		return
	}
	info.VirtualizationRole = detectedVirtualizationRole(role, string(output), exitCode)
	applyCPUTopology(info, "/sys/devices/system/cpu")
}

func detectedVirtualizationRole(role, output string, exitCode int) string {
	// Positive guest evidence always wins, including inside a nested hypervisor.
	if role == "guest" {
		return "guest"
	}
	output = strings.TrimSpace(output)
	if exitCode == 0 && output != "" && output != "none" && !strings.ContainsAny(output, " \t\r\n") {
		return "guest"
	}
	// Exit 1 alone also covers errors. Only its documented "none" output
	// means detection succeeded without finding a VM or container.
	if exitCode == 1 && output == "none" {
		if role == "host" {
			return "host"
		}
		if role == "" {
			return "none"
		}
	}
	return ""
}

func applyCPUTopology(info *spec.HostInfo, root string) {
	if info.VirtualizationRole != "none" && info.VirtualizationRole != "host" {
		return
	}
	cores, sockets, ok := readCPUTopology(root, info.CPUCores)
	if ok {
		info.CPUPhysicalCores, info.CPUSockets = cores, sockets
	}
}

func cpuTopologyIncomplete(info *spec.HostInfo) bool {
	if info.VirtualizationRole == "guest" {
		return false
	}
	return info.VirtualizationRole == "" || info.CPUPhysicalCores <= 0 || info.CPUSockets <= 0
}

// readCPUTopology counts complete, consistent online CPU groups. It does not
// infer SMT from a model name or divide logical CPUs by an assumed thread count.
// IDs may be sparse and repeat across packages. The sibling sets independently
// verify each (package, core) group, rejecting unsupported architecture defaults
// and inconsistent snapshots during CPU hotplug.
func readCPUTopology(root string, logical int) (cores, sockets int, ok bool) {
	online, err := readCPUList(filepath.Join(root, "online"))
	if err != nil || logical <= 0 || len(online) != logical {
		return 0, 0, false
	}
	type coreKey struct{ pkg, core int }
	type coreGroup struct{ cpus, siblings []int }
	groups := make(map[coreKey]coreGroup)
	packages := make(map[int]struct{})
	for _, id := range online {
		dir := filepath.Join(root, "cpu"+strconv.Itoa(id), "topology")
		pkg, err := topologyID(filepath.Join(dir, "physical_package_id"))
		if err != nil {
			return 0, 0, false
		}
		core, err := topologyID(filepath.Join(dir, "core_id"))
		if err != nil {
			return 0, 0, false
		}
		siblings, err := readCPUList(filepath.Join(dir, "core_cpus_list"))
		if errors.Is(err, os.ErrNotExist) {
			siblings, err = readCPUList(filepath.Join(dir, "thread_siblings_list"))
		}
		if err != nil || !slices.Contains(siblings, id) {
			return 0, 0, false
		}
		// Offline sibling threads are outside this snapshot's logical count.
		siblings = slices.DeleteFunc(siblings, func(cpu int) bool {
			_, found := slices.BinarySearch(online, cpu)
			return !found
		})
		key := coreKey{pkg, core}
		group, exists := groups[key]
		if exists && !slices.Equal(group.siblings, siblings) {
			return 0, 0, false
		}
		groups[key] = coreGroup{append(group.cpus, id), siblings}
		packages[pkg] = struct{}{}
	}
	for _, group := range groups {
		if !slices.Equal(group.cpus, group.siblings) {
			return 0, 0, false
		}
	}
	// Read the mask again so a CPU going offline halfway through cannot leave
	// a partial hardware specification alongside the old logical CPU count.
	after, err := readCPUList(filepath.Join(root, "online"))
	if err != nil || !slices.Equal(online, after) {
		return 0, 0, false
	}
	return len(groups), len(packages), true
}

func topologyID(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	id, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 32)
	if err != nil || id < 0 {
		return 0, errors.New("unknown CPU topology ID")
	}
	return int(id), nil
}

func readCPUList(path string) ([]int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCPUList(string(data))
}

func parseCPUList(value string) ([]int, error) {
	const maxCPU = 1 << 16
	invalid := errors.New("invalid CPU list")
	var ids []int
	for _, part := range strings.Split(strings.TrimSpace(value), ",") {
		first, last, isRange := strings.Cut(strings.TrimSpace(part), "-")
		start, err := strconv.Atoi(first)
		if err != nil || start < 0 || start >= maxCPU {
			return nil, invalid
		}
		end := start
		if isRange {
			end, err = strconv.Atoi(last)
			if err != nil || end < start || end >= maxCPU {
				return nil, invalid
			}
		}
		if len(ids)+end-start+1 > maxCPU {
			return nil, invalid
		}
		for id := start; id <= end; id++ {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	for i := 1; i < len(ids); i++ {
		if ids[i] == ids[i-1] {
			return nil, invalid
		}
	}
	return ids, nil
}
