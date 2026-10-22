package sysinfo

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

type topologyCPU struct {
	id, pkg, core int
	siblings      string
}

func cpuTopologyFixture(t *testing.T, online string, cpus []topologyCPU) string {
	t.Helper()
	root := t.TempDir()
	writeTopologyFile(t, filepath.Join(root, "online"), online)
	for _, cpu := range cpus {
		dir := filepath.Join(root, fmt.Sprintf("cpu%d", cpu.id), "topology")
		writeTopologyFile(t, filepath.Join(dir, "physical_package_id"), fmt.Sprint(cpu.pkg))
		writeTopologyFile(t, filepath.Join(dir, "core_id"), fmt.Sprint(cpu.core))
		writeTopologyFile(t, filepath.Join(dir, "core_cpus_list"), cpu.siblings)
	}
	return root
}

func writeTopologyFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadCPUTopology(t *testing.T) {
	for _, tc := range []struct {
		name, online   string
		cpus           []topologyCPU
		cores, sockets int
	}{
		{
			name: "two sockets reuse core IDs", online: "0-7",
			cpus: []topologyCPU{
				{0, 2, 0, "0,4"}, {1, 2, 1, "1,5"}, {2, 7, 0, "2,6"}, {3, 7, 1, "3,7"},
				{4, 2, 0, "0,4"}, {5, 2, 1, "1,5"}, {6, 7, 0, "2,6"}, {7, 7, 1, "3,7"},
			},
			cores: 4, sockets: 2,
		},
		{
			name: "ARM without SMT", online: "0-3",
			cpus:  []topologyCPU{{0, 0, 0, "0"}, {1, 0, 1, "1"}, {2, 0, 2, "2"}, {3, 0, 3, "3"}},
			cores: 4, sockets: 1,
		},
		{
			name: "hybrid cores with different thread counts", online: "0-5",
			cpus: []topologyCPU{
				{0, 0, 0, "0,4"}, {1, 0, 1, "1,5"}, {2, 0, 2, "2"}, {3, 0, 3, "3"},
				{4, 0, 0, "0,4"}, {5, 0, 1, "1,5"},
			},
			cores: 4, sockets: 1,
		},
		{
			name: "SMT four", online: "0-3",
			cpus:  []topologyCPU{{0, 0, 0, "0-3"}, {1, 0, 0, "0-3"}, {2, 0, 0, "0-3"}, {3, 0, 0, "0-3"}},
			cores: 1, sockets: 1,
		},
		{
			name: "offline siblings and sparse IDs", online: "1,3,8",
			cpus:  []topologyCPU{{1, 0, 9, "1,2"}, {3, 0, 17, "3,4"}, {8, 0, 21, "8"}},
			cores: 3, sockets: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := cpuTopologyFixture(t, tc.online, tc.cpus)
			cores, sockets, ok := readCPUTopology(root, len(tc.cpus))
			if !ok || cores != tc.cores || sockets != tc.sockets {
				t.Fatalf("got cores=%d sockets=%d ok=%v", cores, sockets, ok)
			}
		})
	}
}

func TestReadCPUTopologyRejectsIncompleteOrInconsistentData(t *testing.T) {
	for _, tc := range []struct {
		name, path, value string
		remove            bool
		logical           int
	}{
		{name: "missing topology", path: "cpu1/topology/core_id", remove: true, logical: 2},
		{name: "unknown package ID", path: "cpu0/topology/physical_package_id", value: "-1", logical: 2},
		{name: "unknown core ID", path: "cpu0/topology/core_id", value: "-1", logical: 2},
		{name: "invalid ID", path: "cpu0/topology/core_id", value: "invalid", logical: 2},
		{name: "default core ID with unrelated siblings", path: "cpu1/topology/core_id", value: "0", logical: 2},
		{name: "sibling belongs to different core", path: "cpu0/topology/core_cpus_list", value: "0-1", logical: 2},
		{name: "siblings omit self", path: "cpu0/topology/core_cpus_list", value: "1", logical: 2},
		{name: "missing sibling mask", path: "cpu0/topology/core_cpus_list", remove: true, logical: 2},
		{name: "malformed online mask", path: "online", value: "0-", logical: 2},
		{name: "CPU count changed", logical: 3},
		{name: "CPU count missing", logical: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := cpuTopologyFixture(t, "0-1", []topologyCPU{{0, 0, 0, "0"}, {1, 0, 1, "1"}})
			if tc.path != "" {
				path := filepath.Join(root, tc.path)
				if tc.remove {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				} else {
					writeTopologyFile(t, path, tc.value)
				}
			}
			cores, sockets, ok := readCPUTopology(root, tc.logical)
			if ok || cores != 0 || sockets != 0 {
				t.Fatalf("fabricated partial topology: cores=%d sockets=%d ok=%v", cores, sockets, ok)
			}
		})
	}
}

func TestReadCPUTopologyLegacySiblingName(t *testing.T) {
	root := cpuTopologyFixture(t, "0-1", []topologyCPU{{0, 0, 0, "0-1"}, {1, 0, 0, "0-1"}})
	for _, id := range []string{"cpu0", "cpu1"} {
		dir := filepath.Join(root, id, "topology")
		if err := os.Rename(filepath.Join(dir, "core_cpus_list"), filepath.Join(dir, "thread_siblings_list")); err != nil {
			t.Fatal(err)
		}
	}
	if cores, sockets, ok := readCPUTopology(root, 2); !ok || cores != 1 || sockets != 1 {
		t.Fatalf("got cores=%d sockets=%d ok=%v", cores, sockets, ok)
	}
}

func TestCPUTopologyNotReportedForGuestsOrUnknownHosts(t *testing.T) {
	root := cpuTopologyFixture(t, "0-1", []topologyCPU{{0, 0, 0, "0-1"}, {1, 0, 0, "0-1"}})
	for _, role := range []string{"guest", "", "unsupported", "none", "host"} {
		t.Run(role, func(t *testing.T) {
			info := &spec.HostInfo{CPUCores: 2, VirtualizationRole: role}
			applyCPUTopology(info, root)
			want := 0
			if role == "none" || role == "host" {
				want = 1
			}
			if info.CPUPhysicalCores != want || info.CPUSockets != want || info.CPUCores != 2 {
				t.Fatalf("unexpected CPU counts: %+v", info)
			}
		})
	}
}

func TestDetectedVirtualizationRole(t *testing.T) {
	for _, tc := range []struct {
		name, role, output string
		exitCode           int
		want               string
	}{
		{"bare metal", "", "none\n", 1, "none"},
		{"KVM host", "host", "none\n", 1, "host"},
		{"nested KVM", "host", "kvm\n", 0, "guest"},
		{"container on host", "host", "docker\n", 0, "guest"},
		{"VM detected only by systemd", "", "qemu\n", 0, "guest"},
		{"guest without systemd", "guest", "", -1, "guest"},
		{"guest wins disagreement", "guest", "none\n", 1, "guest"},
		{"host without systemd", "host", "", -1, ""},
		{"missing detector", "", "", -1, ""},
		{"timeout", "", "none\n", -1, ""},
		{"error exit 1", "", "", 1, ""},
		{"failure despite none output", "", "none\n", 2, ""},
		{"success without identifier", "", "", 0, ""},
		{"success with none", "", "none\n", 0, ""},
		{"invalid output", "", "unexpected output\n", 0, ""},
		{"unknown gopsutil role", "other", "none\n", 1, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := detectedVirtualizationRole(tc.role, tc.output, tc.exitCode); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseCPUList(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  []int
	}{
		{"0", []int{0}},
		{"0-3,8,10-11\n", []int{0, 1, 2, 3, 8, 10, 11}},
		{" 8, 0-1, 4 ", []int{0, 1, 4, 8}},
	} {
		got, err := parseCPUList(tc.value)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("parse %q: %v, %v", tc.value, got, err)
		}
	}
	for _, value := range []string{"", "-1", "0,", "0,,1", "0-", "2-1", "0-2-3", "0-65536", "99999999999999999999", "0-1,1", "cpu0"} {
		if _, err := parseCPUList(value); err == nil {
			t.Fatalf("accepted malformed or unbounded CPU list %q", value)
		}
	}
}
