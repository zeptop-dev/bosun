package spec

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// ResourceOptions selects NICs for host totals, rates and monthly monitoring
// traffic. It does not affect proxy traffic accounting. Names match exactly.
type ResourceOptions struct {
	GPU               bool     `json:"gpu,omitempty" yaml:"gpu"` // opt-in, never required for host sampling
	IncludeInterfaces []string `json:"include_interfaces,omitempty" yaml:"include_interfaces"`
	ExcludeInterfaces []string `json:"exclude_interfaces,omitempty" yaml:"exclude_interfaces"`
}

func (o ResourceOptions) Validate() error {
	for _, list := range [][]string{o.IncludeInterfaces, o.ExcludeInterfaces} {
		if len(list) > 128 {
			return fmt.Errorf("too many network interfaces")
		}
		for _, name := range list {
			if name == "" || len(name) > 128 || !Plain(name) || strings.ContainsAny(name, " /\\\"'\t\n") {
				return fmt.Errorf("invalid network interface name")
			}
		}
	}
	return nil
}

func (o ResourceOptions) Includes(name string) bool {
	if slices.Contains(o.ExcludeInterfaces, name) {
		return false
	}
	if len(o.IncludeInterfaces) > 0 {
		return slices.Contains(o.IncludeInterfaces, name)
	}
	// Managed tunnels and shaping devices see packets also counted on the
	// uplink. Keep their details, but exclude the extra layer from host totals
	// unless the operator explicitly selects it.
	if name == "ifb-bosun" || name == "ifb-bosun-up" {
		return false
	}
	if suffix, ok := strings.CutPrefix(name, "bwg"); ok {
		slot, err := strconv.Atoi(suffix)
		if err == nil && slot >= 1 && slot <= 16383 && (WireGuardLink{Slot: slot}).Interface() == name {
			return false
		}
	}
	return name != "lo" && name != "lo0" && !strings.HasPrefix(name, "docker") && !strings.HasPrefix(name, "br-") && !strings.HasPrefix(name, "veth") && !strings.HasPrefix(name, "virbr")
}

// MetricValidity distinguishes unavailable data from measured zero, while
// preserving the numeric fields understood by older panels and exporters.
// A nil SystemStatus.Valid means the sender predates validity reporting.
type MetricValidity struct {
	CPU         bool `json:"cpu"`
	Memory      bool `json:"memory"`
	Swap        bool `json:"swap"`
	Disk        bool `json:"disk"`
	Network     bool `json:"network"`
	Load        bool `json:"load"`
	Connections bool `json:"connections"`
	Processes   bool `json:"processes"`
	Uptime      bool `json:"uptime"`
}

// Resources is private operational detail; panels must not copy it to public
// status pages. Null lists mean collection failed; empty lists mean no devices.
// Null rates mean a baseline is missing or a counter reset, never zero usage.
type Resources struct {
	GPU         *GPUStatus           `json:"gpu,omitempty"`
	Epoch       string               `json:"epoch"`    // random sampler identity, changes on agent restart
	Sequence    uint64               `json:"sequence"` // monotonic within Epoch
	At          int64                `json:"at"`       // Unix milliseconds of collection, not receipt
	CPUs        []CPUResource        `json:"cpus"`
	Networks    []NetworkResource    `json:"networks"`
	Filesystems []FilesystemResource `json:"filesystems"`
	Disks       []DiskResource       `json:"disks"`
	Processes   []ProcessResource    `json:"processes"`
}

// GPUStatus has its own clock/sequence: cached GPU readings must not look like
// fresh measurements just because the host heartbeat is newer.
type GPUStatus struct {
	Epoch     string        `json:"epoch,omitempty"`
	Sequence  uint64        `json:"sequence,omitempty"`
	At        int64         `json:"at"`    // Unix milliseconds
	State     string        `json:"state"` // disabled | pending | ok | partial | unavailable | error | unsupported
	Devices   []GPUResource `json:"devices"`
	Truncated bool          `json:"truncated,omitempty"`
}

type GPUResource struct {
	ID          string   `json:"id"` // vendor + UUID/PCI path; private management data
	Name        string   `json:"name"`
	Vendor      string   `json:"vendor"`
	Utilization *float64 `json:"utilization"`
	MemoryTotal *uint64  `json:"memory_total"`
	MemoryUsed  *uint64  `json:"memory_used"`
	Temperature *float64 `json:"temperature"` // Celsius
	Power       *float64 `json:"power"`       // watts
}

type CPUResource struct {
	Name    string   `json:"name"`
	Percent *float64 `json:"percent"`
}

type NetworkResource struct {
	Name     string   `json:"name"`
	ID       string   `json:"id"` // boot + interface index; detects replacement/reboot
	Included bool     `json:"included"`
	Up       uint64   `json:"up"` // cumulative bytes sent
	Down     uint64   `json:"down"`
	UpRate   *float64 `json:"up_rate"`
	DownRate *float64 `json:"down_rate"`
}

type FilesystemResource struct {
	ID           string   `json:"id,omitempty"`            // opaque identity; private paths remain in Mount/Device
	SampledAt    int64    `json:"sampled_at,omitempty"`    // last successful capacity read, Unix milliseconds
	Pool         bool     `json:"pool,omitempty"`          // explicitly identified union filesystem, not inferred from capacity
	MemberMounts []string `json:"member_mounts,omitempty"` // confirmed complete pool membership; private management data
	Mount        string   `json:"mount"`
	Device       string   `json:"device"`
	Type         string   `json:"type"`
	Total        *uint64  `json:"total"`
	Used         *uint64  `json:"used"`
	InodesTotal  *uint64  `json:"inodes_total"`
	InodesUsed   *uint64  `json:"inodes_used"`
}

type DiskResource struct {
	Name      string   `json:"name"`
	ReadRate  *float64 `json:"read_rate"`
	WriteRate *float64 `json:"write_rate"`
	ReadIOPS  *float64 `json:"read_iops"`
	WriteIOPS *float64 `json:"write_iops"`
}

type ProcessResource struct {
	Name string   `json:"name"` // bosun or a supervised core/forwarder instance
	PID  int32    `json:"pid"`
	CPU  *float64 `json:"cpu"` // 100% = one logical CPU, may exceed 100%
	RSS  *uint64  `json:"rss"`
}

func (s SystemStatus) Validity() MetricValidity {
	if s.Valid != nil {
		return *s.Valid
	}
	return MetricValidity{CPU: true, Memory: true, Swap: true, Disk: true, Network: true, Load: true, Connections: true, Processes: true, Uptime: true}
}
