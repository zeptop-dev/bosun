package spec

import (
	"encoding/json"
	"testing"
)

func TestHostInfoTopologyIsAdditive(t *testing.T) {
	var old HostInfo
	if err := json.Unmarshal([]byte(`{"cpu_cores":4,"virt":"kvm"}`), &old); err != nil {
		t.Fatal(err)
	}
	if old.CPUCores != 4 || old.CPUPhysicalCores != 0 || old.CPUSockets != 0 || old.VirtualizationRole != "" {
		t.Fatalf("old report gained invented topology: %+v", old)
	}
	data, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"cpu_physical_cores", "cpu_sockets", "virtualization_role"} {
		if _, present := fields[key]; present {
			t.Fatalf("unknown field %q should be omitted", key)
		}
	}
	data, err = json.Marshal(HostInfo{CPUCores: 64, CPUPhysicalCores: 32, CPUSockets: 2, VirtualizationRole: "none"})
	if err != nil {
		t.Fatal(err)
	}
	var legacy struct {
		CPUCores int `json:"cpu_cores"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil || legacy.CPUCores != 64 {
		t.Fatalf("legacy reader lost logical CPU count: %+v, %v", legacy, err)
	}
}
