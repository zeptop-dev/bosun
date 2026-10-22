package sysinfo

import (
	"context"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestHostInfoRetriesIncompleteTopologyWithoutMutatingReports(t *testing.T) {
	var sampler Sampler
	now := time.Unix(100, 0)
	attempts := 0
	collect := func(context.Context) (*spec.HostInfo, bool) {
		attempts++
		info := &spec.HostInfo{CPUCores: 8, BootTime: 1}
		if attempts > 1 {
			info.VirtualizationRole = "none"
			info.CPUPhysicalCores, info.CPUSockets = 4, 1
		}
		return info, cpuTopologyIncomplete(info)
	}
	first := sampler.cachedHostInfo(context.Background(), now, collect)
	for _, delay := range []time.Duration{time.Second, time.Minute, 5*time.Minute - time.Nanosecond} {
		if got := sampler.cachedHostInfo(context.Background(), now.Add(delay), collect); got != first || attempts != 1 {
			t.Fatal("topology detector retried before its deadline")
		}
	}
	second := sampler.cachedHostInfo(context.Background(), now.Add(5*time.Minute), collect)
	if attempts != 2 || second == first || second.CPUPhysicalCores != 4 || second.CPUSockets != 1 {
		t.Fatalf("topology did not recover: attempts=%d, info=%+v", attempts, second)
	}
	if first.VirtualizationRole != "" || first.CPUPhysicalCores != 0 || first.CPUSockets != 0 {
		t.Fatal("retry mutated the host info held by an earlier report")
	}
	if got := sampler.cachedHostInfo(context.Background(), now.Add(time.Hour), collect); got != second || attempts != 2 {
		t.Fatal("complete topology should remain cached")
	}
}

func TestHostInfoFailedRefreshKeepsFactsAndThrottlesRetry(t *testing.T) {
	now := time.Unix(100, 0)
	first := &spec.HostInfo{CPUCores: 8, BootTime: 1}
	sampler := Sampler{info: first, infoRetryAt: now}
	attempts := 0
	collect := func(context.Context) (*spec.HostInfo, bool) {
		attempts++
		return &spec.HostInfo{}, true
	}
	if got := sampler.cachedHostInfo(context.Background(), now, collect); got != first || attempts != 1 {
		t.Fatal("failed refresh discarded existing host facts")
	}
	if got := sampler.cachedHostInfo(context.Background(), now.Add(time.Minute), collect); got != first || attempts != 1 {
		t.Fatal("failed refresh retried without a delay")
	}
	if got := sampler.cachedHostInfo(context.Background(), now.Add(5*time.Minute), collect); got != first || attempts != 2 {
		t.Fatal("failed refresh never retried")
	}
}

func TestHostInfoInitialFailureIsThrottledAndRecovers(t *testing.T) {
	var sampler Sampler
	now := time.Unix(100, 0)
	attempts := 0
	collect := func(context.Context) (*spec.HostInfo, bool) {
		attempts++
		if attempts == 1 {
			return &spec.HostInfo{CPUCores: 8}, true
		}
		return &spec.HostInfo{CPUCores: 8, BootTime: 1, VirtualizationRole: "guest"}, false
	}
	first := sampler.cachedHostInfo(context.Background(), now, collect)
	if got := sampler.cachedHostInfo(context.Background(), now.Add(time.Minute), collect); got != first || attempts != 1 {
		t.Fatal("initial host info failure invoked the optional detector again before its deadline")
	}
	second := sampler.cachedHostInfo(context.Background(), now.Add(5*time.Minute), collect)
	if attempts != 2 || second == first || second.BootTime != 1 || second.VirtualizationRole != "guest" {
		t.Fatal("initial host info failure did not recover after its deadline")
	}
	if first.BootTime != 0 || first.VirtualizationRole != "" {
		t.Fatal("recovery changed the partial facts held by an earlier report")
	}
}

func TestCPUTopologyRetryConditions(t *testing.T) {
	for _, tc := range []struct {
		name string
		info spec.HostInfo
		want bool
	}{
		{"guest has no physical topology", spec.HostInfo{VirtualizationRole: "guest"}, false},
		{"unknown virtualization", spec.HostInfo{}, true},
		{"non-guest unknown topology", spec.HostInfo{VirtualizationRole: "none"}, true},
		{"host unknown sockets", spec.HostInfo{VirtualizationRole: "host", CPUPhysicalCores: 4}, true},
		{"complete host", spec.HostInfo{VirtualizationRole: "host", CPUPhysicalCores: 4, CPUSockets: 1}, false},
		{"complete bare metal", spec.HostInfo{VirtualizationRole: "none", CPUPhysicalCores: 4, CPUSockets: 1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cpuTopologyIncomplete(&tc.info); got != tc.want {
				t.Fatalf("retry=%v, want %v", got, tc.want)
			}
		})
	}
}
