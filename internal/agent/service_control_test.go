package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/internal/servicecontrol"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func serviceControlTestRunner(installed *string, fail *bool) func(context.Context, []string, string) ([]byte, error) {
	return func(_ context.Context, args []string, input string) ([]byte, error) {
		if *fail {
			return nil, errors.New("nft failed")
		}
		switch strings.Join(args, " ") {
		case "-j list ruleset":
			return []byte(`{"nftables":[]}`), nil
		case "-c -f -":
			return nil, nil
		case "-f -":
			*installed = input
			return nil, nil
		case "-j list table inet bosun_service_control":
			return []byte(`{"nftables":[{"table":{"name":"bosun_service_control"}},{"chain":{"name":"controlled"}}]}`), nil
		}
		return nil, fmt.Errorf("unexpected command %v", args)
	}
}
func TestServiceControlPauseStopsEvenWhenCheckpointFails(t *testing.T) {
	a, c, _ := checkpointRig(t)
	c.bytes = 100
	c.statsErr = errors.New("counter unavailable")
	var script string
	fail := false
	a.ServiceControl = &servicecontrol.Manager{Dir: t.TempDir(), Run: serviceControlTestRunner(&script, &fail)}
	a.node.ServiceControl = &spec.ServiceControl{Revision: "pause-1", Mode: "pause"}
	if err := a.apply(context.Background()); err == nil {
		t.Fatal("checkpoint failure not reported")
	}
	if c.running {
		t.Fatal("failed checkpoint held proxy service open")
	}
	if !strings.Contains(script, "counter drop") {
		t.Fatal("pause failed to install independent packet guard")
	}
	if got := a.serviceControlReport(); got.AppliedRevision != "" || got.Error == "" || got.Mode != "pause" {
		t.Fatal(got)
	}
	c.statsErr = nil
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.applyForwards(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := a.serviceControlReport(); got.AppliedRevision != "pause-1" || got.Error != "" {
		t.Fatal(got)
	}
	a.node.ServiceControl = &spec.ServiceControl{Revision: "normal-2", Mode: "normal"}
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.applyForwards(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !c.running || strings.Contains(script, "chain") {
		t.Fatal("normal did not restore proxy and remove guard")
	}
}
func TestServiceControlGuardFailureStopsButNeverConfirms(t *testing.T) {
	a, c, _ := checkpointRig(t)
	var script string
	fail := true
	a.ServiceControl = &servicecontrol.Manager{Dir: t.TempDir(), Run: serviceControlTestRunner(&script, &fail)}
	a.node.ServiceControl = &spec.ServiceControl{Revision: "limit-1", Mode: "limit", LimitMbps: 10}
	if err := a.apply(context.Background()); err == nil {
		t.Fatal("failed guard accepted")
	}
	if c.running {
		t.Fatal("failed guard left managed core active")
	}
	if got := a.serviceControlReport(); got.AppliedRevision != "" || got.Error == "" {
		t.Fatal(got)
	}
	fail = false
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.applyForwards(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !c.running || !strings.Contains(script, "rate over 1250000 bytes/second") {
		t.Fatal("limit retry failed")
	}
	if got := a.serviceControlReport(); got.AppliedRevision != "limit-1" || got.LimitMbps != 10 {
		t.Fatal(got)
	}
}
func TestServiceControlNoPerUserLimitMutation(t *testing.T) {
	a, _, _ := checkpointRig(t)
	var script string
	fail := false
	a.ServiceControl = &servicecontrol.Manager{Run: serviceControlTestRunner(&script, &fail)}
	a.users[0].SpeedLimitMbps = 3
	a.node.UserSpeedLimitMbps = 5
	a.node.ServiceControl = &spec.ServiceControl{Revision: "limit", Mode: "limit", LimitMbps: 10}
	if err := a.reconcileServiceControl(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.users[0].SpeedLimitMbps != 3 || a.node.UserSpeedLimitMbps != 5 {
		t.Fatal("server control changed user shaping policy")
	}
	a.users[0].ID = spec.ServiceControlSocketMark - 0x10000
	if err := a.reconcileServiceControl(context.Background()); err == nil {
		t.Fatal("legacy speed mark collision accepted")
	}
}

func TestServiceControlPeriodicFailureStopsWithoutPanelPull(t *testing.T) {
	a, c, _ := checkpointRig(t)
	var script string
	fail := false
	a.ServiceControl = &servicecontrol.Manager{Dir: t.TempDir(), Run: serviceControlTestRunner(&script, &fail)}
	a.node.ServiceControl = &spec.ServiceControl{Revision: "limit-offline", Mode: "limit", LimitMbps: 10}
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.applyForwards(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !c.running {
		t.Fatal("core did not start")
	}
	fail = true
	c.statsErr = errors.New("counter unavailable during outage")
	if err := a.refreshServiceControl(context.Background()); err == nil {
		t.Fatal("lost guard not reported")
	}
	if c.running {
		t.Fatal("periodic guard failure kept proxy running while panel could be offline")
	}
	if !a.coreDirty || !a.forwardDirty || !a.dirty {
		t.Fatal("failure did not schedule full retry")
	}
	if got := a.serviceControlReport(); got.AppliedRevision != "" || got.Error == "" {
		t.Fatal(got)
	}
	fail = false
	c.statsErr = nil
	if err := a.refreshServiceControl(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := a.serviceControlReport(); got.AppliedRevision != "" {
		t.Fatal("guard repair falsely confirmed stopped service", got)
	}
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.applyForwards(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := a.serviceControlReport(); got.AppliedRevision != "limit-offline" || got.Error != "" || !c.running {
		t.Fatal(got)
	}
	// Existing periodic WireGuard reconciliation only applies the core half.
	// It must not leave an otherwise fully applied control permanently pending.
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := a.serviceControlReport(); got.AppliedRevision != "limit-offline" {
		t.Fatal(got)
	}
}

func TestServiceControlScopedLegacyMarkCollision(t *testing.T) {
	a, _, _ := checkpointRig(t)
	var script string
	fail := false
	a.ServiceControl = &servicecontrol.Manager{Run: serviceControlTestRunner(&script, &fail)}
	a.node.ServiceControl = &spec.ServiceControl{Revision: "limit", Mode: "limit", LimitMbps: 10}
	a.node.Inbounds[0].Users = []spec.User{{ID: spec.ServiceControlSocketMark - 0x10000}}
	if err := a.reconcileServiceControl(context.Background()); err == nil {
		t.Fatal("scoped legacy mark collision accepted")
	}
}
