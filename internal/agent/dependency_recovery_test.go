package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/egressguard"
	"github.com/zeptop-dev/bosun/internal/shaper"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

type dependencyCore struct {
	fakeCore
	users    []spec.User
	inbounds []spec.Inbound
	renders  int
}

func (c *dependencyCore) Render(node *spec.Node, ibs []spec.Inbound, users []spec.User) (*core.Bundle, error) {
	c.users = append([]spec.User(nil), users...)
	c.inbounds = append([]spec.Inbound(nil), ibs...)
	c.renders++
	return c.fakeCore.Render(node, ibs, users)
}

func dependencyRig(t *testing.T) (*Agent, *dependencyCore) {
	t.Helper()
	// No real system commands or kernel writes, even on Linux runners.
	t.Setenv("PATH", t.TempDir())
	c := &dependencyCore{fakeCore: fakeCore{name: "singbox", protos: []spec.Protocol{spec.VLESS}}}
	reg := core.NewRegistry()
	reg.Register(c)
	a := New(&config.Config{DataDir: t.TempDir()}, nopDriver{}, reg, nil, slog.Default())
	a.Shaper = &shaper.Shaper{Interface: "eth0"}
	a.Egress = &egressguard.Guard{}
	a.node = &spec.Node{Inbounds: []spec.Inbound{{Tag: "test", Protocol: spec.VLESS, Port: 443}}}
	a.users = []spec.User{{ID: 1, Name: "limited", UUID: "test", SpeedLimitMbps: 10}}
	return a, c
}

func installDependencyRunners(a *Agent, fail *bool, commands *[]string) {
	a.Shaper.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		command := name + " " + strings.Join(args, " ")
		*commands = append(*commands, command)
		if *fail {
			return nil, errors.New("operation not permitted")
		}
		return nil, nil
	}
	a.Egress.Run = func(_ context.Context, script, name string, args ...string) ([]byte, error) {
		*commands = append(*commands, name+" "+strings.Join(args, " ")+" "+script)
		if *fail {
			return nil, errors.New("operation not permitted")
		}
		return nil, nil
	}
}

func TestDependencyRecoveryPreservesDesiredLimitsAndAppliesAfterInstall(t *testing.T) {
	a, c := dependencyRig(t)
	ctx := context.Background()
	if err := a.apply(ctx); err != nil {
		t.Fatal(err)
	}
	if a.users[0].SpeedLimitMbps != 10 || c.users[0].SpeedLimitMbps != 0 || !a.configUserLimitsOmitted {
		t.Fatalf("desired users must survive degraded render: desired=%+v render=%+v", a.users, c.users)
	}
	if a.dependencyRecovery.missing != dependencyShaper|dependencyEgress {
		t.Fatal(a.dependencyRecovery)
	}
	before := c.renders
	if a.reconcileAfterPull(ctx, false, time.Now().Add(time.Hour)) || c.renders != before {
		t.Fatal("missing binaries must not trigger reconfiguration")
	}
	var commands []string
	fail := false
	installDependencyRunners(a, &fail, &commands)
	if !a.reconcileAfterPull(ctx, false, time.Now()) {
		t.Fatal("tool installation did not trigger recovery")
	}
	if c.users[0].SpeedLimitMbps != 10 || a.configUserLimitsOmitted || a.dependencyRecovery.missing != 0 {
		t.Fatalf("limits not restored: render=%+v state=%+v", c.users, a.dependencyRecovery)
	}
	if !strings.Contains(strings.Join(commands, "\n"), "htb rate 10mbit ceil 10mbit") {
		t.Fatal("no requested kernel rate installed", commands)
	}
	if st := a.Status(); st.Egress == nil || !st.Egress.Supported || st.Egress.Error != "" || st.Shaper == nil || st.Shaper.Users != 1 || st.Shaper.Error != "" {
		t.Fatalf("missing actual helper success: %+v", st)
	}
	if a.reconcileAfterPull(ctx, false, time.Now().Add(time.Hour)) {
		t.Fatal("successful recovery kept retrying")
	}
}

func TestDependencyRecoveryBoundsKernelFailuresAndHonorsBackoff(t *testing.T) {
	a, c := dependencyRig(t)
	ctx := context.Background()
	if err := a.apply(ctx); err != nil {
		t.Fatal(err)
	}
	var commands []string
	fail := true
	installDependencyRunners(a, &fail, &commands)
	at := time.Now()
	for i := 1; i <= dependencyRecoveryMax; i++ {
		if !a.reconcileAfterPull(ctx, false, at) {
			t.Fatalf("attempt %d missing", i)
		}
		if a.dependencyRecovery.attempts != i {
			t.Fatal(a.dependencyRecovery)
		}
		if a.reconcileAfterPull(ctx, false, at.Add(time.Second)) {
			t.Fatal("backoff bypassed")
		}
		at = at.Add(5 * time.Minute)
	}
	// A private-access hard failure can mark the core dirty; it must not
	// defeat the dependency retry budget on the ordinary pull branch.
	a.coreDirty, a.dirty, a.coreDependencyFailure = true, true, true
	before := c.renders
	if a.reconcileAfterPull(ctx, false, at.Add(time.Hour)) || c.renders != before {
		t.Fatal("exhausted recovery restarted cores")
	}
	if st := a.Status(); st.Egress == nil || st.Egress.Error == "" || st.Shaper == nil || st.Shaper.Error == "" {
		t.Fatal("kernel failure must remain visible")
	}
	// Independently failed forward work is still retried without core writes.
	a.forwardDirty = true
	if !a.reconcileAfterPull(ctx, false, at.Add(time.Hour)) || c.renders != before {
		t.Fatal("forward retry was lost or restarted cores")
	}
}

func TestDependencyRecoveryUsesLatestUsersAndScopedLimits(t *testing.T) {
	a, c := dependencyRig(t)
	a.node.Inbounds[0].ScopedUsers = true
	a.node.Inbounds[0].Users = append([]spec.User(nil), a.users...)
	ctx := context.Background()
	if err := a.apply(ctx); err != nil {
		t.Fatal(err)
	}
	if a.node.Inbounds[0].Users[0].SpeedLimitMbps != 10 || c.inbounds[0].Users[0].SpeedLimitMbps != 0 {
		t.Fatal("scoped intent was mutated or degraded render still marked sockets")
	}
	// A new grant revokes user 1 before recovery. No retry owns a copy of it.
	p := &configRevisionPanel{revisionPanel: &revisionPanel{}, users: []spec.User{{ID: 2, Name: "replacement", UUID: "replacement", SpeedLimitMbps: 3}}, usersChanged: true}
	a.driver = p
	changed, err := a.pull(ctx)
	if err != nil || !changed {
		t.Fatal(changed, err)
	}
	a.node.Inbounds[0].Users = append([]spec.User(nil), a.users...)
	var commands []string
	fail := false
	installDependencyRunners(a, &fail, &commands)
	if !a.reconcileAfterPull(ctx, changed, time.Now()) {
		t.Fatal("new intent not applied")
	}
	if len(c.users) != 1 || c.users[0].ID != 2 || c.users[0].SpeedLimitMbps != 3 || c.inbounds[0].Users[0].ID != 2 {
		t.Fatalf("revoked authorization restored: %+v", c.users)
	}
	all := strings.Join(commands, "\n")
	if strings.Contains(all, "10mbit") || !strings.Contains(all, "3mbit") {
		t.Fatal(all)
	}
}

func TestDependencyRecoveryStopsOnPauseModeOrRevocation(t *testing.T) {
	for _, kind := range []string{"pause", "monitor", "changing", "revoked", "offline"} {
		t.Run(kind, func(t *testing.T) {
			a, c := dependencyRig(t)
			if err := a.apply(context.Background()); err != nil {
				t.Fatal(err)
			}
			var commands []string
			fail := false
			installDependencyRunners(a, &fail, &commands)
			switch kind {
			case "pause":
				a.node.ServiceControl = &spec.ServiceControl{Mode: spec.ServiceControlPause}
			case "monitor":
				a.cfg.NodeMode = spec.NodeMonitor
			case "changing":
				a.modeChanging.Store(true)
			case "revoked", "offline":
				p := &configRevisionPanel{revisionPanel: &revisionPanel{}}
				if kind == "revoked" {
					p.leaseError = fmt.Errorf("authorization revoked")
				} else {
					p.offline = true
				}
				a.driver = p
			}
			before := c.renders
			a.coreDirty, a.coreDependencyFailure = true, true // hard dependency failures must not fall into legacy retries
			if a.reconcileAfterPull(context.Background(), false, time.Now().Add(time.Hour)) || c.renders != before || len(commands) != 0 || a.dependencyRecovery.attempts != 0 {
				t.Fatal("stale retry survived changed authority", a.dependencyRecovery, commands)
			}
		})
	}
}

func TestDependencyRecoveryDoctorRemainsReadOnly(t *testing.T) {
	a, _ := dependencyRig(t)
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	var commands []string
	fail := false
	installDependencyRunners(a, &fail, &commands)
	before := a.dependencyRecovery
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = a.Doctor(ctx)
	if len(commands) != 0 || a.dependencyRecovery != before {
		t.Fatal("Doctor applied rules or consumed a recovery attempt", commands)
	}
}

// On Linux exercise real exec.LookPath and the actual command adapter, not the
// Run injection that intentionally advertises support on non-Linux test hosts.
func TestDependencyRecoveryActualPATHTransition(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux command adapter")
	}
	a, c := dependencyRig(t)
	ctx := context.Background()
	if err := a.apply(ctx); err != nil {
		t.Fatal(err)
	}
	bin := os.Getenv("PATH")
	logPath := filepath.Join(t.TempDir(), "commands")
	t.Setenv("BOSUN_DEPENDENCY_TEST_COMMANDS", logPath)
	for _, name := range []string{"nft", "tc", "ip"} {
		script := "#!/bin/sh\nprintf '%s\\n' \"" + name + " $*\" >> \"$BOSUN_DEPENDENCY_TEST_COMMANDS\"\n"
		if name == "nft" {
			script += "if [ \"$1\" = -f ]; then while IFS= read -r line; do :; done; fi\n"
		}
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if !a.reconcileAfterPull(ctx, false, time.Now()) {
		t.Fatal("PATH transition not detected")
	}
	if a.dependencyRecovery.missing != 0 || c.users[0].SpeedLimitMbps != 10 {
		t.Fatal("real adapter recovery failed", a.Status())
	}
	commands, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(commands), "htb rate 10mbit ceil 10mbit") {
		t.Fatal(string(commands))
	}
}

func TestDependencyRecoveryRestoresEgressBeforeShapingTools(t *testing.T) {
	a, _ := dependencyRig(t)
	ctx := context.Background()
	if err := a.apply(ctx); err != nil {
		t.Fatal(err)
	}
	a.Egress.Run = func(context.Context, string, string, ...string) ([]byte, error) { return nil, nil }
	at := time.Now()
	if !a.reconcileAfterPull(ctx, false, at) {
		t.Fatal("nft installation did not restore egress")
	}
	if a.dependencyRecovery.missing != dependencyShaper || a.Status().Egress.Error != "" {
		t.Fatal(a.dependencyRecovery, a.Status().Egress)
	}
	if a.reconcileAfterPull(ctx, false, at.Add(time.Hour)) {
		t.Fatal("retried even though remaining shaper tools still missing")
	}
	a.Shaper.Run = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	if !a.reconcileAfterPull(ctx, false, at.Add(time.Hour)) || a.dependencyRecovery.missing != 0 {
		t.Fatal("later tc install did not restore shaping", a.dependencyRecovery)
	}
}

func TestDependencyRecoveryDoesNotSuppressIndependentCoreFailure(t *testing.T) {
	a, c := dependencyRig(t)
	ctx := context.Background()
	c.fail = errors.New("transient core start failure")
	if err := a.apply(ctx); err == nil {
		t.Fatal("missing core failure")
	}
	if a.coreDependencyFailure {
		t.Fatal("unrelated core failure classified as dependency failure")
	}
	before := c.renders
	c.fail = nil
	if !a.reconcileAfterPull(ctx, false, time.Now().Add(time.Minute)) || c.renders == before || !c.running {
		t.Fatal("core retry blocked by missing packages")
	}
	if a.dependencyRecovery.attempts != 0 {
		t.Fatal("core retry consumed dependency budget")
	}
}

func TestDependencyFailureClassificationPreservesIndependentCleanupErrors(t *testing.T) {
	dependency := dependencyFailure(errors.New("nft denied"))
	if !isDependencyFailure(errors.Join(dependency, nil)) {
		t.Fatal("dependency error lost through cleanup join")
	}
	if isDependencyFailure(errors.Join(dependency, errors.New("accounting checkpoint failed"))) {
		t.Fatal("independent cleanup failure lost its retry path")
	}
}
