package agent

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/coreinstall"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

type managedFake struct {
	fakeCore
	checkErr      error
	starts, stops int
}

func (f *managedFake) Check(context.Context, *core.Bundle) error { return f.checkErr }
func (f *managedFake) Start(ctx context.Context, b *core.Bundle) error {
	f.starts++
	return f.fakeCore.Start(ctx, b)
}
func (f *managedFake) Stop(ctx context.Context) error { f.stops++; return f.fakeCore.Stop(ctx) }

func coreChangeRig(t *testing.T) (*Agent, *managedFake, *managedFake, spec.CoreRequest) {
	t.Helper()
	cfg := &config.Config{DataDir: t.TempDir()}
	inst := coreinstall.New(cfg.CoresDir(), slog.Default())
	req := spec.CoreRequest{Action: "activate", Distribution: "singbox", Version: "1.14.1-r3", Revision: 1}
	path := inst.Path(req.Distribution, req.Version)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}
	m, err := coreinstall.NewManager(inst, map[string]spec.CoreInstance{"singbox": {Distribution: "singbox", Version: "1.14.1-r1"}})
	if err != nil {
		t.Fatal(err)
	}
	old := &managedFake{fakeCore: fakeCore{name: "singbox", protos: []spec.Protocol{spec.VLESS}, running: true}}
	next := &managedFake{fakeCore: fakeCore{name: "singbox", protos: []spec.Protocol{spec.VLESS}}}
	m.Factory = func(name, binary, dir string) (core.Core, error) {
		if dir == filepath.Join(cfg.DataDir, "singbox") {
			t.Fatal("preflight reused active configuration path")
		}
		return next, nil
	}
	reg := core.NewRegistry()
	reg.Register(old)
	a := New(cfg, nopDriver{}, reg, nil, slog.Default())
	a.CoreManager = m
	a.kernelNode = &spec.Node{Inbounds: []spec.Inbound{{Tag: "existing", Protocol: spec.VLESS, Port: 443}}}
	a.users = []spec.User{{ID: 9, Name: "billing", UUID: "identity"}}
	a.userIDs = map[string]int64{"billing": 9}
	return a, old, next, req
}

func TestCoreActivationPreflightRollbackAndPersistence(t *testing.T) {
	for _, failure := range []string{"check", "start", "persist", "success"} {
		t.Run(failure, func(t *testing.T) {
			a, old, next, req := coreChangeRig(t)
			switch failure {
			case "check":
				next.checkErr = errors.New("bad candidate config")
			case "start":
				next.fail = errors.New("cannot bind listener")
			case "persist":
				if err := os.Mkdir(filepath.Join(a.cfg.CoresDir(), "active.json"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := a.activateCore(ctx, ctx, req)
			if failure == "success" {
				if err != nil {
					t.Fatal(err)
				}
				if old.running || !next.running {
					t.Fatal("active process did not switch")
				}
				if got, _ := a.reg.Get("singbox"); got != next {
					t.Fatal("registry retained old instance")
				}
				loaded, err := coreinstall.NewManager(a.CoreManager.Install, nil)
				if err != nil {
					t.Fatal(err)
				}
				if loaded.Selected()["singbox"] != req.Version || !loaded.AlreadyApplied(req) {
					t.Fatal("selection or retry receipt was not persisted")
				}
				if err = a.ManageCore(ctx, req); err != nil || next.starts != 1 {
					t.Fatalf("retry restarted an already applied core: %v starts=%d", err, next.starts)
				}
				if a.users[0].ID != 9 || a.users[0].UUID != "identity" {
					t.Fatal("accounting identity changed")
				}
			} else {
				if err == nil {
					t.Fatal("expected visible failure")
				}
				if !old.running || next.running {
					t.Fatalf("rollback failed: old=%v next=%v", old.running, next.running)
				}
				if got, _ := a.reg.Get("singbox"); got != old {
					t.Fatal("failed candidate replaced registry")
				}
				if a.CoreManager.Inventory().Revision != 1 {
					t.Fatal("failed operation advanced revision")
				}
				if failure == "check" && old.stops != 0 {
					t.Fatal("preflight failure stopped the old core")
				}
			}
		})
	}
}

func TestCoreActivationRejectsStaleAndIncompatible(t *testing.T) {
	a, old, next, req := coreChangeRig(t)
	req.Revision = 9
	if err := a.activateCore(context.Background(), context.Background(), req); err == nil {
		t.Fatal("stale revision accepted")
	}
	req.Revision = 1
	next.protos = []spec.Protocol{spec.Mieru}
	if err := a.activateCore(context.Background(), context.Background(), req); err == nil {
		t.Fatal("incompatible version accepted")
	}
	if old.stops != 0 {
		t.Fatal("invalid request disturbed service")
	}
}

func TestCoreDownloadDoesNotActivateAndOrderSurvivesRestart(t *testing.T) {
	a, old, next, req := coreChangeRig(t)
	req.Action = "download"
	if err := a.ManageCore(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if old.stops != 0 || next.starts != 0 || a.CoreManager.Inventory().Revision != 1 {
		t.Fatal("download changed active state")
	}
	req.Action = "activate"
	order := []string{"xray", "singbox"}
	if err := a.CoreManager.Commit(req, order); err != nil {
		t.Fatal(err)
	}
	loaded, err := coreinstall.NewManager(a.CoreManager.Install, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := loaded.Order([]string{"singbox", "xray", "mita"})
	if !reflect.DeepEqual(got, []string{"xray", "singbox", "mita"}) {
		t.Fatalf("restart changed preference: %v", got)
	}
}

func TestCoreActivationRejectsUnappliedConfiguration(t *testing.T) {
	a, old, _, req := coreChangeRig(t)
	a.dirty = true
	if err := a.activateCore(context.Background(), context.Background(), req); err == nil || old.stops != 0 {
		t.Fatal("dirty apply must not disturb the running core")
	}
}

func TestExtendedListenersWaitForUsers(t *testing.T) {
	reg := core.NewRegistry()
	extended := &fakeCore{name: "singbox-extended", protos: []spec.Protocol{spec.SSH, spec.Mieru, spec.VLESS}}
	reg.Register(extended)
	a := New(&config.Config{DataDir: t.TempDir()}, nopDriver{}, reg, nil, slog.Default())
	ib := spec.Inbound{Tag: "ssh", Protocol: spec.SSH, Core: "singbox-extended", Port: 2222}
	spec.FillInboundSecrets(&ib)
	a.node = &spec.Node{Inbounds: []spec.Inbound{ib, {Tag: "mieru", Protocol: spec.Mieru, Core: "singbox-extended", Port: 2223}, {Tag: "vless", Protocol: spec.VLESS, Port: 2224}}}
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(extended.applied, []string{"vless"}) || a.Status().Skipped["ssh"] == "" || a.Status().Skipped["mieru"] == "" {
		t.Fatal("empty authenticated listeners affected other inbounds")
	}
	a.users = []spec.User{{ID: 1, Name: "account", UUID: "identity", Password: "test-password"}}
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(extended.applied) != 3 || len(a.Status().Skipped) != 0 {
		t.Fatal("grant did not start waiting inbounds")
	}
}
