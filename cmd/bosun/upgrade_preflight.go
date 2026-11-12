package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"time"

	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/coreinstall"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func candidatePreflight(configPath string) func(context.Context, string, string) error {
	return func(ctx context.Context, binary, version string) error {
		ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		// The verified target binary supplies its own catalog. Using the old
		// process's catalog cannot validate a new release's default core versions.
		cmd := exec.CommandContext(ctx, binary, "preflight-upgrade", configPath)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s cannot use the configured Captain core delivery; upgrade Captain first or inspect the target with preflight-upgrade: %w", version, err)
		}
		return nil
	}
}
func preflightUpgrade(ctx context.Context, path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if cfg.NodeMode == spec.NodeMonitor {
		return nil
	}
	inst, err := coreCommandInstaller(cfg, false, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return err
	}
	if inst.Downloads == nil {
		return nil
	}
	initial := configuredCores(cfg)
	manager, err := coreinstall.NewManager(inst, initial)
	if err != nil {
		return err
	}
	manager.AutoPin = automaticCores(cfg)
	for name, version := range manager.Selected() {
		initial[name] = spec.CoreInstance{Distribution: name, Version: version}
	}
	for name, instance := range initial {
		if instance.External {
			continue
		}
		if err := inst.CheckDelivery(ctx, name, instance.Version); err != nil {
			return fmt.Errorf("%s %s: %w", name, instance.Version, err)
		}
	}
	return nil
}
