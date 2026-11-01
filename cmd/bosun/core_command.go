package main

import (
	"log/slog"
	"path/filepath"

	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/coreinstall"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// coreCommandInstaller uses one loaded snapshot for the mode, destination and
// authenticated source. Reopening the config could silently mix generations or
// turn a Captain install into an upstream download after a rename/removal.
func coreCommandInstaller(cfg *config.Config, install bool, log *slog.Logger) (*coreinstall.Installer, error) {
	dataDir := "/var/lib/bosun"
	if cfg != nil {
		if install && cfg.NodeMode == spec.NodeMonitor {
			return nil, spec.ErrMonitorOnly
		}
		dataDir = cfg.DataDir
	}
	inst := coreinstall.New(filepath.Join(dataDir, "cores"), log)
	if cfg != nil {
		var err error
		inst.Downloads, err = cfg.Downloads()
		if err != nil {
			return nil, err
		}
		if cfg.Cores.RegistryToken != "" {
			inst.Headers = map[string]string{"Deploy-Token": cfg.Cores.RegistryToken}
		}
	}
	return inst, nil
}
