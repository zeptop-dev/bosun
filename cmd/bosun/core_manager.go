package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/core/hysteria"
	"github.com/zeptop-dev/bosun/internal/core/mita"
	"github.com/zeptop-dev/bosun/internal/core/singbox"
	"github.com/zeptop-dev/bosun/internal/core/snell"
	"github.com/zeptop-dev/bosun/internal/core/xray"
	"github.com/zeptop-dev/bosun/internal/coreinstall"
	"github.com/zeptop-dev/bosun/internal/runas"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func configuredCores(cfg *config.Config) map[string]spec.CoreInstance {
	out := map[string]spec.CoreInstance{}
	add := func(name, binary, version string) {
		if binary == "" {
			var r coreinstall.Release
			var ok bool
			if version == "" {
				r, ok = coreinstall.Default(name)
			} else {
				r, ok = coreinstall.Resolve(name, version)
			}
			if ok {
				version = r.Version
			}
		}
		out[name] = spec.CoreInstance{Distribution: name, Version: version, External: binary != ""}
	}
	if c := cfg.Cores.Singbox; c != nil {
		add("singbox", c.Binary, c.Version)
	}
	if c := cfg.Cores.SingboxExtended; c != nil {
		add("singbox-extended", c.Binary, c.Version)
	}
	if c := cfg.Cores.Xray; c != nil {
		add("xray", c.Binary, c.Version)
	}
	if c := cfg.Cores.Mita; c != nil {
		add("mita", c.Binary, c.Version)
	}
	if c := cfg.Cores.Hysteria; c != nil {
		add("hysteria", c.Binary, c.Version)
	}
	if c := cfg.Cores.Snell; c != nil {
		add("snell", c.Binary, c.Version)
	}
	return out
}

func managedFactory(cfg *config.Config, log *slog.Logger, sink func(string, string, string, int, string)) func(string, string, string) (core.Core, error) {
	return func(name, binary, dir string) (core.Core, error) {
		// Managed versions have nested work directories. Adapter MkdirAll
		// calls otherwise leave the parents at 0750, inaccessible to cores.user.
		if err := prepareManagedWorkDir(cfg.DataDir, dir); err != nil {
			return nil, err
		}
		switch name {
		case "singbox", "singbox-extended":
			settings := cfg.Cores.Singbox
			if name == "singbox-extended" {
				settings = cfg.Cores.SingboxExtended
			}
			if settings == nil {
				settings = &config.SingboxCore{}
			}
			// Reject upstream builds lacking billing support even if someone
			// manually placed an executable into the managed package directory.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, binary, "version").CombinedOutput()
			if err != nil || !strings.Contains(string(output), "with_v2ray_api") {
				return nil, fmt.Errorf("%s build must include with_v2ray_api", name)
			}
			return singbox.New(singbox.Options{Distribution: name, Binary: binary, WorkDir: dir, StatsListen: settings.StatsListen, LogLevel: settings.LogLevel, ConnSink: sink}, log)
		case "xray":
			settings := cfg.Cores.Xray
			if settings == nil {
				settings = &config.XrayCore{}
			}
			return xray.New(xray.Options{Binary: binary, WorkDir: dir, APIListen: settings.APIListen, LogLevel: settings.LogLevel, ConnSink: sink}, log)
		case "mita":
			settings := cfg.Cores.Mita
			if settings == nil {
				settings = &config.MitaCore{}
			}
			return mita.New(mita.Options{Binary: binary, WorkDir: dir, LogLevel: settings.LogLevel}, log)
		case "hysteria":
			settings := cfg.Cores.Hysteria
			if settings == nil {
				settings = &config.HysteriaCore{}
			}
			return hysteria.New(hysteria.Options{Binary: binary, WorkDir: dir, AuthListen: settings.AuthListen, StatsListen: settings.StatsListen, LogLevel: settings.LogLevel, ConnSink: sink}, log)
		case "snell":
			return snell.New(snell.Options{Binary: binary, WorkDir: dir}, log)
		default:
			return nil, fmt.Errorf("unsupported managed distribution %q", name)
		}
	}
}

// Repair every managed level, including directories created by v0.64.0,
// without widening permissions on data_dir or an outside ancestor.
func prepareManagedWorkDir(dataDir, dir string) error {
	rel, err := filepath.Rel(dataDir, dir)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("managed work directory must be inside data_dir")
	}
	path := dataDir
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		path = filepath.Join(path, part)
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("managed work directory cannot be a symlink")
		}
		if err := runas.MkdirRoot(path); err != nil {
			return err
		}
	}
	return nil
}

func automaticCores(cfg *config.Config) map[string]bool {
	out := map[string]bool{}
	if c := cfg.Cores.Singbox; c != nil {
		out["singbox"] = c.Binary == "" && c.Version == ""
	}
	if c := cfg.Cores.SingboxExtended; c != nil {
		out["singbox-extended"] = c.Binary == "" && c.Version == ""
	}
	if c := cfg.Cores.Xray; c != nil {
		out["xray"] = c.Binary == "" && c.Version == ""
	}
	if c := cfg.Cores.Mita; c != nil {
		out["mita"] = c.Binary == "" && c.Version == ""
	}
	if c := cfg.Cores.Hysteria; c != nil {
		out["hysteria"] = c.Binary == "" && c.Version == ""
	}
	if c := cfg.Cores.Snell; c != nil {
		out["snell"] = c.Binary == "" && c.Version == ""
	}
	return out
}
