package main

import (
	"errors"
	"os"
	"time"

	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/pkg/selfupdate"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func nodeModeHook(cfg *config.Config) func(spec.NodeMode, uint64, string) error {
	return func(mode spec.NodeMode, revision uint64, identity string) error {
		if err := validateOpenWrtMode(mode, isOpenWrt()); err != nil {
			return err
		}
		if mode == spec.NodeFull && len(configuredCores(cfg)) == 0 {
			return errors.New("enable at least one core in config.yaml before switching to full mode")
		}
		if err := config.SaveNodeMode(cfg.DataDir, mode, revision, identity); err != nil {
			return err
		}
		selfupdate.Restart(time.Second)
		return nil
	}
}

func isOpenWrt() bool { _, err := os.Stat("/etc/openwrt_release"); return err == nil }

func validateOpenWrtMode(mode spec.NodeMode, openwrt bool) error {
	if openwrt && mode != spec.NodeMonitor {
		return errors.New("OpenWrt supports monitor-only mode; proxy and firewall management are unavailable")
	}
	return nil
}
