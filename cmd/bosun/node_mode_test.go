package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestMonitorSetupDoesNotDownloadOrInitializeProxyCores(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	// Invalid core releases/user would fail or create accounts if setup touched
	// them. Monitor setup must leave the package directory absent.
	raw := "data_dir: " + dir + "\nnode_mode: monitor\ncores:\n  user: no-such-monitor-core-user\n  xray: {version: definitely-not-a-release}\n  singbox: {version: definitely-not-a-release}\npanel: {driver: local}\n"
	if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	e, err := setup([]string{"-c", p})
	if err != nil {
		t.Fatal(err)
	}
	if e.cfg.NodeMode != spec.NodeMonitor || len(e.reg.Names()) != 0 {
		t.Fatal("monitor initialized cores")
	}
	if _, err = os.Stat(filepath.Join(dir, "cores")); !os.IsNotExist(err) {
		t.Fatal("monitor wrote a core cache", err)
	}
	if err = cmdCore([]string{"install", "-c", p, "xray"}); err != spec.ErrMonitorOnly {
		t.Fatal("CLI bypass", err)
	}
}

func TestOpenWrtRejectsProxyMode(t *testing.T) {
	for _, mode := range []spec.NodeMode{spec.NodeMonitor, spec.NodeFull, ""} {
		err := validateOpenWrtMode(mode, true)
		if mode == spec.NodeMonitor && err != nil || mode != spec.NodeMonitor && err == nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
		if err := validateOpenWrtMode(mode, false); err != nil {
			t.Fatalf("changed other Linux modes: %v", err)
		}
	}
}
