package hostupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenWrtUninstallOwnsOnlyMonitorFiles(t *testing.T) {
	for _, keep := range []bool{false, true} {
		t.Run(map[bool]string{false: "full", true: "keep-data"}[keep], func(t *testing.T) {
			root := t.TempDir()
			owned := []string{"/etc/init.d/bosun", "/usr/local/bin/bosun", "/usr/local/bin/bosun.backup", "/usr/local/lib/bosun-updater/worker"}
			data := []string{"/etc/bosun/config.yaml", "/etc/bosun/data/captain.token", "/etc/bosun-updater/backups/previous", "/var/lib/bosun-updater/old"}
			unrelated := []string{"/etc/config/firewall", "/etc/config/network", "/etc/init.d/other-service", "/etc/passwd", "/opt/another-container/data", "/usr/local/bin/other"}
			for _, p := range append(append(append([]string{}, owned...), data...), unrelated...) {
				path := filepath.Join(root, p)
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("preserved\n# bosun OpenWrt monitor service.\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var actions []string
			run := func(_ context.Context, name string, args ...string) ([]byte, error) {
				if name != filepath.Join(root, "/etc/init.d/bosun") {
					t.Fatalf("unrelated command: %s %v", name, args)
				}
				actions = append(actions, strings.Join(args, " "))
				return nil, nil
			}
			if err := uninstallOpenWrt(context.Background(), root, keep, run); err != nil {
				t.Fatal(err)
			}
			if strings.Join(actions, ",") != "stop,disable" {
				t.Fatal(actions)
			}
			for _, p := range owned {
				if _, err := os.Lstat(filepath.Join(root, p)); !os.IsNotExist(err) {
					t.Fatalf("owned file remains %s: %v", p, err)
				}
			}
			for _, p := range unrelated {
				if raw, err := os.ReadFile(filepath.Join(root, p)); err != nil || !strings.HasPrefix(string(raw), "preserved") {
					t.Fatalf("unrelated file modified %s: %v", p, err)
				}
			}
			for _, p := range data {
				_, err := os.Stat(filepath.Join(root, p))
				if keep && err != nil || !keep && !os.IsNotExist(err) {
					t.Fatalf("keep=%v path=%s err=%v", keep, p, err)
				}
			}
		})
	}
}

func TestOpenWrtUninstallRefusesUnknownServiceOrFailedStop(t *testing.T) {
	for _, scenario := range []string{"unknown-service", "symlink-service", "failed-stop", "failed-disable"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			service := filepath.Join(root, "etc/init.d/bosun")
			os.MkdirAll(filepath.Dir(service), 0755)
			content := "# bosun OpenWrt monitor service.\n"
			if scenario == "unknown-service" {
				content = "#!/bin/sh\n# operator-managed service\n"
			}
			os.WriteFile(service, []byte(content), 0755)
			if scenario == "symlink-service" {
				os.Rename(service, service+".real")
				os.Symlink(service+".real", service)
			}
			cfg := filepath.Join(root, "etc/bosun/config.yaml")
			os.MkdirAll(filepath.Dir(cfg), 0700)
			os.WriteFile(cfg, []byte("preserved"), 0600)
			count := 0
			run := func(_ context.Context, _ string, args ...string) ([]byte, error) {
				count++
				if (scenario == "failed-stop" && args[0] == "stop") || (scenario == "failed-disable" && args[0] == "disable") {
					return nil, errors.New("cannot stop service")
				}
				return nil, nil
			}
			if err := uninstallOpenWrt(context.Background(), root, false, run); err == nil {
				t.Fatal("expected refusal")
			}
			if raw, err := os.ReadFile(cfg); err != nil || string(raw) != "preserved" {
				t.Fatal("removed data after failure", err)
			}
			if _, err := os.Lstat(service); err != nil {
				t.Fatal("removed service after failure", err)
			}
			if strings.Contains(scenario, "service") && count != 0 {
				t.Fatal("executed unknown service")
			}
		})
	}
}

func TestOpenWrtStandardLayoutIsNarrowAndComplete(t *testing.T) {
	valid := "node_mode: monitor\ndata_dir: /etc/bosun/data\npanel: {captain: {token_file: /etc/bosun/data/captain.token}}\n"
	if err := standardLayout("bosun", []byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{strings.Replace(valid, "monitor", "full", 1), strings.Replace(valid, "/etc/bosun/data/captain.token", "/etc/bosun/token", 1), strings.Replace(valid, "data_dir: /etc/bosun/data", "data_dir: /etc/other/data", 1), valid + "web: {state_file: /etc/bosun/data/../../other.json}\n"} {
		if standardLayout("bosun", []byte(raw)) == nil {
			t.Fatal("accepted incomplete layout", raw)
		}
	}
	if standardLayout("captain", []byte(valid)) == nil {
		t.Fatal("router exception leaked to Captain")
	}
}
