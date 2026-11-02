package hostupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// OpenWrt monitor installations own no Docker, user or firewall resources.
// Keep their removal separate so a router's unrelated services/rules are never
// inspected, stopped or rewritten. root is empty outside isolated tests.
func uninstallOpenWrt(ctx context.Context, root string, keep bool, run runner) error {
	path := func(s string) string { return filepath.Join(root, s) }
	service := path("/etc/init.d/bosun")
	st, err := os.Lstat(service)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("OpenWrt bosun service must be a regular installer-owned file")
	}
	raw, err := os.ReadFile(service)
	if err != nil {
		return err
	}
	if !strings.Contains(string(raw), "# bosun OpenWrt monitor service.") {
		return errors.New("unrecognized OpenWrt bosun service; remove it manually")
	}
	if _, err = run(ctx, service, "stop"); err != nil {
		return err
	}
	if _, err = run(ctx, service, "disable"); err != nil {
		return err
	}
	owned := []string{"/etc/init.d/bosun", "/usr/local/bin/bosun", "/usr/local/bin/bosun.new", "/usr/local/bin/bosun.backup", "/usr/local/bin/bosun.backup.version", "/usr/local/lib/bosun-updater"}
	if !keep {
		owned = append(owned, "/etc/bosun", "/etc/bosun-updater", "/var/lib/bosun-updater")
	}
	for _, s := range owned {
		if err := os.RemoveAll(path(s)); err != nil {
			return err
		}
	}
	return nil
}
