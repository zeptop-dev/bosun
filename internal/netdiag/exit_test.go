package netdiag

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/coremanifest"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func writeOldGeoCheckCache(t *testing.T, root string) string {
	t.Helper()
	path := filepath.Join(root, "tools", "geocheck", "0.3.0-r1", "geocheck")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("old diagnostic tool"), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGeoCheckUsesCurrentCache(t *testing.T) {
	root := t.TempDir()
	old := writeOldGeoCheckCache(t, root)
	release := coremanifest.DiagnosticRelease()
	current := filepath.Join(root, "tools", release.Core, release.Version, release.Core)
	if current == old {
		t.Fatal("security rebuild reuses the old cache identity")
	}
	if err := os.MkdirAll(filepath.Dir(current), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(current, []byte("patched diagnostic tool"), 0700); err != nil {
		t.Fatal(err)
	}
	got, err := ensureGeoCheck(context.Background(), root)
	if err != nil || got != current {
		t.Fatalf("current cached tool: path=%q err=%v", got, err)
	}
	if data, err := os.ReadFile(old); err != nil || string(data) != "old diagnostic tool" {
		t.Fatalf("old cache was changed: %q %v", data, err)
	}
}

func TestGeoCheckDoesNotFallBackToOldCache(t *testing.T) {
	root := t.TempDir()
	old := writeOldGeoCheckCache(t, root)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if path, err := ensureGeoCheck(ctx, root); err == nil || path != "" {
		t.Fatalf("unavailable upgrade must not reuse old cache: path=%q err=%v", path, err)
	}
	if data, err := os.ReadFile(old); err != nil || string(data) != "old diagnostic tool" {
		t.Fatalf("old cache was changed: %q %v", data, err)
	}
}

func TestGeoCheckCurrentCachePermissions(t *testing.T) {
	for _, unsafe := range []string{"directory-symlink", "directory-writable", "binary-symlink", "binary-writable", "binary-not-executable"} {
		t.Run(unsafe, func(t *testing.T) {
			root := t.TempDir()
			writeOldGeoCheckCache(t, root)
			release := coremanifest.DiagnosticRelease()
			dir := filepath.Join(root, "tools", release.Core, release.Version)
			path := filepath.Join(dir, release.Core)
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("diagnostic tool"), 0700); err != nil {
				t.Fatal(err)
			}
			switch unsafe {
			case "directory-symlink", "binary-symlink":
				target := dir
				if unsafe == "binary-symlink" {
					target = path
				}
				if err := os.Rename(target, target+"-real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target+"-real", target); err != nil {
					t.Fatal(err)
				}
			case "directory-writable":
				if err := os.Chmod(dir, 0770); err != nil {
					t.Fatal(err)
				}
			case "binary-writable":
				if err := os.Chmod(path, 0770); err != nil {
					t.Fatal(err)
				}
			case "binary-not-executable":
				if err := os.Chmod(path, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := ensureGeoCheck(context.Background(), root); !os.IsPermission(err) || got != "" {
				t.Fatalf("unsafe current cache accepted: path=%q err=%v", got, err)
			}
		})
	}
}

func TestExitToolBoundary(t *testing.T) {
	for _, in := range []spec.DiagnosticRequest{{Type: "exit", Target: "https://example.com"}, {Type: "exit", SourceIP: "--proxy=example.com"}, {Type: "exit", Resolver: "192.0.2.10"}, {Type: "dns", Target: "example.com", Services: true}} {
		if in.Validate() == nil {
			t.Fatal("unsafe input", in)
		}
	}
	args := geoCheckArgs(spec.DiagnosticRequest{Type: "exit", SourceIP: "192.0.2.10"})
	for _, flag := range []string{"--interface", "192.0.2.10", "--no-access", "--no-ai"} {
		if !strings.Contains(strings.Join(args, " "), flag) {
			t.Fatal(args)
		}
	}
	dir := t.TempDir()
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(dir, "tools")); err != nil {
		t.Fatal(err)
	}
	if _, err := privateToolDir(dir); err == nil {
		t.Fatal("symlink tool directory accepted")
	}
	var buf exitBuffer
	buf.Write(make([]byte, maxExitReport+5))
	if !buf.overflow || len(buf.data) != maxExitReport {
		t.Fatal("unbounded report")
	}
	for _, raw := range []string{`{"schema":2}`, `{"schema":1,"identity":{"ipv4":"example.com"}}`, `<html>failure</html>`} {
		if _, out := validateExitReport([]byte(raw)); out != "invalid_report" {
			t.Fatal(raw, out)
		}
	}
	raw := []byte(`{"schema":1,"identity":{"ipv4":"192.0.2.10","ipv6":"2001:db8::1"},"stash_checks":[{"name":"Example","state":"unknown"}]}`)
	if report, out := validateExitReport(raw); out != "ok" || !json.Valid(report) {
		t.Fatal(out)
	}
}
func TestExitToolTimeoutAndOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geocheck")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec /bin/sleep 5\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if _, out := executeGeoCheck(ctx, path, spec.DiagnosticRequest{Type: "exit"}); out != "timeout" {
		t.Fatal(out)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\nhead -c 150000 /dev/zero\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, out := executeGeoCheck(context.Background(), path, spec.DiagnosticRequest{Type: "exit"}); out != "report_too_large" {
		t.Fatal(out)
	}
}
func TestInstalledGeoCheckSchema(t *testing.T) {
	path := os.Getenv("BOSUN_TEST_GEOCHECK")
	if path == "" {
		t.Skip("release pipeline supplies the real pinned tool")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--demo", "--json")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if _, result := validateExitReport(out); result != "ok" {
		t.Fatalf("pinned upstream schema changed: %s", result)
	}
}
