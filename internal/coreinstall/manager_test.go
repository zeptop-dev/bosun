package coreinstall

import (
	"github.com/zeptop-dev/bosun/pkg/spec"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestManagedPackageValidationAndPins(t *testing.T) {
	i := New(t.TempDir(), slog.Default())
	m, err := NewManager(i, map[string]spec.CoreInstance{"singbox": {Distribution: "singbox", External: true}})
	if err != nil {
		t.Fatal(err)
	}
	r := spec.CoreRequest{Action: "activate", Distribution: "singbox", Version: "1.14.1-r4", Revision: 1}
	if _, err = m.Validate(r); err == nil {
		t.Fatal("external binary pin bypassed")
	}
	r.Action = "download"
	r.Version = "unknown"
	if _, err = m.Validate(r); err == nil {
		t.Fatal("unknown version accepted")
	}
	r.Version = "../../bin/sh"
	if _, err = m.Validate(r); err == nil {
		t.Fatal("path accepted as version")
	}
	path := i.Path("singbox", "1.14.1-r4")
	if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(i.Root, "external")
	if err = os.WriteFile(target, []byte("fake"), 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if i.Installed("singbox", "1.14.1-r4") {
		t.Fatal("symlink mistaken for a managed binary")
	}
}

func TestManagedLegacySecurityBuildsAreRejected(t *testing.T) {
	i := New(t.TempDir(), slog.Default())
	m, err := NewManager(i, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Validate(spec.CoreRequest{Action: "download", Distribution: "singbox", Version: "1.14.1-r4"}); err != nil {
		t.Fatalf("safe compatible download rejected: %v", err)
	}
	for _, version := range []string{"1.14.1-r1", "1.14.1-r2"} {
		if _, err := m.Validate(spec.CoreRequest{Action: "download", Distribution: "singbox", Version: version}); err == nil || err.Error() != "this core version is marked broken" {
			t.Fatalf("legacy vulnerable package %s was not rejected as broken: %v", version, err)
		}
	}
}

func TestInvalidPersistedCoreOrderFailsClosed(t *testing.T) {
	i := New(t.TempDir(), slog.Default())
	if err := os.WriteFile(filepath.Join(i.Root, "active.json"), []byte(`{"revision":2,"versions":{},"order":["not-an-adapter"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManager(i, nil); err == nil {
		t.Fatal("unknown adapter would panic on restart")
	}
}

func TestRememberInitialPreservesExplicitConfigAndRejectsBrokenFallback(t *testing.T) {
	i := New(t.TempDir(), slog.Default())
	m, err := NewManager(i, map[string]spec.CoreInstance{"singbox": {Distribution: "singbox", Version: "1.14.1-r4"}})
	if err != nil {
		t.Fatal(err)
	}
	m.AutoPin = map[string]bool{"singbox": true}
	if err = m.RememberInitial("singbox"); err != nil {
		t.Fatal(err)
	}
	if m.ExplicitSelection("singbox") {
		t.Fatal("remembered default became an administrator selection")
	}
	revision := m.Inventory().Revision
	if err = m.RememberInitial("singbox"); err != nil || m.Inventory().Revision != revision {
		t.Fatal("idempotent pin changed revision")
	}
	next, err := NewManager(i, map[string]spec.CoreInstance{"singbox": {Distribution: "singbox", Version: "1.14.4-r2"}})
	if err != nil {
		t.Fatal(err)
	}
	next.AutoPin = map[string]bool{"singbox": true}
	if next.Selected()["singbox"] != "1.14.1-r4" {
		t.Fatal("new default replaced successful version")
	}
	next.AutoPin = map[string]bool{"singbox": false}
	if next.Selected()["singbox"] != "" {
		t.Fatal("auto pin overrode explicit config")
	}
	next.AutoPin["singbox"] = true
	next.state.Defaults["singbox"] = "1.14.1-r3"
	if next.Selected()["singbox"] != "" {
		t.Fatal("automatic fallback selected broken package")
	}
}
