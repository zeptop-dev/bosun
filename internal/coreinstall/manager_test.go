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
	r := spec.CoreRequest{Action: "activate", Distribution: "singbox", Version: "1.14.1-r3", Revision: 1}
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
	path := i.Path("singbox", "1.14.1-r3")
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
	if i.Installed("singbox", "1.14.1-r3") {
		t.Fatal("symlink mistaken for a managed binary")
	}
}

func TestManagedLegacySecurityBuildsAreRejected(t *testing.T) {
	i := New(t.TempDir(), slog.Default())
	m, err := NewManager(i, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Validate(spec.CoreRequest{Action: "download", Distribution: "singbox", Version: "1.14.1-r3"}); err != nil {
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
