package runas

import (
	"os"
	"path/filepath"
	"testing"
)

// With no account configured every call is a no-op and the cores keep
// bosun's identity: an installation that never sets cores.user must not
// change behaviour.
func TestInactiveIsANoOp(t *testing.T) {
	Clear()
	if Active() || Name() != "" {
		t.Fatalf("cleared state is active: %v %q", Active(), Name())
	}
	if u, g := IDs(); u != -1 || g != -1 {
		t.Fatalf("ids without an account: %d %d", u, g)
	}
	if err := Set(""); err != nil {
		t.Fatalf("Set(\"\"): %v", err)
	}
	if err := Chown(filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Fatalf("Chown without an account: %v", err)
	}
	if err := ChownTree(t.TempDir()); err != nil {
		t.Fatalf("ChownTree without an account: %v", err)
	}
}

// The capability answer is sticky and reports whether it changed: the
// agent restarts the cores only on a change, because a restart drops every
// connection they serve.
func TestSetNetAdminReportsChanges(t *testing.T) {
	Clear()
	SetNetAdmin(false)
	if changed := SetNetAdmin(true); !changed {
		t.Fatal("off -> on should report a change")
	}
	if !NetAdmin() {
		t.Fatal("NetAdmin did not stick")
	}
	if changed := SetNetAdmin(true); changed {
		t.Fatal("on -> on reported a change: the cores would restart for nothing")
	}
	if changed := SetNetAdmin(false); !changed {
		t.Fatal("on -> off should report a change")
	}
	SetNetAdmin(false)
}

// A setup failure is remembered so the doctor can show it instead of the
// agent exiting: a node with a broken account still has to reach the panel.
func TestSetupErrorIsRemembered(t *testing.T) {
	Clear()
	if Error() != "" {
		t.Fatalf("fresh state has an error: %q", Error())
	}
	SetError("useradd: not found")
	if Error() != "useradd: not found" {
		t.Fatalf("error not kept: %q", Error())
	}
	Clear()
	if Error() != "" {
		t.Fatalf("Clear left the error: %q", Error())
	}
}

// WriteFile must never follow a symlink: a core owns some of the
// directories bosun writes into, so a planted link would otherwise let it
// redirect a root write at, say, /etc/shadow.
func TestWriteFileRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "config.json")
	// The core plants config.json.tmp -> victim before bosun writes.
	if err := os.Symlink(victim, target+".tmp"); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := WriteFile(target, []byte("pushed by the panel"), 0o600, false); err != nil {
		t.Fatalf("write through a planted link failed for the wrong reason: %v", err)
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Fatalf("the planted symlink was followed: victim now holds %q", got)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "pushed by the panel" {
		t.Fatalf("the file was not written: %v %q", err, got)
	}
}

// MkdirRoot leaves the directory traversable but not writable by others:
// the cores read their configs there, they do not add entries.
func TestMkdirRootPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "work", "singbox")
	if err := MkdirRoot(dir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		t.Fatalf("group or other can write the core's directory: %o", perm)
	}
	if perm := fi.Mode().Perm(); perm&0o005 != 0o005 {
		t.Fatalf("the core cannot traverse its own directory: %o", perm)
	}
}
