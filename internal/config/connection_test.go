package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConnectionSelectionAuthorityAndPersistence(t *testing.T) {
	dir := t.TempDir()
	old := "https://old.example.com:2096"
	target := "https://agent.example.com:2096"
	if err := SaveConnection(dir, old, old, target, "migration-id", "secret"); err != nil {
		t.Fatal(err)
	}
	v, err := ReadConnection(dir, old, "secret")
	if err != nil || v.URL != target {
		t.Fatal(v, err)
	}
	for _, j := range []struct{ origin, token string }{{old, "replacement"}, {"https://different.example.com", "secret"}} {
		v, err := ReadConnection(dir, j.origin, j.token)
		if err != nil || v.URL != j.origin {
			t.Fatal("cross identity reuse", v, err)
		}
	}
	if err := SaveConnection(dir, old, "https://stale.example.com", old, "new-id", "secret"); err == nil {
		t.Fatal("accepted stale source")
	}
	if err := os.Chmod(filepath.Join(dir, "captain-connection.json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadConnection(dir, old, "secret"); err == nil {
		t.Fatal("accepted public override")
	}
}
func TestConnectionSelectionRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("{}"), 0600)
	os.Symlink(target, filepath.Join(dir, "captain-connection.json"))
	if _, err := ReadConnection(dir, "https://old.example.com", "token"); err == nil {
		t.Fatal("followed symlink")
	}
}
