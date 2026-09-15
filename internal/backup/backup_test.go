package backup

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/internal/local"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestRoundTrip(t *testing.T) {
	src := t.TempDir()
	store, _, err := local.Open(filepath.Join(src, "local.json"), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	_ = store.SetAdmin("boss", "correct-horse")
	if err := store.PutInbound(local.Inbound{Inbound: spec.Inbound{Tag: "ss", Protocol: spec.Shadowsocks, Port: 8388, Cipher: "aes-128-gcm", ServerKey: "x"}, Enabled: true}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUser(local.User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutForward(spec.Forward{Tag: "f", Port: 24443, Protocol: "tcp", Target: "198.51.100.20:443"}, ""); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(src, "certs", "custom", "example.com"), 0o750)
	_ = os.WriteFile(filepath.Join(src, "certs", "custom", "example.com", "fullchain.pem"), []byte("PEM"), 0o600)
	_ = os.WriteFile(filepath.Join(src, "komari.json"), []byte(`{"server":"x","uuid":"u","token":"t"}`), 0o600)
	_ = os.WriteFile(filepath.Join(src, "certs", "secret.txt"), []byte("no"), 0o600)

	var buf bytes.Buffer
	if err := Write(src, &buf); err != nil {
		t.Fatal(err)
	}

	dst := t.TempDir()
	fresh, _, err := local.Open(filepath.Join(dst, "local.json"), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	sum, _, err := Restore(dst, bytes.NewReader(buf.Bytes()), fresh.Username()+":other")
	if err != nil {
		t.Fatal(err)
	}
	if sum.Inbounds != 1 || sum.Users != 1 || sum.Forwards != 1 || sum.Ingresses != 0 || !sum.AdminChanged {
		t.Fatalf("summary %+v", sum)
	}
	if err := fresh.Reload(); err != nil {
		t.Fatal(err)
	}
	if !fresh.Login("boss", "correct-horse") || len(fresh.Inbounds()) != 1 || len(fresh.ListUsers()) != 1 || len(fresh.ListForwards()) != 1 {
		t.Fatal("restored store does not show the archived objects")
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "certs", "custom", "example.com", "fullchain.pem")); string(b) != "PEM" {
		t.Fatal("custom certificate not restored")
	}
	if _, err := os.Stat(filepath.Join(dst, "komari.json")); err != nil {
		t.Fatal("komari.json not restored")
	}
	if _, err := os.Stat(filepath.Join(dst, "certs", "secret.txt")); err == nil {
		t.Fatal("files outside the allow-list must not travel")
	}
	// Garbage is refused, and so is a managed-mode archive.
	if _, _, err := Restore(dst, bytes.NewReader([]byte("nope")), ""); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestRestoreRollback(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "local.json"), []byte(`{"mode":"local","admin":{"username":"old","password_hash":"h"}}`), 0o600)
	var buf bytes.Buffer
	if err := Write(dir, &buf); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "local.json"), []byte(`{"mode":"local","admin":{"username":"current","password_hash":"h2"}}`), 0o600)
	sum, rollback, err := Restore(dir, &buf, "current:h2")
	if err != nil || rollback == nil || !sum.AdminChanged {
		t.Fatalf("restore: %+v %v", sum, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "local.json")); !strings.Contains(string(b), "old") {
		t.Fatalf("restore did not write: %s", b)
	}
	if err := rollback(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "local.json")); !strings.Contains(string(b), "current") {
		t.Fatalf("rollback did not restore: %s", b)
	}
}
