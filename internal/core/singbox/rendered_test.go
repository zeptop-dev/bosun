package singbox

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/core"
)

func renderedCoreFixture(t *testing.T) *Core {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "fixture-core")
	// This real subprocess records exactly the file addressed by the exec
	// arguments. It does not parse a desired Node or use a mock apply result.
	program := `#!/bin/sh
mode="$1"
shift
config=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-c" ]; then shift; config="$1"; fi
  shift
done
if [ "$mode" = "check" ]; then
  if grep -q 'reject-fixture' "$config"; then exit 1; fi
  exit 0
fi
cat "$config" > "$config.loaded"
exec sleep 120
`
	if err := os.WriteFile(bin, []byte(program), 0o700); err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{Binary: bin, WorkDir: filepath.Join(dir, "runtime")}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Stop(context.Background()) })
	return c
}

func renderedWait(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("fixture did not reach expected subprocess state")
}

func TestRenderedEvidenceUsesActualActivationFilesAndNotLaterDisk(t *testing.T) {
	c := renderedCoreFixture(t)
	ctx := context.Background()
	one := &core.Bundle{Main: "config.json", Files: map[string][]byte{"config.json": []byte(`{"credential":"first-private-secret","listen":"198.51.100.20"}`)}}
	if err := c.Start(ctx, one); err != nil {
		t.Fatal(err)
	}
	loaded := c.configPath(one) + ".loaded"
	renderedWait(t, func() bool { b, _ := os.ReadFile(loaded); return bytes.Equal(b, one.Files[one.Main]) })
	first := c.RenderedConfig()
	if first == nil || first.Files != 1 || first.Processes != 1 || first.RuntimeUpdates {
		t.Fatal("missing actual activation evidence", first)
	}
	raw, _ := json.Marshal(first)
	for _, secret := range []string{"first-private-secret", "198.51.100.20", "config.json", c.opt.WorkDir} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("private activation material escaped")
		}
	}
	two := &core.Bundle{Main: "config.json", Files: map[string][]byte{"config.json": []byte(`{"credential":"second-private-secret"}`)}}
	// Validation overwrites the disk file but must not relabel the old
	// running process as having accepted the staged bytes.
	if err := c.Check(ctx, two); err != nil {
		t.Fatal(err)
	}
	if got := c.RenderedConfig(); got == nil || *got != *first {
		t.Fatal("staged file incorrectly replaced running evidence")
	}
	if b, _ := os.ReadFile(loaded); !bytes.Equal(b, one.Files[one.Main]) {
		t.Fatal("fixture silently reloaded staged bytes")
	}
	if err := c.Apply(ctx, two); err != nil {
		t.Fatal(err)
	}
	renderedWait(t, func() bool { b, _ := os.ReadFile(loaded); return bytes.Equal(b, two.Files[two.Main]) })
	second := c.RenderedConfig()
	if second == nil || second.Digest == first.Digest {
		t.Fatal("new activated bytes did not change keyed evidence")
	}
	if err := c.Apply(ctx, two); err != nil {
		t.Fatal(err)
	}
	if got := c.RenderedConfig(); got == nil || *got != *second {
		t.Fatal("unchanged retry refreshed activation time or digest")
	}
}

func TestRenderedEvidenceCheckFailureAndAutomaticRestartRevoke(t *testing.T) {
	c := renderedCoreFixture(t)
	ctx := context.Background()
	good := &core.Bundle{Main: "config.json", Files: map[string][]byte{"config.json": []byte(`{"ok":true}`)}}
	if err := c.Start(ctx, good); err != nil {
		t.Fatal(err)
	}
	loaded := c.configPath(good) + ".loaded"
	renderedWait(t, func() bool { _, err := os.Stat(loaded); return err == nil })
	first := c.RenderedConfig()
	bad := &core.Bundle{Main: "config.json", Files: map[string][]byte{"config.json": []byte(`{"reject-fixture":true}`)}}
	if err := c.Apply(ctx, bad); err == nil {
		t.Fatal("fixture did not reject staged config")
	}
	if c.RenderedConfig() != nil || !c.Running() {
		t.Fatal("failed application was confirmed or destroyed old process")
	}
	if err := c.Apply(ctx, good); err != nil {
		t.Fatal(err)
	}
	if got := c.RenderedConfig(); got == nil || got.Digest != first.Digest {
		t.Fatal("successful same-process retry did not recover")
	}
	// A staged file may differ from the accepted file when an unrelated
	// crash makes the supervisor read it. A new generation must never inherit
	// the old successful activation, even while Running is true again.
	if err := c.Check(ctx, bad); err == nil {
		t.Fatal("fixture did not leave rejected staged bytes on disk")
	}
	old := c.sup.PID()
	process, err := os.FindProcess(old)
	if err != nil || process.Kill() != nil {
		t.Fatal("could not stop isolated fixture process")
	}
	renderedWait(t, func() bool { return c.sup.PID() > 0 && c.sup.PID() != old })
	if c.RenderedConfig() != nil {
		t.Fatal("automatic restart borrowed old activation")
	}
	if err := c.Apply(ctx, good); err != nil {
		t.Fatal(err)
	}
	if c.RenderedConfig() != nil {
		t.Fatal("noop reapply invented evidence for an unobserved generation")
	}
	if err := c.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(ctx, good); err != nil {
		t.Fatal(err)
	}
	if got := c.RenderedConfig(); got == nil || !got.ActivatedAt.After(first.ActivatedAt) {
		t.Fatal("explicit new activation did not recover")
	}
}

func TestRenderedEvidenceRepeatedStartCannotClaimNewFiles(t *testing.T) {
	c := renderedCoreFixture(t)
	ctx := context.Background()
	one := &core.Bundle{Main: "config.json", Files: map[string][]byte{"config.json": []byte(`{"value":1}`)}}
	if err := c.Start(ctx, one); err != nil {
		t.Fatal(err)
	}
	loaded := c.configPath(one) + ".loaded"
	renderedWait(t, func() bool { b, _ := os.ReadFile(loaded); return bytes.Equal(b, one.Files[one.Main]) })
	two := &core.Bundle{Main: "config.json", Files: map[string][]byte{"config.json": []byte(`{"value":2}`)}}
	if err := c.Start(ctx, two); err == nil {
		t.Fatal("supervisor must reject Start on a running process")
	}
	if got := c.RenderedConfig(); got != nil {
		t.Fatal("repeated Start claimed activation of staged bytes")
	}
	if b, _ := os.ReadFile(loaded); !bytes.Equal(b, one.Files[one.Main]) {
		t.Fatal("running fixture unexpectedly reloaded")
	}
}
