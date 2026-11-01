package snell

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/core"
)

func TestRenderedEvidenceRequiresEverySnellProcessAndAtomicAcceptance(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fixture-snell")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\ncat \"$2\" > \"$2.loaded\"\nexec sleep 120\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{Binary: bin, WorkDir: filepath.Join(dir, "runtime")}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	t.Cleanup(func() { _ = c.Stop(ctx) })
	b := &core.Bundle{Meta: map[string]string{"one": "snell", "two": "snell"}, Files: map[string][]byte{"one/" + configFile: []byte("psk = private-one\n"), "two/" + configFile: []byte("psk = private-two\n")}}
	if err := c.Apply(ctx, b); err != nil {
		t.Fatal(err)
	}
	first := c.RenderedConfig()
	if first == nil || first.Files != 2 || first.Processes != 2 {
		t.Fatal("whole multi-process activation absent", first)
	}
	if err := c.Apply(ctx, b); err != nil {
		t.Fatal(err)
	}
	if got := c.RenderedConfig(); got == nil || *got != *first {
		t.Fatal("unchanged multi-process retry changed evidence")
	}
	b.Files["one/"+configFile] = []byte("psk = changed-one\n")
	b.Files["two/"+configFile] = []byte("psk = changed-two\n")
	// The first instance restarts successfully; writing the second fails.
	c.instances["two"].cfg = dir
	if err := c.Apply(ctx, b); err == nil {
		t.Fatal("fixture did not fail second instance")
	}
	if c.RenderedConfig() != nil {
		t.Fatal("partial multi-process application became complete")
	}
	c.instances["two"].cfg = filepath.Join(c.opt.WorkDir, "two", configFile)
	if err := c.Apply(ctx, b); err != nil {
		t.Fatal(err)
	}
	if got := c.RenderedConfig(); got == nil || got.Digest == first.Digest || got.Processes != 2 {
		t.Fatal("successful retry did not recover both instances")
	}
	old := c.instances["two"].sup.PID()
	process, err := os.FindProcess(old)
	if err != nil || process.Kill() != nil {
		t.Fatal("could not stop isolated fixture process")
	}
	deadline := time.Now().Add(5 * time.Second)
	for c.instances["two"].sup.PID() == old && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !c.Running() || c.RenderedConfig() != nil {
		t.Fatal("any-instance liveness incorrectly confirmed every process")
	}
}
