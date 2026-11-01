package hysteria

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestRenderedEvidenceHysteriaFilesExcludeLiveAuth(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fixture-hysteria")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexec sleep 120\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "{}") }))
	t.Cleanup(server.Close)
	c, err := New(Options{Binary: bin, WorkDir: filepath.Join(dir, "runtime"), AuthListen: "127.0.0.1:0", StatsListen: strings.TrimPrefix(server.URL, "http://")}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	t.Cleanup(func() { _ = c.Stop(ctx) })
	ib := []spec.Inbound{{Tag: "example", Protocol: spec.Hysteria2, Port: 18443, TLS: &spec.TLS{Mode: spec.TLSStandard, CertPath: "/synthetic/cert", KeyPath: "/synthetic/key"}}}
	users := []spec.User{{Name: "example", Password: "private-old"}}
	firstBundle, err := c.Render(&spec.Node{}, ib, users)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(ctx, firstBundle); err != nil {
		t.Fatal(err)
	}
	first := c.RenderedConfig()
	if first == nil || first.RuntimeUpdates {
		t.Fatal("startup evidence absent")
	}
	if err := c.Apply(ctx, firstBundle); err != nil {
		t.Fatal(err)
	}
	if got := c.RenderedConfig(); got == nil || got.RuntimeUpdates {
		t.Fatal("unchanged auth falsely marked changed")
	}
	users[0].Password = "private-new"
	secondBundle, err := c.Render(&spec.Node{}, ib, users)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBundle.Files[firstBundle.Main], secondBundle.Files[secondBundle.Main]) {
		t.Fatal("fixture expected auth-independent activation bytes")
	}
	if err := c.Apply(ctx, secondBundle); err != nil {
		t.Fatal(err)
	}
	second := c.RenderedConfig()
	if second == nil || second.Digest != first.Digest || second.ActivatedAt != first.ActivatedAt || !second.RuntimeUpdates {
		t.Fatal("in-memory auth was confused with file activation", second)
	}
	// Auth is swapped before a server-config write. A failed write must not
	// allow the next same-key hot retry to revive the old startup evidence.
	ib[0].Port++
	users[0].Password = "private-after-write-failure"
	thirdBundle, err := c.Render(&spec.Node{}, ib, users)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.opt.WorkDir, configFile)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(ctx, thirdBundle); err == nil {
		t.Fatal("fixture should reject config write")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(ctx, thirdBundle); err != nil {
		t.Fatal(err)
	}
	if c.RenderedConfig() != nil {
		t.Fatal("failed server update and hot retry resurrected old evidence")
	}
	if err := c.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if c.RenderedConfig() != nil {
		t.Fatal("stopped core retained evidence")
	}
}
