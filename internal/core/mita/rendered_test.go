package mita

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/core/grpcraw"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// This isolated helper is a real child process reached through the adapter's
// exec invocation and Unix RPC socket. It reads MITA_CONFIG_JSON_FILE only on
// startup/Start; Reload intentionally does not load listeners or other settings.
func TestRenderedMitaHelper(t *testing.T) {
	if os.Getenv("BOSUN_RENDERED_MITA_FIXTURE") != "1" {
		return
	}
	if os.Args[len(os.Args)-1] == "version" {
		fmt.Println("mita 3.37.0")
		os.Exit(0)
	}
	cfg, socket := os.Getenv("MITA_CONFIG_JSON_FILE"), os.Getenv("MITA_UDS_PATH")
	load := func() error {
		b, err := os.ReadFile(cfg)
		if err != nil {
			return err
		}
		return os.WriteFile(cfg+".loaded", b, 0o600)
	}
	if err := load(); err != nil {
		os.Exit(2)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		os.Exit(3)
	}
	server := grpc.NewServer(grpc.ForceServerCodec(grpcraw.Codec{}), grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
		var raw []byte
		if err := stream.RecvMsg(&raw); err != nil {
			return err
		}
		method, _ := grpc.MethodFromServerStream(stream)
		switch method {
		case methodStatus:
			if _, err := os.Stat(cfg + ".fail-status"); err == nil {
				return status.Error(codes.Unavailable, "fixture status unavailable")
			}
			return stream.SendMsg([]byte{8, byte(statusRunning)})
		case methodStart:
			if err := load(); err != nil {
				return status.Error(codes.Internal, "fixture load failed")
			}
		case methodReload:
			if err := os.WriteFile(cfg+".reloaded", []byte("true"), 0o600); err != nil {
				return status.Error(codes.Internal, "fixture reload failed")
			}
		}
		return stream.SendMsg([]byte{})
	}))
	_ = server.Serve(listener)
	os.Exit(0)
}

func TestRenderedEvidenceMitaFailedCycleCannotResurrectOldFiles(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fixture-mita")
	quoted := "'" + strings.ReplaceAll(os.Args[0], "'", "'\\''") + "'"
	program := "#!/bin/sh\nexport BOSUN_RENDERED_MITA_FIXTURE=1\nexec " + quoted + " -test.run='^TestRenderedMitaHelper$' -- \"$@\"\n"
	if err := os.WriteFile(bin, []byte(program), 0o700); err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{Binary: bin, WorkDir: filepath.Join(dir, "runtime")}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	t.Cleanup(func() { _ = c.Stop(ctx) })
	name := filepath.Join("example", configFile)
	b := &core.Bundle{Meta: map[string]string{"example": "listener-A"}, Files: map[string][]byte{name: []byte("{\"listeners\":\"A\",\"users\":\"private\"}")}}
	if err := c.Apply(ctx, b); err != nil {
		t.Fatal(err)
	}
	first := c.RenderedConfig()
	if first == nil {
		t.Fatal("actual helper startup evidence absent")
	}
	path := filepath.Join(c.opt.WorkDir, name)
	if raw, _ := os.ReadFile(path + ".loaded"); !bytes.Equal(raw, b.Files[name]) {
		t.Fatal("real helper did not read configured activation file")
	}
	// A successful Reload acknowledges dynamic users without reloading the
	// activation file. Its digest must remain A even though disk now differs.
	b.Files[name] = []byte("{\"listeners\":\"A\",\"users\":\"changed-private\"}")
	if err := c.Apply(ctx, b); err != nil {
		t.Fatal(err)
	}
	if got := c.RenderedConfig(); got == nil || got.Digest != first.Digest || !got.RuntimeUpdates {
		t.Fatal("runtime-only reload replaced activation file evidence")
	}
	// Start successfully loads B in the same process, but status fails after
	// that side effect. A subsequent same-B Reload must not resurrect A.
	b.Meta["example"] = "listener-B"
	b.Files[name] = []byte("{\"listeners\":\"B\",\"users\":\"changed-private\"}")
	if err := os.WriteFile(path+".fail-status", []byte("true"), 0o600); err != nil {
		t.Fatal(err)
	}
	failed, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	err = c.Apply(failed, b)
	cancel()
	if err == nil {
		t.Fatal("fixture readiness should fail after Start")
	}
	if raw, _ := os.ReadFile(path + ".loaded"); !bytes.Equal(raw, b.Files[name]) {
		t.Fatal("fixture did not reproduce activation before readiness failure")
	}
	if err := os.Remove(path + ".fail-status"); err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(ctx, b); err != nil {
		t.Fatal(err)
	}
	if c.RenderedConfig() != nil {
		t.Fatal("same-process hot retry resurrected the old activation digest")
	}
	// An explicit full proxy cycle establishes evidence again, even with
	// identical bytes and PID, after the old activation was forgotten.
	b.Meta["example"] = "force-new-cycle"
	if err := c.Apply(ctx, b); err != nil {
		t.Fatal(err)
	}
	if got := c.RenderedConfig(); got == nil || got.Digest == first.Digest || got.RuntimeUpdates || !got.ActivatedAt.After(first.ActivatedAt) {
		t.Fatal("explicit full cycle did not recover activation evidence")
	}
}
