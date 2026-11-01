package xray

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/core/grpcraw"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestRenderedEvidenceXrayHotUsersDoNotClaimReloadedFiles(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fixture-xray")
	program := []byte(`#!/bin/sh
if [ "$1" = "version" ]; then echo 'Xray 26.7.11'; exit 0; fi
config=""
check=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-test" ]; then check="yes"; fi
  if [ "$1" = "-c" ]; then shift; config="$1"; fi
  shift
done
if [ -n "$check" ]; then exit 0; fi
cat "$config" > "$config.loaded"
exec sleep 120
`)
	if err := os.WriteFile(bin, program, 0o700); err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{Binary: bin, WorkDir: filepath.Join(dir, "runtime")}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	t.Cleanup(func() { _ = c.Stop(ctx) })
	listener := bufconn.Listen(1 << 20)
	var calls atomic.Int64
	var fail atomic.Bool
	server := grpc.NewServer(grpc.ForceServerCodec(grpcraw.Codec{}), grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
		var raw []byte
		if err := stream.RecvMsg(&raw); err != nil {
			return err
		}
		calls.Add(1)
		if fail.Load() {
			// Force both a partial RPC failure and a failed restart. Remove
			// the executable only after the adapter's config check succeeded.
			_ = os.Remove(bin)
			return status.Error(codes.Unavailable, "fixture RPC failure")
		}
		return stream.SendMsg([]byte{})
	}))
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	c.conn, err = grpc.NewClient("passthrough:///fixture", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	ib := []spec.Inbound{{Tag: "example", Protocol: spec.VLESS, Port: 18443}}
	u := []spec.User{{ID: 1, Name: "synthetic", UUID: "11111111-1111-4111-8111-111111111111"}}
	firstBundle, err := c.Render(&spec.Node{}, ib, u)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(ctx, firstBundle); err != nil {
		t.Fatal(err)
	}
	loaded := c.configPath(firstBundle) + ".loaded"
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b, _ := os.ReadFile(loaded)
		if bytes.Equal(b, firstBundle.Files[firstBundle.Main]) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if b, _ := os.ReadFile(loaded); !bytes.Equal(b, firstBundle.Files[firstBundle.Main]) {
		t.Fatal("actual fixture did not read startup file")
	}
	first := c.RenderedConfig()
	if first == nil {
		t.Fatal("startup evidence absent")
	}
	u[0].UUID = "22222222-2222-4222-8222-222222222222"
	secondBundle, err := c.Render(&spec.Node{}, ib, u)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(ctx, secondBundle); err != nil {
		t.Fatal(err)
	}
	second := c.RenderedConfig()
	if second == nil || second.Digest != first.Digest || second.ActivatedAt != first.ActivatedAt || !second.RuntimeUpdates || calls.Load() < 2 {
		t.Fatal("hot RPC changes relabeled activation files", second)
	}
	if b, _ := os.ReadFile(loaded); !bytes.Equal(b, firstBundle.Files[firstBundle.Main]) {
		t.Fatal("hot fixture unexpectedly reread startup file")
	}
	u[0].UUID = "33333333-3333-4333-8333-333333333333"
	thirdBundle, err := c.Render(&spec.Node{}, ib, u)
	if err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if err := c.Apply(ctx, thirdBundle); err == nil {
		t.Fatal("failed hot RPC and restart unexpectedly succeeded")
	}
	if c.RenderedConfig() != nil {
		t.Fatal("partial hot update retained complete activation evidence")
	}
	fail.Store(false)
	if err := os.WriteFile(bin, program, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(ctx, thirdBundle); err != nil {
		t.Fatal(err)
	}
	if got := c.RenderedConfig(); got == nil || got.Digest == first.Digest || got.RuntimeUpdates {
		t.Fatal("successful explicit retry did not establish fresh activation")
	}
}
