package coreinstall

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentdownload"
)

func TestLazyBinaryDoesNotBlockAndCancelsWithAgent(t *testing.T) {
	entered := make(chan struct{})
	cancelled := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done(); close(cancelled) }))
	defer srv.Close()
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	os.WriteFile(token, []byte("fixture"), 0600)
	client, err := agentdownload.New(srv.URL, token, "", true)
	if err != nil {
		t.Fatal(err)
	}
	i := New(filepath.Join(dir, "cores"), slog.Default())
	i.GOOS = "linux"
	i.GOARCH = "amd64"
	i.Downloads = client
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resolve := i.LazyBinary(ctx, "realm", "")
	if _, err := resolve(ctx); err == nil {
		t.Fatal("missing binary accepted")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("no preparation request")
	}
	for range 10 {
		if _, err := resolve(ctx); err == nil {
			t.Fatal("hung preparation accepted")
		}
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("download outlived owning agent")
	}
	if _, err := resolve(context.Background()); err == nil {
		t.Fatal("cancelled owner supplied binary")
	}
}
