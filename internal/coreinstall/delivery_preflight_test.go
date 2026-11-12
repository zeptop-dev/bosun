package coreinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentdownload"
)

func TestDeliveryFailureDoesNotInstallAndCanRecover(t *testing.T) {
	for _, kind := range []string{"404", "401", "timeout", "digest"} {
		t.Run(kind, func(t *testing.T) {
			payload := []byte("verified binary fixture")
			sum := sha256.Sum256(payload)
			var mode atomic.Value
			mode.Store(kind)
			prefix := agentdownload.Prefix + "cores/singbox/1.14.1-r4/linux/amd64/"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer fixture-token" {
					t.Error("missing identity")
				}
				switch mode.Load().(string) {
				case "404":
					http.NotFound(w, r)
					return
				case "401":
					w.WriteHeader(401)
					return
				case "timeout":
					<-r.Context().Done()
					return
				}
				if strings.HasSuffix(r.URL.Path, "manifest") {
					digest := hex.EncodeToString(sum[:])
					if mode.Load().(string) == "digest" {
						digest = strings.Repeat("0", 64)
					}
					json.NewEncoder(w).Encode(map[string]any{"sha256": digest, "url": prefix + "asset", "source_verified": true})
					return
				}
				if r.URL.Path != prefix+"asset" {
					t.Errorf("unexpected endpoint %s", r.URL.Path)
				}
				w.Write(payload)
			}))
			defer srv.Close()
			dir := t.TempDir()
			token := filepath.Join(dir, "token")
			os.WriteFile(token, []byte("fixture-token"), 0600)
			client, err := agentdownload.New(srv.URL, token, "", true)
			if err != nil {
				t.Fatal(err)
			}
			i := New(filepath.Join(dir, "cores"), slog.Default())
			i.GOOS = "linux"
			i.GOARCH = "amd64"
			i.Downloads = client
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			_, err = i.Ensure(ctx, "singbox", "1.14.1-r4")
			cancel()
			if err == nil || i.Installed("singbox", "1.14.1-r4") {
				t.Fatal("bad artifact installed", err)
			}
			// Previous request has finished before changing this non-parallel fixture.
			mode.Store("ok")
			if err = i.CheckDelivery(context.Background(), "singbox", "1.14.1-r4"); err != nil {
				t.Fatal(err)
			}
			if i.Installed("singbox", "1.14.1-r4") {
				t.Fatal("preflight modified local cache")
			}
			if _, err = i.Ensure(context.Background(), "singbox", "1.14.1-r4"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStalledPackageDoesNotBlockOtherCore(t *testing.T) {
	payload := []byte("fixture")
	sum := sha256.Sum256(payload)
	entered := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/xray/") {
			close(entered)
			<-r.Context().Done()
			return
		}
		if strings.HasSuffix(r.URL.Path, "manifest") {
			json.NewEncoder(w).Encode(map[string]any{"sha256": hex.EncodeToString(sum[:]), "url": strings.TrimSuffix(r.URL.Path, "manifest") + "asset", "source_verified": true})
			return
		}
		w.Write(payload)
	}))
	defer srv.Close()
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	os.WriteFile(token, []byte("fixture-token"), 0600)
	client, err := agentdownload.New(srv.URL, token, "", true)
	if err != nil {
		t.Fatal(err)
	}
	i := New(filepath.Join(dir, "cores"), slog.Default())
	i.GOOS = "linux"
	i.GOARCH = "amd64"
	i.Downloads = client
	release := func(name string) Release {
		return Release{Core: name, Version: "1.0.0", Assets: map[string]Asset{"linux/amd64": {URL: "https://example.com/core", Archive: "raw", SHA256: hex.EncodeToString(sum[:])}}}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := i.Install(ctx, release("xray")); done <- err }()
	defer func() { cancel(); <-done }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("slow download not entered")
	}
	fastCtx, fastCancel := context.WithTimeout(context.Background(), time.Second)
	defer fastCancel()
	if _, err = i.Install(fastCtx, release("singbox")); err != nil {
		t.Fatal("independent package blocked", err)
	}
}
