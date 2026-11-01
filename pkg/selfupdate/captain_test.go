package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/agentdownload"
)

func TestCaptainUpgradeUsesAuthenticatedMetadataAndKeepsBackup(t *testing.T) {
	t.Setenv("IN_CONTAINER", "")
	if InContainer() {
		t.Skip("native update requires a native host")
	}
	data := []byte("#!/bin/sh\necho new\n")
	sum := sha256.Sum256(data)
	asset := fmt.Sprintf("bosun-%s-%s", runtime.GOOS, runtime.GOARCH)
	root := agentdownload.Prefix + "bosun/v0.90.0/"
	count := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		if r.Header.Get("Authorization") != "Bearer node-token" || r.Header.Get("X-Bosun-Pair-Code") != "" {
			t.Error("bad authentication")
		}
		switch r.URL.Path {
		case agentdownload.Prefix + "repos/zeptop-dev/bosun/releases/latest", agentdownload.Prefix + "repos/zeptop-dev/bosun/releases/tags/v0.90.0":
			json.NewEncoder(w).Encode(map[string]any{"tag_name": "v0.90.0", "assets": []map[string]any{{"name": asset, "browser_download_url": root + asset, "size": len(data)}, {"name": "SHA256SUMS", "browser_download_url": root + "SHA256SUMS"}}})
		case root + asset:
			w.Write(data)
		case root + "SHA256SUMS":
			fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(sum[:]), asset)
		default:
			t.Errorf("unexpected route %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	os.WriteFile(token, []byte("node-token"), 0600)
	dl, err := agentdownload.New(srv.URL, token, "expired-pair", true)
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "bosun")
	os.WriteFile(exe, []byte("old"), 0755)
	c := &Client{Downloads: dl, Repo: "zeptop-dev/bosun", Binary: "bosun", Version: "v0.89.0", MinVersion: "v0.89.0", Exe: exe, Token: "must-not-leak"}
	if info := c.Check(context.Background(), true); !info.HasUpdate {
		t.Fatalf("check: %+v", info)
	}
	if tag, err := c.Apply(context.Background(), "v0.90.0"); err != nil || tag != "v0.90.0" {
		t.Fatalf("apply %s %v", tag, err)
	}
	if got, _ := os.ReadFile(exe); string(got) != string(data) {
		t.Fatal("new binary missing")
	}
	if got, _ := os.ReadFile(exe + ".backup"); string(got) != "old" {
		t.Fatal("backup missing")
	}
	c.Version = "v0.90.0"
	if tag, err := c.Rollback(); err != nil || tag != "v0.89.0" {
		t.Fatalf("rollback %s %v", tag, err)
	}
	if count != 4 {
		t.Fatalf("unexpected network request count %d", count)
	}
}

func TestCaptainUpgradeRejectsOldVersionAndUnsafeAssets(t *testing.T) {
	t.Setenv("IN_CONTAINER", "")
	if InContainer() {
		t.Skip("native update requires a native host")
	}
	for _, kind := range []string{"old-version", "wrong-version", "external", "wrong-asset", "checksum"} {
		t.Run(kind, func(t *testing.T) {
			asset := fmt.Sprintf("bosun-%s-%s", runtime.GOOS, runtime.GOARCH)
			root := agentdownload.Prefix + "bosun/v0.90.0/"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/repos/") {
					tag := "v0.90.0"
					u := root + asset
					switch kind {
					case "old-version":
						tag = "v0.88.0"
					case "wrong-version":
						tag = "v0.91.0"
					case "external":
						u = "https://example.com/binary"
					case "wrong-asset":
						u = agentdownload.Prefix + "bosun/v0.91.0/" + asset
					}
					json.NewEncoder(w).Encode(map[string]any{"tag_name": tag, "assets": []map[string]any{{"name": asset, "browser_download_url": u}, {"name": "SHA256SUMS", "browser_download_url": root + "SHA256SUMS"}}})
					return
				}
				if strings.HasSuffix(r.URL.Path, "SHA256SUMS") {
					fmt.Fprintf(w, "%s  %s\n", strings.Repeat("0", 64), asset)
				} else {
					w.Write([]byte("new"))
				}
			}))
			defer srv.Close()
			dir := t.TempDir()
			exe := filepath.Join(dir, "bosun")
			os.WriteFile(exe, []byte("old"), 0755)
			dl, _ := agentdownload.New(srv.URL, filepath.Join(dir, "missing"), "PAIR", true)
			c := &Client{Downloads: dl, Repo: "zeptop-dev/bosun", Binary: "bosun", Version: "v0.86.0", Exe: exe}
			if _, err := c.Apply(context.Background(), "v0.90.0"); err == nil {
				t.Fatal("expected refusal")
			}
			if got, _ := os.ReadFile(exe); string(got) != "old" {
				t.Fatal("binary changed after refusal")
			}
		})
	}
}
