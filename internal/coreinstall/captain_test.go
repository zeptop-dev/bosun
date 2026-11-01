package coreinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/agentdownload"
)

func TestCaptainInstallsOriginalArchiveWithoutUpstreamAccess(t *testing.T) {
	for _, kind := range []string{"raw", "zip", "tar.gz"} {
		t.Run(kind, func(t *testing.T) {
			bin := []byte("#!/bin/sh\necho core\n")
			body := bin
			if kind == "zip" {
				body = zipped(t, "xray", bin)
			}
			if kind == "tar.gz" {
				body = tarGz(t, "xray", bin)
			}
			sum := sha256.Sum256(body)
			digest := hex.EncodeToString(sum[:])
			requests := []string{}
			root := agentdownload.Prefix + "cores/xray/1.2.3/linux/arm64/"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests = append(requests, r.URL.Path)
				if r.Header.Get("X-Bosun-Pair-Code") != "PAIR" {
					t.Error("missing authentication")
				}
				switch r.URL.Path {
				case root + "manifest":
					json.NewEncoder(w).Encode(map[string]any{"sha256": digest, "url": root + "asset", "source_verified": true})
				case root + "asset":
					w.Write(body)
				default:
					http.Error(w, "unexpected request", 500)
				}
			}))
			defer srv.Close()
			d, err := agentdownload.New(srv.URL, filepath.Join(t.TempDir(), "token"), "PAIR", true)
			if err != nil {
				t.Fatal(err)
			}
			inst := New(t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))
			inst.Downloads = d
			inst.GOOS = "linux"
			inst.GOARCH = "arm64"
			inst.Musl = false
			rel := Release{Core: "xray", Version: "1.2.3", Assets: map[string]Asset{"linux/arm64": {URL: "https://unreachable.invalid/core", SHA256: digest, Archive: kind, Member: "xray"}}}
			dest, err := inst.Install(context.Background(), rel)
			if err != nil {
				t.Fatal(err)
			}
			data, _ := os.ReadFile(dest)
			if string(data) != string(bin) {
				t.Fatal("wrong installed bytes")
			}
			if len(requests) != 2 || requests[0] != root+"manifest" || requests[1] != root+"asset" {
				t.Fatalf("wrong requests %v", requests)
			}
		})
	}
}

func TestCaptainFailureNeverFallsBackOrReplacesInstalledBinary(t *testing.T) {
	for _, failure := range []string{"unavailable", "mismatched-pin", "unverified", "external-url", "tampered", "missing-platform"} {
		t.Run(failure, func(t *testing.T) {
			original := []byte("verified binary")
			sum := sha256.Sum256(original)
			digest := hex.EncodeToString(sum[:])
			root := agentdownload.Prefix + "cores/xray/1.2.3/linux/amd64/"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if failure == "unavailable" {
					http.Error(w, "unavailable", 503)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/manifest") {
					m := map[string]any{"sha256": digest, "url": root + "asset", "source_verified": true}
					switch failure {
					case "mismatched-pin":
						m["sha256"] = strings.Repeat("0", 64)
					case "unverified":
						m["source_verified"] = false
					case "external-url":
						m["url"] = "https://example.com/package"
					}
					json.NewEncoder(w).Encode(m)
					return
				}
				if failure == "tampered" {
					w.Write([]byte("tampered"))
				} else {
					w.Write(original)
				}
			}))
			defer srv.Close()
			dir := t.TempDir()
			marker := filepath.Join(dir, "built")
			if err := os.WriteFile(filepath.Join(dir, "go"), []byte("#!/bin/sh\ntouch '"+marker+"'\nexit 1\n"), 0755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			d, _ := agentdownload.New(srv.URL, filepath.Join(dir, "token"), "PAIR", true)
			inst := New(filepath.Join(dir, "cores"), slog.New(slog.NewTextHandler(io.Discard, nil)))
			inst.Downloads = d
			inst.GOOS = "linux"
			inst.GOARCH = "amd64"
			inst.Musl = false
			rel := Release{Core: "xray", Version: "1.2.3", Build: &Build{Package: "example.invalid/core", Version: "v1.2.3"}, Assets: map[string]Asset{"linux/amd64": {URL: "https://unreachable.invalid/core", SHA256: digest, Archive: "raw"}}}
			if failure == "missing-platform" {
				rel.Assets = nil
			}
			dest := inst.Path(rel.Core, rel.Version)
			os.MkdirAll(filepath.Dir(dest), 0755)
			os.WriteFile(dest, []byte("old"), 0755)
			if _, err := inst.Install(context.Background(), rel); err == nil {
				t.Fatal("expected failure")
			}
			if data, _ := os.ReadFile(dest); string(data) != "old" {
				t.Fatal("old binary replaced")
			}
			if _, err := os.Stat(marker); err == nil {
				t.Fatal("source build fallback executed")
			}
		})
	}
}
