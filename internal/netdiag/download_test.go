package netdiag

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/agentdownload"
	"github.com/zeptop-dev/bosun/pkg/coremanifest"
)

func TestDiagnosticToolsUseCaptainChannel(t *testing.T) {
	for _, tool := range []string{"geocheck", "nexttrace"} {
		t.Run(tool, func(t *testing.T) {
			release := coremanifest.DiagnosticRelease()
			if tool == "nexttrace" {
				release = coremanifest.RouteToolRelease()
			}
			root := agentdownload.Prefix + "cores/" + tool + "/" + release.Version + "/linux/" + runtime.GOARCH + "/"
			data := []byte("#!/bin/sh\necho diagnostic\n")
			sum := sha256.Sum256(data)
			digest := hex.EncodeToString(sum[:])
			if tool == "nexttrace" {
				digest = release.Assets["linux/"+runtime.GOARCH].SHA256
			}
			hits := []string{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits = append(hits, r.URL.Path)
				if r.Header.Get("X-Bosun-Pair-Code") != "PAIR" {
					t.Error("missing authentication")
				}
				if strings.HasSuffix(r.URL.Path, "/manifest") {
					json.NewEncoder(w).Encode(map[string]any{"sha256": digest, "url": root + "asset", "source_verified": true})
				} else {
					w.Write(data)
				}
			}))
			defer srv.Close()
			d, _ := agentdownload.New(srv.URL, filepath.Join(t.TempDir(), "token"), "PAIR", true)
			ctx := agentdownload.WithClient(context.Background(), d)
			dir := t.TempDir()
			os.Chmod(dir, 0700)
			if tool == "geocheck" {
				// coreinstall selects the host platform; the production tools are Linux.
				// The shared release still contains only the supported Linux artifacts.
				if runtime.GOOS != "linux" {
					t.Skip("GeoCheck production install requires Linux")
				}
				path, err := ensureGeoCheck(ctx, dir)
				if err != nil {
					t.Fatal(err)
				}
				if got, _ := os.ReadFile(path); string(got) != string(data) {
					t.Fatal("wrong tool content")
				}
			} else {
				if err := installRouteTool(ctx, dir); err == nil || !strings.Contains(err.Error(), "checksum") {
					t.Fatalf("expected checksum refusal: %v", err)
				}
			}
			if len(hits) != 2 || hits[0] != root+"manifest" || hits[1] != root+"asset" {
				t.Fatalf("unexpected requests %v", hits)
			}
		})
	}
}
