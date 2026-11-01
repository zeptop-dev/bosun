package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/coreinstall"
	"github.com/zeptop-dev/bosun/pkg/agentdownload"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestCoreCommandKeepsLoadedSourceAfterConfigChanges(t *testing.T) {
	for _, change := range []string{"deleted", "replaced", "invalid"} {
		t.Run(change, func(t *testing.T) {
			payload := []byte("fake core binary")
			sum := sha256.Sum256(payload)
			digest := hex.EncodeToString(sum[:])
			prefix := agentdownload.Prefix + "cores/xray/1.2.3/linux/amd64/"
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Header.Get("X-Bosun-Pair-Code") != "PAIR" || r.Header.Get("Deploy-Token") != "" {
					t.Error("wrong Captain authentication")
				}
				switch r.URL.Path {
				case prefix + "manifest":
					json.NewEncoder(w).Encode(map[string]any{"sha256": digest, "url": prefix + "asset", "source_verified": true})
				case prefix + "asset":
					w.Write(payload)
				default:
					t.Error("unexpected source request")
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			dir := t.TempDir()
			dataDir := filepath.Join(dir, "original-data")
			path := filepath.Join(dir, "config.yaml")
			raw := fmt.Sprintf("data_dir: %s\ncores:\n  registry_token: original-registry\n  xray: {}\npanel:\n  driver: captain\n  captain:\n    url: %s\n    pair_code: PAIR\n    allow_insecure: true\n    download_source: captain\n", dataDir, srv.URL)
			if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			snapshot, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "deleted":
				err = os.Remove(path)
			case "replaced":
				err = os.WriteFile(path, []byte("data_dir: "+filepath.Join(dir, "new-data")+"\ncores:\n  registry_token: changed\n  xray: {}\npanel:\n  driver: local\n"), 0600)
			case "invalid":
				err = os.WriteFile(path, []byte("invalid: ["), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			inst, err := coreCommandInstaller(snapshot, true, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			if inst.Root != filepath.Join(dataDir, "cores") || inst.Downloads == nil || inst.Headers["Deploy-Token"] != "original-registry" {
				t.Fatal("mixed configuration generations")
			}
			inst.GOOS, inst.GOARCH, inst.Musl = "linux", "amd64", false
			rel := coreinstall.Release{Core: "xray", Version: "1.2.3", Assets: map[string]coreinstall.Asset{"linux/amd64": {URL: "https://unreachable.invalid/core", Archive: "raw", SHA256: digest}}}
			dest, err := inst.Install(context.Background(), rel)
			if err != nil {
				t.Fatal(err)
			}
			if got, _ := os.ReadFile(dest); string(got) != string(payload) || calls != 2 {
				t.Fatalf("Captain download was not retained: %q, calls %d", got, calls)
			}
		})
	}
}

func TestCoreCommandKeepsMonitorAndAbsentConfigSemantics(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{NodeMode: spec.NodeMonitor, DataDir: t.TempDir()}
	if _, err := coreCommandInstaller(cfg, true, log); !errors.Is(err, spec.ErrMonitorOnly) {
		t.Fatalf("monitor install: %v", err)
	}
	if _, err := coreCommandInstaller(cfg, false, log); err != nil {
		t.Fatal(err)
	}
	inst, err := coreCommandInstaller(nil, true, log)
	if err != nil || inst.Root != "/var/lib/bosun/cores" || inst.Downloads != nil {
		t.Fatalf("absent config semantics changed: %+v %v", inst, err)
	}
	path := filepath.Join(t.TempDir(), "invalid.yaml")
	os.WriteFile(path, []byte("invalid: ["), 0600)
	if err := cmdCore([]string{"list", "-c", path}); err == nil {
		t.Fatal("invalid existing config silently became standalone")
	}
}
