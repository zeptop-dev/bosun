package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/zeptop-dev/bosun/internal/agent"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/core"
)

func TestDeferredSetupDoesNotWaitForCoreDelivery(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); http.NotFound(w, r) }))
	defer srv.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := fmt.Sprintf("data_dir: %s\ncores:\n  user: ''\n  singbox: {}\npanel:\n  driver: captain\n  captain:\n    url: %s\n    pair_code: PAIR\n    allow_insecure: true\n    download_source: captain\n", dir, srv.URL)
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	e, err := setupMode([]string{"-c", path}, true)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatal("setup performed network download")
	}
	c, ok := e.reg.Get("singbox")
	if !ok {
		t.Fatal("configured identity lost")
	}
	if _, ok = c.(*core.Pending); !ok || c.Running() {
		t.Fatal("not pending")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// Preflight sees the same target catalog and fails without creating an active selection.
	if err = preflightUpgrade(ctx, path); err == nil {
		t.Fatal("unsupported delivery accepted")
	}
	if _, err = os.Stat(filepath.Join(dir, "cores", "active.json")); !os.IsNotExist(err) {
		t.Fatal("preflight modified selection")
	}
}

func TestRealCaptainDriverReportsWhileManifestFails(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(fmt.Sprint(blocked), func(t *testing.T) {
			manifests := make(chan struct{}, 1)
			reports := make(chan agentproto.Report, 8)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer fixture-token" {
					t.Error("lost node authentication")
				}
				switch {
				case strings.HasPrefix(r.URL.Path, "/api/agent/downloads/"):
					select {
					case manifests <- struct{}{}:
					default:
					}
					if blocked {
						<-r.Context().Done()
						return
					}
					http.NotFound(w, r)
				case r.URL.Path == "/api/agent/state":
					if r.URL.Query().Get("wait") != "" {
						select {
						case <-r.Context().Done():
							return
						case <-time.After(50 * time.Millisecond):
						}
					}
					json.NewEncoder(w).Encode(agentproto.State{Revision: "state-1", Node: spec.Node{Inbounds: []spec.Inbound{{Tag: "listener", Protocol: spec.VLESS, Core: "singbox", Port: 18443}}}, Users: []spec.User{{ID: 1, Name: "fixture", UUID: "11111111-1111-4111-8111-111111111111"}}, PullSeconds: 1, PushSeconds: 1})
				case r.URL.Path == "/api/agent/report":
					var rep agentproto.Report
					if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
						t.Error(err)
					}
					select {
					case reports <- rep:
					default:
					}
					json.NewEncoder(w).Encode(agentproto.ReportResponse{})
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			token := filepath.Join(dir, "token")
			if err := os.WriteFile(token, []byte("fixture-token"), 0600); err != nil {
				t.Fatal(err)
			}
			raw := fmt.Sprintf("data_dir: %s\ncores:\n  user: ''\n  singbox: {}\npanel:\n  driver: captain\n  captain:\n    url: %s\n    token_file: %s\n    allow_insecure: true\n    download_source: captain\n", dir, srv.URL, token)
			if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			e, err := setupMode([]string{"-c", path}, true)
			if err != nil {
				t.Fatal(err)
			}
			e.inst.GOOS = "linux"
			e.inst.GOARCH = "amd64"
			e.inst.Musl = false
			a := agent.New(e.cfg, e.driver, e.reg, nil, e.log)
			a.CoreManager = e.manager
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- a.Run(ctx) }()
			defer func() { cancel(); <-done }()
			select {
			case <-manifests:
			case <-ctx.Done():
				t.Fatal("no manifest request")
			}
			for range 2 {
				select {
				case rep := <-reports:
					if rep.Cores["singbox"].Running || rep.Cores["singbox"].PreparationError == "" || rep.AppliedRevision != "" {
						t.Fatal("false running/application status", rep.Cores)
					}
				case <-ctx.Done():
					t.Fatal("real driver stopped reporting")
				}
			}
		})
	}
}

func TestDeferredSetupDoesNotResurrectRemovedCoreFromOrder(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "cores"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cores", "active.json"), []byte(`{"revision":2,"versions":{},"order":["singbox","xray"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("data_dir: "+dir+"\ncores:\n  user: ''\n  xray: {}\npanel: {driver: local}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	e, err := setupMode([]string{"-c", path}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := e.reg.Get("singbox"); ok {
		t.Fatal("removed core restored by old priority metadata")
	}
	if _, ok := e.reg.Get("xray"); !ok {
		t.Fatal("configured core lost")
	}
}
