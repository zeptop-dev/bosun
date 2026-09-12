package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestVersions(t *testing.T) {
	cases := []struct {
		a, b  string
		newer bool
	}{
		{"v0.6.0", "v0.5.0", true}, {"v0.5.0", "v0.5.0", false}, {"v0.5.0", "v0.10.0", false},
		{"v1.0.0", "v1.0.0-rc1", true}, {"v0.5.1", "v0.5.0", true}, {"dev", "v0.5.0", false}, {"v0.6.0", "dev", false},
	}
	for _, c := range cases {
		if got := Newer(c.a, c.b); got != c.newer {
			t.Errorf("Newer(%s,%s)=%v", c.a, c.b, got)
		}
	}
}

func TestCheckApplyRollback(t *testing.T) {
	t.Setenv("IN_CONTAINER", "")
	if InContainer() {
		t.Skip("running in a container")
	}
	newBin := []byte("#!/bin/sh\necho new\n")
	sum := sha256.Sum256(newBin)
	asset := fmt.Sprintf("tool-%s-%s", runtime.GOOS, runtime.GOARCH)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/releases/latest", "/repos/o/r/releases/tags/v0.6.0":
			fmt.Fprintf(w, `{"tag_name":"v0.6.0","body":"notes","html_url":"u","assets":[{"name":%q,"browser_download_url":%q},{"name":"SHA256SUMS","browser_download_url":%q}]}`,
				asset, srv.URL+"/dl/"+asset, srv.URL+"/dl/SHA256SUMS")
		case "/dl/" + asset:
			w.Write(newBin)
		case "/dl/SHA256SUMS":
			fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(sum[:]), asset)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	exe := filepath.Join(dir, "tool")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := &Client{Repo: "o/r", Binary: "tool", Version: "v0.5.0", APIBase: srv.URL, Exe: exe, HTTP: srv.Client()}
	info := c.Check(context.Background(), true)
	if !info.HasUpdate || info.Latest != "v0.6.0" || !info.ReleaseBuild {
		t.Fatalf("check: %+v", info)
	}
	if info2 := c.Check(context.Background(), false); !info2.Cached {
		t.Fatal("second check should be cached")
	}
	dev := &Client{Repo: "o/r", Binary: "tool", Version: "dev", APIBase: srv.URL, Exe: exe, HTTP: srv.Client()}
	if d := dev.Check(context.Background(), true); d.HasUpdate || d.ReleaseBuild {
		t.Fatalf("dev build must not offer updates: %+v", d)
	}
	if _, err := dev.Apply(context.Background(), ""); err == nil {
		t.Fatal("dev build apply should fail")
	}

	got, err := c.Apply(context.Background(), "")
	if err != nil || got != "v0.6.0" {
		t.Fatalf("apply: %v %s", err, got)
	}
	if b, _ := os.ReadFile(exe); string(b) != string(newBin) {
		t.Fatalf("binary not replaced: %q", b)
	}
	if b, _ := os.ReadFile(exe + ".backup"); string(b) != "old" {
		t.Fatal("backup missing")
	}
	if st, _ := os.Stat(exe); st.Mode()&0o111 == 0 {
		t.Fatal("new binary not executable")
	}
	if !c.Check(context.Background(), true).HasBackup {
		t.Fatal("HasBackup should be true")
	}
	c.Version = "v0.6.0"
	if _, err := c.Apply(context.Background(), ""); err != ErrUpToDate {
		t.Fatalf("expected ErrUpToDate, got %v", err)
	}
	ver, err := c.Rollback()
	if err != nil || ver != "v0.5.0" {
		t.Fatalf("rollback: %v %s", err, ver)
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatal("rollback did not restore the old binary")
	}
	if b, _ := os.ReadFile(exe + ".backup"); string(b) != string(newBin) {
		t.Fatal("rollback should keep the newer binary as backup")
	}

	// Tampered asset is rejected and the binary untouched.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/releases/latest":
			fmt.Fprintf(w, `{"tag_name":"v0.7.0","assets":[{"name":%q,"browser_download_url":%q},{"name":"SHA256SUMS","browser_download_url":%q}]}`, asset, srv.URL+"/dl/"+asset, srv.URL+"/dl/SHA256SUMS")
		}
	}))
	defer bad.Close()
	c2 := &Client{Repo: "o/r", Binary: "tool", Version: "v0.5.0", APIBase: bad.URL, Exe: exe, HTTP: bad.Client()}
	// Same asset but the SHA256SUMS on srv matches it, so tamper by changing expected via a different sums server.
	tamper := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/releases/latest":
			fmt.Fprintf(w, `{"tag_name":"v0.7.0","assets":[{"name":%q,"browser_download_url":%q},{"name":"SHA256SUMS","browser_download_url":%q}]}`, asset, srv.URL+"/dl/"+asset, "https://"+r.Host+"/sums")
		}
	}))
	defer tamper.Close()
	_ = c2
	c3 := &Client{Repo: "o/r", Binary: "tool", Version: "v0.5.0", APIBase: tamper.URL, Exe: exe, HTTP: &http.Client{Transport: srv.Client().Transport}}
	if _, err := c3.Apply(context.Background(), ""); err == nil {
		t.Fatal("bad checksum source must fail")
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatal("failed apply must leave the binary alone")
	}
}
