package coreinstall

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestManifestSanity(t *testing.T) {
	hexRe := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, core := range Cores() {
		if _, ok := Default(core); !ok {
			t.Errorf("%s: no usable release", core)
		}
		if Binary[core] == "" {
			t.Errorf("%s: no binary name", core)
		}
	}
	for _, r := range Manifest {
		if len(r.Assets) == 0 && r.Build == nil {
			t.Errorf("%s %s: neither assets nor build", r.Core, r.Version)
		}
		for plat, a := range r.Assets {
			if a.SHA256 != "" && !hexRe.MatchString(a.SHA256) {
				t.Errorf("%s %s %s: bad sha256", r.Core, r.Version, plat)
			}
			if a.Archive != "raw" && a.Member == "" {
				t.Errorf("%s %s %s: archive without member", r.Core, r.Version, plat)
			}
		}
	}
	if r, ok := Tested("xray"); !ok || r.Version != "26.3.27" {
		t.Fatalf("tested xray should be 26.3.27, got %+v", r)
	}
}

func tarGz(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "dir/README", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("hello"))
	_ = tw.WriteHeader(&tar.Header{Name: "dir/" + name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(content)
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func zipped(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("LICENSE")
	_, _ = w.Write([]byte("mit"))
	w, _ = zw.Create(name)
	_, _ = w.Write(content)
	_ = zw.Close()
	return buf.Bytes()
}

func TestExtract(t *testing.T) {
	bin := []byte("#!/bin/sh\necho core\n")
	got, err := extractTarGz(tarGz(t, "mita", bin), "mita")
	if err != nil || !bytes.Equal(got, bin) {
		t.Fatalf("tar.gz: %v %q", err, got)
	}
	got, err = extractZip(zipped(t, "xray", bin), "xray")
	if err != nil || !bytes.Equal(got, bin) {
		t.Fatalf("zip: %v %q", err, got)
	}
	if _, err := extractZip(zipped(t, "xray", bin), "nope"); err == nil {
		t.Fatal("expected missing member error")
	}
}

func TestEnsureDownloadsVerifiesAndInstalls(t *testing.T) {
	bin := []byte("#!/bin/sh\necho fake-xray\n")
	archive := zipped(t, "xray", bin)
	sum := sha256.Sum256(archive)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bad.zip" {
			_, _ = w.Write([]byte("tampered"))
			return
		}
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	root := t.TempDir()
	inst := New(root, slog.Default())
	inst.GOOS, inst.GOARCH = "testos", "testarch"
	rel := Release{Core: "xray", Version: "0.0.1", Status: StatusTested, Assets: map[string]Asset{
		"testos/testarch": {URL: srv.URL + "/ok.zip", SHA256: hex.EncodeToString(sum[:]), Archive: "zip", Member: "xray"},
	}}
	path, err := inst.Install(context.Background(), rel)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(root, "xray", "0.0.1", "xray") {
		t.Fatalf("path: %s", path)
	}
	data, _ := os.ReadFile(path)
	if !bytes.Equal(data, bin) {
		t.Fatalf("content: %q", data)
	}
	if !inst.Installed("xray", "0.0.1") {
		t.Fatal("should be installed")
	}

	bad := rel
	bad.Version = "0.0.2"
	bad.Assets = map[string]Asset{"testos/testarch": {URL: srv.URL + "/bad.zip", SHA256: hex.EncodeToString(sum[:]), Archive: "zip", Member: "xray"}}
	if _, err := inst.Install(context.Background(), bad); err == nil {
		t.Fatal("expected sha256 mismatch")
	}
	if inst.Installed("xray", "0.0.2") {
		t.Fatal("tampered download must not be installed")
	}
	if _, err := os.Stat(filepath.Join(root, "xray", "0.0.2", "xray.partial")); err == nil {
		t.Fatal("partial file must be cleaned up")
	}
}

func TestSumsURLAndFallback(t *testing.T) {
	bin := []byte("#!/bin/sh\necho ci-singbox\n")
	sum := sha256.Sum256(bin)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Deploy-Token") != "tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/sing-box/1.0.0/SHA256SUMS":
			_, _ = w.Write([]byte(hex.EncodeToString(sum[:]) + "  sing-box-1.0.0-testos-testarch\nabc  other\n"))
		case "/sing-box/1.0.0/sing-box-1.0.0-testos-testarch":
			_, _ = w.Write(bin)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	inst := New(t.TempDir(), slog.Default())
	inst.GOOS, inst.GOARCH = "testos", "testarch"
	base := srv.URL + "/sing-box/1.0.0/"
	rel := Release{Core: "singbox", Version: "1.0.0", Status: StatusTested, Assets: map[string]Asset{
		"testos/testarch": {URL: base + "sing-box-1.0.0-testos-testarch", SumsURL: base + "SHA256SUMS", Archive: "raw"},
	}}

	// Without the token the registry answers 401 and there is no build recipe.
	if _, err := inst.Install(context.Background(), rel); err == nil {
		t.Fatal("expected failure without token")
	}
	inst.Headers = map[string]string{"Deploy-Token": "tok"}
	path, err := inst.Install(context.Background(), rel)
	if err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); !bytes.Equal(data, bin) {
		t.Fatalf("content: %q", data)
	}

	// An asset missing from SHA256SUMS is refused.
	rel.Version = "1.0.1"
	rel.Assets["testos/testarch"] = Asset{URL: base + "sing-box-1.0.1-testos-testarch", SumsURL: base + "SHA256SUMS", Archive: "raw"}
	if _, err := inst.Install(context.Background(), rel); err == nil {
		t.Fatal("expected failure for unlisted asset")
	}
}
