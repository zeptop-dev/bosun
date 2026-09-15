package coreinstall

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Installer places core binaries under Root/<core>/<version>/<binary>.
type Installer struct {
	Root    string
	Log     *slog.Logger
	HTTP    *http.Client
	GOOS    string            // defaults to runtime.GOOS
	GOARCH  string            // defaults to runtime.GOARCH
	Headers map[string]string // extra request headers, e.g. a GitLab Deploy-Token
}

// New returns an installer rooted at root.
func New(root string, log *slog.Logger) *Installer {
	return &Installer{Root: root, Log: log.With("component", "coreinstall"), HTTP: &http.Client{Timeout: 10 * time.Minute}, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
}

func (i *Installer) platform() string { return i.GOOS + "/" + i.GOARCH }

// Path is where a release's binary lives once installed.
func (i *Installer) Path(core, version string) string {
	return filepath.Join(i.Root, core, version, Binary[core])
}

// Installed reports whether the release binary is present and executable.
func (i *Installer) Installed(core, version string) bool {
	st, err := os.Stat(i.Path(core, version))
	return err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0
}

// Ensure returns the binary path for core at version, installing it if
// needed. An empty version selects the newest tested release (or caution
// release if none is tested). A release marked broken is only installed when
// explicitly named, with a warning.
func (i *Installer) Ensure(ctx context.Context, core, version string) (string, error) {
	var rel Release
	var ok bool
	if version == "" {
		rel, ok = Default(core)
		if !ok {
			return "", fmt.Errorf("coreinstall: no usable release for %s", core)
		}
		if rel.Status != StatusTested {
			i.Log.Warn("no tested release; using the newest caution release", "core", core, "version", rel.Version, "note", rel.Note)
		}
	} else {
		rel, ok = Find(core, version)
		if !ok {
			return "", fmt.Errorf("coreinstall: %s %s is not in the manifest", core, version)
		}
		if rel.Status == StatusBroken {
			i.Log.Warn("installing a release marked broken", "core", core, "version", version, "note", rel.Note)
		}
	}
	if i.Installed(core, rel.Version) {
		return i.Path(core, rel.Version), nil
	}
	return i.Install(ctx, rel)
}

// Install fetches and verifies a release, preferring a prebuilt asset for
// this platform and falling back to a Go build.
func (i *Installer) Install(ctx context.Context, rel Release) (string, error) {
	dest := i.Path(rel.Core, rel.Version)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", err
	}
	tmp := dest + ".partial"
	defer os.Remove(tmp)

	var err error
	asset, hasAsset := rel.Assets[i.platform()]
	if hasAsset {
		i.Log.Info("downloading", "core", rel.Core, "version", rel.Version, "url", asset.URL)
		err = i.download(ctx, asset, tmp)
		if err != nil && rel.Build != nil {
			i.Log.Warn("download failed, building from source instead", "core", rel.Core, "version", rel.Version, "err", err)
			err = i.build(ctx, *rel.Build, tmp)
		}
	} else if rel.Build != nil {
		i.Log.Info("no prebuilt asset for this platform, building from source", "core", rel.Core, "version", rel.Version, "package", rel.Build.Package)
		err = i.build(ctx, *rel.Build, tmp)
	} else {
		return "", fmt.Errorf("coreinstall: %s %s has no asset for %s and no build recipe", rel.Core, rel.Version, i.platform())
	}
	if err != nil {
		return "", err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return "", err
	}
	i.Log.Info("installed", "core", rel.Core, "version", rel.Version, "path", dest)
	return dest, nil
}

func (i *Installer) fetch(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range i.Headers {
		req.Header.Set(k, v)
	}
	resp, err := i.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("coreinstall: GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// expectedSum resolves the digest for an asset: pinned in the manifest, or
// looked up by file name in a SHA256SUMS file next to it.
func (i *Installer) expectedSum(ctx context.Context, a Asset) (string, error) {
	if a.SHA256 != "" {
		return a.SHA256, nil
	}
	if a.SumsURL == "" {
		return "", nil
	}
	sums, err := i.fetch(ctx, a.SumsURL, 1<<20)
	if err != nil {
		return "", err
	}
	name := a.URL[strings.LastIndex(a.URL, "/")+1:]
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == name {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("coreinstall: %s not listed in %s", name, a.SumsURL)
}

func (i *Installer) download(ctx context.Context, a Asset, dest string) error {
	want, err := i.expectedSum(ctx, a)
	if err != nil {
		return err
	}
	body, err := i.fetch(ctx, a.URL, 512<<20)
	if err != nil {
		return err
	}
	if want != "" {
		sum := sha256.Sum256(body)
		if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, want) {
			return fmt.Errorf("coreinstall: sha256 mismatch for %s: got %s want %s", a.URL, got, want)
		}
	} else {
		i.Log.Warn("asset has no sha256 in the manifest; skipping verification", "url", a.URL)
	}
	// xray's zip ships geoip.dat/geosite.dat; it looks for them next to
	// the binary, which is what geosite:/geoip: route rules need.
	if a.Archive == "zip" && a.Member == "xray" {
		for _, extra := range []string{"geoip.dat", "geosite.dat"} {
			if data, err := extractZip(body, extra); err == nil {
				_ = os.WriteFile(filepath.Join(filepath.Dir(dest), extra), data, 0o644)
			}
		}
	}
	bin, err := extract(a, body)
	if err != nil {
		return err
	}
	return os.WriteFile(dest, bin, 0o755)
}

// extract pulls the binary out of the downloaded bytes.
func extract(a Asset, body []byte) ([]byte, error) {
	switch a.Archive {
	case "raw":
		return body, nil
	case "tar.gz":
		return extractTarGz(body, a.Member)
	case "zip":
		return extractZip(body, a.Member)
	}
	return nil, fmt.Errorf("coreinstall: unknown archive type %q", a.Archive)
}

func memberMatches(name, member string) bool {
	name = strings.TrimPrefix(name, "./")
	return name == member || strings.HasSuffix(name, "/"+member)
}

func extractTarGz(body []byte, member string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag == tar.TypeReg && memberMatches(h.Name, member) {
			return io.ReadAll(tr)
		}
	}
	return nil, fmt.Errorf("coreinstall: %q not found in tar.gz", member)
}

func extractZip(body []byte, member string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !memberMatches(f.Name, member) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}
	return nil, fmt.Errorf("coreinstall: %q not found in zip", member)
}

// build runs `go install <package>@<version>` with the given tags into a
// temporary GOBIN and moves the result to dest. Module sums are verified by
// the Go toolchain against the checksum database.
func (i *Installer) build(ctx context.Context, b Build, dest string) error {
	goBin, err := exec.LookPath("go")
	if err != nil {
		return fmt.Errorf("coreinstall: building requires the Go toolchain: %w", err)
	}
	gobin, err := os.MkdirTemp("", "bosun-gobin-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(gobin)

	args := []string{"install", "-trimpath"}
	if len(b.Tags) > 0 {
		args = append(args, "-tags", strings.Join(b.Tags, ","))
	}
	if b.LDFlags != "" {
		args = append(args, "-ldflags", "-s -w "+b.LDFlags)
	}
	args = append(args, b.Package+"@"+b.Version)
	cmd := exec.CommandContext(ctx, goBin, args...)
	cmd.Env = append(os.Environ(), "GOBIN="+gobin, "CGO_ENABLED=0", "GOFLAGS=-mod=mod")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("coreinstall: go %s: %v\n%s", strings.Join(args, " "), err, bytes.TrimSpace(out.Bytes()))
	}
	built := filepath.Join(gobin, filepath.Base(b.Package))
	data, err := os.ReadFile(built)
	if err != nil {
		return fmt.Errorf("coreinstall: build produced no binary: %w", err)
	}
	return os.WriteFile(dest, data, 0o755)
}
