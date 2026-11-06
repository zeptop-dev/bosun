package netdiag

import (
	"context"
	_ "embed"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/zeptop-dev/bosun/internal/coreinstall"
	"github.com/zeptop-dev/bosun/pkg/agentdownload"
	"github.com/zeptop-dev/bosun/pkg/coremanifest"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Our static rebuild of the unmodified MIT upstream tag uses the same patched
// toolchain as bosun. Never download upstream latest or execute a PATH override.
//
//go:embed geocheck-MIT.txt
var geoCheckLicense []byte

const maxExitReport = 128 << 10

func geoCheckArgs(in spec.DiagnosticRequest) []string {
	args := []string{"--json", "--quiet", "--timeout", "4", "--no-mtr", "--no-detect", "--no-portal", "--doh", "off"}
	if in.SourceIP != "" {
		args = append(args, "--interface", in.SourceIP)
	}
	if !in.Services {
		args = append(args, "--group", "geoip", "--no-access", "--no-ai")
	}
	return args
}

func privateToolDir(root string) (string, error) {
	dir := filepath.Join(root, "tools")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	// Every executable parent below tools must be owned by this service user;
	// otherwise a writable data volume could replace a root-run executable.
	release := coremanifest.DiagnosticRelease()
	for _, path := range []string{dir, filepath.Join(dir, release.Core), filepath.Join(dir, release.Core, release.Version)} {
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !info.IsDir() || info.Mode()&0022 != 0 || !ok || int(stat.Uid) != os.Geteuid() {
			return "", os.ErrPermission
		}
	}
	return dir, nil
}
func ensureGeoCheck(ctx context.Context, root string) (string, error) {
	dir, err := privateToolDir(root)
	if err != nil {
		return "", err
	}
	installer := coreinstall.New(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	installer.Downloads = agentdownload.FromContext(ctx)
	release := coremanifest.DiagnosticRelease()
	path := installer.Path(release.Core, release.Version)
	licensePath := filepath.Join(dir, "geocheck-LICENSE.txt")
	f, e := os.OpenFile(licensePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e == nil {
		_, e = f.Write(geoCheckLicense)
		closeErr := f.Close()
		if e != nil {
			return "", e
		}
		if closeErr != nil {
			return "", closeErr
		}
	} else if !os.IsExist(e) {
		return "", e
	}

	if info, err := os.Lstat(path); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || info.Mode()&0022 != 0 || info.Mode()&0100 == 0 || !ok || int(stat.Uid) != os.Geteuid() {
			return "", os.ErrPermission
		}
		return path, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	// The private version directory must exist before Install opens .partial.
	versionDir := filepath.Dir(path)
	if err = os.MkdirAll(versionDir, 0700); err != nil {
		return "", err
	}
	partial := path + ".partial"
	if _, err = os.Lstat(partial); err == nil {
		if err = os.Remove(partial); err != nil {
			return "", err
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	installCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return installer.Install(installCtx, release)
}
func runExit(ctx context.Context, in spec.DiagnosticRequest, root string) (json.RawMessage, string) {
	if root == "" || runtime.GOOS != "linux" {
		return nil, "unavailable"
	}
	path, err := ensureGeoCheck(ctx, root)
	if err != nil {
		return nil, "install_failed"
	}
	return executeGeoCheck(ctx, path, in)
}
func executeGeoCheck(ctx context.Context, path string, in spec.DiagnosticRequest) (json.RawMessage, string) {
	cmd := exec.CommandContext(ctx, path, geoCheckArgs(in)...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.WaitDelay = time.Second
	out := &exitBuffer{}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, contextOutcome(ctx.Err())
		}
		return nil, "failed"
	}
	if out.overflow {
		return nil, "report_too_large"
	}
	return validateExitReport(out.data)
}
func validateExitReport(b []byte) (json.RawMessage, string) {
	var report struct {
		Schema   int `json:"schema"`
		Identity struct {
			IPv4 string `json:"ipv4"`
			IPv6 string `json:"ipv6"`
		} `json:"identity"`
	}
	if len(b) > maxExitReport || json.Unmarshal(b, &report) != nil || report.Schema != 1 {
		return nil, "invalid_report"
	}
	if report.Identity.IPv4 != "" && (net.ParseIP(report.Identity.IPv4) == nil || net.ParseIP(report.Identity.IPv4).To4() == nil) {
		return nil, "invalid_report"
	}
	if report.Identity.IPv6 != "" && (net.ParseIP(report.Identity.IPv6) == nil || net.ParseIP(report.Identity.IPv6).To4() != nil) {
		return nil, "invalid_report"
	}
	if report.Identity.IPv4 == "" && report.Identity.IPv6 == "" {
		return json.RawMessage(b), "failed"
	}
	return json.RawMessage(b), "ok"
}

type exitBuffer struct {
	data     []byte
	overflow bool
}

func (b *exitBuffer) Write(p []byte) (int, error) {
	n := min(len(p), maxExitReport-len(b.data))
	b.data = append(b.data, p[:n]...)
	b.overflow = b.overflow || n < len(p)
	return len(p), nil
}
