// Package removal retires a standard installer-managed node from a worker
// outside its service. Captain retains the node until this worker reports the
// result; stopping bosun must never be mistaken for a completed uninstall.
package removal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/firewall"
	"github.com/zeptop-dev/bosun/internal/local"
	"github.com/zeptop-dev/bosun/internal/shaper"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"gopkg.in/yaml.v3"
)

const Kind = "node_remove"
const configPath = "/etc/bosun/config.yaml"
const dataDir = "/var/lib/bosun"
const binaryPath = "/usr/local/bin/bosun"

type Params struct {
	Mode      string `json:"mode"`
	KeepData  bool   `json:"keep_data"`
	ExpiresAt int64  `json:"expires_at"`
}
type Plan struct {
	ID     string            `json:"id"`
	Params Params            `json:"params"`
	URL    string            `json:"url"`
	Token  string            `json:"token"`
	Init   string            `json:"init"`
	State  *agentproto.State `json:"state,omitempty"`
}
type Result struct {
	ID         string `json:"id"`
	Phase      string `json:"phase"`
	Error      string `json:"error,omitempty"`
	Listen     string `json:"listen,omitempty"`
	LoginSetup bool   `json:"login_setup,omitempty"`
}

func validate(p Plan, at time.Time) error {
	if !spec.ValidTag(p.ID) || len(p.ID) > 80 {
		return errors.New("invalid removal job ID")
	}
	if p.Params.Mode != "standalone" && p.Params.Mode != "uninstall" {
		return errors.New("unknown removal mode")
	}
	if p.Params.ExpiresAt <= at.Unix() {
		return errors.New("removal request expired")
	}
	if p.Params.Mode == "standalone" && p.State == nil {
		return errors.New("no Captain configuration has been received")
	}
	if p.URL == "" || p.Token == "" {
		return errors.New("Captain connection is unavailable")
	}
	return nil
}

// Start copies the executable into a private staging directory before asking
// the init system to launch it. No downloaded script or panel-supplied command
// is executed. Paths and service names are deliberately fixed.
func Start(ctx context.Context, cfgPath string, cfg *config.Config, p Plan) error {
	if err := validate(p, time.Now()); err != nil {
		return err
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("remote removal requires a root Linux installation")
	}
	if os.Getenv("BOSUN_CAPTAIN") != "" {
		return errors.New("container installations must be managed on the host")
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return errors.New("container installations must be managed on the host")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if filepath.Clean(cfgPath) != configPath || filepath.Clean(cfg.DataDir) != dataDir || exe != binaryPath {
		return errors.New("remote removal requires the standard bosun installer paths")
	}
	if cfg.Panel.Captain != nil && cfg.Panel.Captain.TokenFile != filepath.Join(dataDir, "captain.token") {
		return errors.New("remote removal requires the standard Captain token path")
	}
	if cfg.Web != nil && cfg.Web.StateFile != filepath.Join(dataDir, "local.json") {
		return errors.New("remote removal requires the standard local state path")
	}
	for _, path := range []string{"/etc", "/var", "/var/lib", "/usr", "/usr/local", "/usr/local/bin", configPath, filepath.Dir(configPath), dataDir, binaryPath} {
		if err := privateOwned(path); err != nil {
			return err
		}
	}
	for _, path := range []string{filepath.Join(dataDir, "local.json"), filepath.Join(dataDir, "captain.token")} {
		if err := privateOwned(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		if _, err := exec.LookPath("systemd-run"); err != nil {
			return errors.New("systemd-run is required for remote removal")
		}
		p.Init = "systemd"
	} else if _, err := os.Stat("/run/openrc"); err == nil {
		p.Init = "openrc"
	} else {
		return errors.New("remote removal requires systemd or OpenRC")
	}
	dir := filepath.Join("/var/tmp", "bosun-removal-"+p.ID)
	if err := os.Mkdir(dir, 0700); err != nil {
		if os.IsExist(err) {
			// A restarted agent can receive the same pending job again while
			// the independent worker is still active. Do not fail that job.
			return privateOwned(dir)
		}
		return err
	}
	launched := false
	defer func() {
		if !launched {
			_ = os.RemoveAll(dir)
		}
	}()
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := writeNew(filepath.Join(dir, "plan.json"), raw, 0600); err != nil {
		return err
	}
	executable, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	worker := filepath.Join(dir, "worker")
	if err := writeNew(worker, executable, 0700); err != nil {
		return err
	}
	// Once launch is attempted, leave the stage available even if the parent
	// is stopped before systemd-run returns. The worker may already be alive.
	launched = true
	launchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if p.Init == "systemd" {
		cmd := exec.CommandContext(launchCtx, "systemd-run", "--quiet", "--collect", "--unit=bosun-removal-"+p.ID, "--property=Type=exec", worker, "internal-node-removal", filepath.Join(dir, "plan.json"))
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("start removal worker: %w", err)
		}
	} else {
		if err := launchDetached(worker, filepath.Join(dir, "plan.json")); err != nil {
			return err
		}
	}
	launched = true
	return nil
}

func writeNew(path string, raw []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Run is only entered by the staged worker. Its plan contains credentials and
// is never logged. A completed result is saved before delivery so replaying
// the worker only retries the callback, never the destructive operation.
func Run(path string) error {
	if os.Geteuid() != 0 || runtime.GOOS != "linux" {
		return errors.New("removal worker requires root on Linux")
	}
	if err := privateOwned(filepath.Dir(path)); err != nil {
		return err
	}
	if err := privateOwned(path); err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var p Plan
	if err := json.Unmarshal(raw, &p); err != nil {
		return errors.New("invalid removal plan")
	}
	if filepath.Dir(path) != filepath.Join("/var/tmp", "bosun-removal-"+p.ID) || filepath.Base(path) != "plan.json" {
		return errors.New("invalid removal staging path")
	}
	if p.Init != "systemd" && p.Init != "openrc" {
		return errors.New("invalid service manager")
	}
	lock := filepath.Join(filepath.Dir(path), "running.lock")
	if err := writeNew(lock, nil, 0600); err != nil {
		return errors.New("removal worker is already running; check its service before retrying")
	}
	defer os.Remove(lock)
	resultPath := filepath.Join(filepath.Dir(path), "result.json")
	result := Result{ID: p.ID, Phase: "complete"}
	if b, err := os.ReadFile(resultPath); err == nil {
		if json.Unmarshal(b, &result) != nil {
			return errors.New("invalid saved removal result")
		}
	} else if !os.IsNotExist(err) {
		return err
	} else {
		if err := validate(p, time.Now()); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		err := notify(ctx, p, Result{ID: p.ID, Phase: "running"})
		cancel()
		if err != nil {
			return err
		} // No successful claim, no machine changes.
		ctx, cancel = context.WithTimeout(context.Background(), 3*time.Minute)
		result.Listen, result.LoginSetup, err = execute(ctx, p, execCommand, standardPaths(), cleanNetwork, waitListening)
		cancel()
		if err != nil {
			result.Error = err.Error()
		}
		raw, _ := json.Marshal(result)
		if err := writeNew(resultPath, raw, 0600); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	for {
		if err := notify(ctx, p, result); err == nil {
			return os.RemoveAll(filepath.Dir(path))
		}
		select {
		case <-ctx.Done():
			return errors.New("could not deliver removal result; staged result retained for retry")
		case <-time.After(5 * time.Second):
		}
	}
}

type command func(context.Context, string, ...string) error

func execCommand(ctx context.Context, name string, args ...string) error {
	if err := exec.CommandContext(ctx, name, args...).Run(); err != nil {
		return fmt.Errorf("%s failed: %w", name, err)
	}
	return nil
}

type installation struct{ config, data, binary, systemd, openrc string }

func standardPaths() installation {
	return installation{configPath, dataDir, binaryPath, "/etc/systemd/system/bosun.service", "/etc/init.d/bosun"}
}

func execute(ctx context.Context, p Plan, run command, paths installation, cleanup func(context.Context, installation) error, ready func(context.Context, string) error) (listen string, login bool, err error) {
	var restore func() error
	if p.Params.Mode == "standalone" {
		restore, err = backupStandalone(paths)
		if err != nil {
			return "", false, err
		}
	}
	stop := func() error {
		if p.Init == "systemd" {
			return run(ctx, "systemctl", "stop", "bosun")
		}
		return run(ctx, "rc-service", "bosun", "stop")
	}
	start := func() error {
		if p.Init == "systemd" {
			return run(ctx, "systemctl", "start", "bosun")
		}
		return run(ctx, "rc-service", "bosun", "start")
	}
	if err = stop(); err != nil {
		return "", false, err
	}
	if p.Params.Mode == "standalone" {
		defer func() {
			if err != nil {
				// Restore both configuration and credentials before bringing the
				// original managed service back after a failed conversion.
				recoveryCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				// Even a failed start may have left a partial process alive.
				if p.Init == "systemd" {
					_ = run(recoveryCtx, "systemctl", "stop", "bosun")
				} else {
					_ = run(recoveryCtx, "rc-service", "bosun", "stop")
				}
				if restoreErr := restore(); restoreErr != nil {
					err = fmt.Errorf("conversion failed and rollback failed: %w", restoreErr)
					return
				}
				var restartErr error
				if p.Init == "systemd" {
					restartErr = run(recoveryCtx, "systemctl", "start", "bosun")
				} else {
					restartErr = run(recoveryCtx, "rc-service", "bosun", "start")
				}
				if restartErr != nil {
					err = fmt.Errorf("configuration restored, but service restart failed: %w", restartErr)
				}
			}
		}()
		// After the old process stops, the panel address must be available.
		cfg, loadErr := config.Load(paths.config)
		if loadErr != nil {
			return "", false, loadErr
		}
		addr := "127.0.0.1:2053"
		if cfg.Web != nil {
			addr = cfg.Web.Listen
		}
		ln, listenErr := net.Listen("tcp", addr)
		if listenErr != nil {
			return "", false, errors.New("standalone panel listen address is unavailable")
		}
		_ = ln.Close()
		listen, login, err = standalone(p.State, paths)
		if err == nil {
			err = start()
		}
		if err == nil {
			err = ready(ctx, listen)
		}
		if err == nil {
			if p.Init == "systemd" {
				err = run(ctx, "systemctl", "is-active", "--quiet", "bosun")
			} else {
				err = run(ctx, "rc-service", "bosun", "status")
			}
		}
		return
	}
	if err = cleanup(ctx, paths); err != nil {
		return "", false, err
	}
	if p.Init == "systemd" {
		if err = run(ctx, "systemctl", "disable", "bosun"); err != nil {
			return
		}
		if err = os.Remove(paths.systemd); err != nil && !os.IsNotExist(err) {
			return
		}
		if err = run(ctx, "systemctl", "daemon-reload"); err != nil {
			return
		}
	} else {
		if err = run(ctx, "rc-update", "del", "bosun", "default"); err != nil {
			return
		}
		if err = os.Remove(paths.openrc); err != nil && !os.IsNotExist(err) {
			return
		}
	}
	remove := []string{paths.binary, paths.binary + ".backup", paths.binary + ".backup.version", filepath.Dir(paths.config)}
	if !p.Params.KeepData {
		remove = append(remove, paths.data)
	}
	for _, path := range remove {
		if err = os.RemoveAll(path); err != nil {
			return
		}
	}
	return "", false, nil
}

func cleanNetwork(ctx context.Context, paths installation) error {
	// These helpers know which qdisc/classes and firewall openings belong to
	// bosun. Unrelated host firewall and shaping configuration stays intact.
	if err := (&shaper.Shaper{}).Apply(ctx, nil); err != nil {
		return err
	}
	if err := (&firewall.Manager{StateFile: filepath.Join(paths.data, "firewall.json")}).Apply(ctx, nil); err != nil {
		return err
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return nil
	}
	for _, table := range []string{"bosun_fwd", "bosun_ingress", "bosun_egress", "bosun_shaper"} {
		// Create-if-absent followed by delete avoids mistaking an absent table
		// for a permission failure. Table names are fixed, never panel input.
		cmd := exec.CommandContext(ctx, "nft", "-f", "-")
		cmd.Stdin = strings.NewReader("table inet " + table + "\ndelete table inet " + table + "\n")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("remove bosun network rules: %w", err)
		}
	}
	return nil
}

func backupStandalone(paths installation) (func() error, error) {
	cfg, err := config.Load(paths.config)
	if err != nil {
		return nil, err
	}
	state := filepath.Join(paths.data, "local.json")
	if cfg.Web != nil {
		state = cfg.Web.StateFile
	}
	saved := map[string][]byte{}
	for _, path := range []string{paths.config, state, filepath.Join(paths.data, "captain.token")} {
		raw, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if os.IsNotExist(err) {
			saved[path] = nil
		} else {
			saved[path] = raw
		}
	}
	return func() error {
		for path, raw := range saved {
			if raw == nil {
				if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
					return err
				}
				continue
			}
			if err := atomicWrite(path, raw); err != nil {
				return err
			}
		}
		return nil
	}, nil
}

func atomicWrite(path string, raw []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".bosun-removal-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func standalone(st *agentproto.State, paths installation) (string, bool, error) {
	cfg, err := config.Load(paths.config)
	if err != nil {
		return "", false, err
	}
	if cfg.Web == nil {
		cfg.Web = &config.Web{Listen: "127.0.0.1:2053", StateFile: filepath.Join(paths.data, "local.json")}
	}
	cfg.Panel.Driver, cfg.Panel.Captain, cfg.Panel.Xboard = "local", nil, nil
	raw, err := os.ReadFile(paths.config)
	if err != nil {
		return "", false, err
	}
	if err := writeNew(paths.config+".before-removal", raw, 0600); err != nil && !os.IsExist(err) {
		return "", false, err
	}
	s, initial, err := local.Open(cfg.Web.StateFile, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return "", false, err
	}
	if err := s.ImportManaged(st); err != nil {
		return "", false, err
	}
	raw, err = yaml.Marshal(cfg)
	if err != nil {
		return "", false, err
	}
	if err := atomicWrite(paths.config, raw); err != nil {
		return "", false, err
	}
	if err := os.Remove(filepath.Join(paths.data, "captain.token")); err != nil && !os.IsNotExist(err) {
		return "", false, err
	}
	return cfg.Web.Listen, initial != "", nil
}

func notify(ctx context.Context, p Plan, result Result) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(p.URL, "/")+"/api/agent/removal", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return errors.New("Captain removal callback failed")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("Captain removal callback returned HTTP %d", res.StatusCode)
	}
	return nil
}

// Readiness includes the standalone UI listener: the service can stay alive
// after ListenAndServe fails, so an init-system status alone is insufficient.
func waitListening(ctx context.Context, addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return errors.New("invalid standalone panel listen address")
	}
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if host == "::" {
		host = "::1"
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		c, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if err == nil {
			c.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("standalone panel did not start; restoring managed configuration")
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// CleanNetwork is used by the host installer after the service/container stops.
// It uses persisted ownership records and leaves unrelated host rules intact.
func CleanNetwork(ctx context.Context, data string) error {
	paths := standardPaths()
	paths.data = data
	return cleanNetwork(ctx, paths)
}
