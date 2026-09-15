package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/zeptop-dev/bosun/internal/backup"
	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/doctor"
	"github.com/zeptop-dev/bosun/internal/local"
	"github.com/zeptop-dev/bosun/internal/sysinfo"
)

// cmdDoctor runs the self-check outside the service: it sees the local
// state file and the host, not the cores this process does not run, so
// core checks are skipped; listeners, certificates, ports, firewall, disk
// and clock are checked for real.
func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("bosun doctor", flag.ContinueOnError)
	cfgPath := fs.String("c", "/etc/bosun/config.yaml", "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	deps := doctor.Deps{}
	if cfg.Web != nil {
		if _, err := os.Stat(cfg.Web.StateFile); err == nil {
			store, _, err := local.Open(cfg.Web.StateFile, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
			if err != nil {
				return err
			}
			if node, _, err := store.Node(context.Background()); err == nil {
				deps.Node = node
			}
			for _, f := range store.ListForwards() {
				deps.Forwards = append(deps.Forwards, doctor.ForwardState{Tag: f.Tag, Protocol: f.Protocol, Listen: f.Listen, Port: f.Port, Target: f.Target, Up: true})
			}
			for _, c := range store.ListCertificates() {
				deps.Certs = append(deps.Certs, doctor.CertState{Domain: c.Domain, NotAfter: c.NotAfter})
			}
			k := store.KomariSettings()
			deps.KomariEnabled = k.Enabled
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	deps.Host = sysinfo.Snapshot(ctx)
	rep := doctor.Run(ctx, deps)
	for _, c := range rep.Checks {
		fmt.Printf("%-5s %-32s %s\n", strings.ToUpper(c.Status), c.Name, c.Detail)
	}
	fmt.Printf("ok %d  warn %d  fail %d  skip %d\n", rep.Summary.OK, rep.Summary.Warn, rep.Summary.Fail, rep.Summary.Skip)
	if rep.Failed() {
		return errors.New("doctor: checks failed")
	}
	return nil
}

// cmdBackup archives or restores the standalone configuration.
func cmdBackup(args []string) error {
	if len(args) == 0 || (args[0] != "create" && args[0] != "restore") {
		usage()
		return fmt.Errorf("backup: unknown subcommand")
	}
	fs := flag.NewFlagSet("bosun backup", flag.ContinueOnError)
	cfgPath := fs.String("c", "/etc/bosun/config.yaml", "config file")
	out := fs.String("o", "", "output file (create)")
	force := fs.Bool("force", false, "restore even if the service seems to be running")
	passphrase := fs.String("passphrase", "", "encrypt the archive (create) or decrypt it (restore) with this passphrase")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.Web == nil {
		return errors.New("backup: no standalone panel configured (web section missing)")
	}
	dataDir := filepath.Dir(cfg.Web.StateFile)
	switch args[0] {
	case "create":
		name := *out
		if name == "" {
			name = backup.Name(time.Now())
		}
		f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		if *passphrase != "" {
			var buf bytes.Buffer
			if err := backup.Write(dataDir, &buf); err != nil {
				f.Close()
				return err
			}
			if err := backup.Seal(f, buf.Bytes(), *passphrase); err != nil {
				f.Close()
				return err
			}
		} else if err := backup.Write(dataDir, f); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		fmt.Println(name)
		return nil
	default:
		if fs.NArg() != 1 {
			return errors.New("backup restore: archive path required")
		}
		if !*force && serviceRunning() {
			return errors.New("backup restore: bosun seems to be running; stop it first (systemctl stop bosun) or pass --force")
		}
		f, err := os.Open(fs.Arg(0))
		if err != nil {
			return err
		}
		defer f.Close()
		sum, _, err := backup.Restore(dataDir, f, "", *passphrase)
		if err != nil {
			return err
		}
		fmt.Printf("restored: %d inbounds, %d users, %d forwards, %d ingresses\nrestart bosun to apply\n", sum.Inbounds, sum.Users, sum.Forwards, sum.Ingresses)
		return nil
	}
}

// serviceRunning is a best-effort look at systemd (or OpenRC on Alpine).
func serviceRunning() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		if _, err := exec.LookPath("rc-service"); err == nil {
			out, _ := exec.Command("rc-service", "bosun", "status").CombinedOutput()
			return strings.Contains(string(out), "started")
		}
		return false
	}
	out, err := exec.Command("systemctl", "is-active", "bosun").Output()
	return err == nil && strings.TrimSpace(string(out)) == "active"
}
