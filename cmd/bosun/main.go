// Command bosun is the node agent. Managed mode only for now: it pulls its
// desired state from a panel and drives proxy cores as child processes.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"gitlab.com/boyang-hu/bosun/internal/agent"
	"gitlab.com/boyang-hu/bosun/internal/config"
	"gitlab.com/boyang-hu/bosun/internal/core"
	"gitlab.com/boyang-hu/bosun/internal/core/hysteria"
	"gitlab.com/boyang-hu/bosun/internal/core/mita"
	"gitlab.com/boyang-hu/bosun/internal/core/singbox"
	"gitlab.com/boyang-hu/bosun/internal/core/xray"
	"gitlab.com/boyang-hu/bosun/internal/coreinstall"
	"gitlab.com/boyang-hu/bosun/internal/metrics"
	"gitlab.com/boyang-hu/bosun/internal/panel"
	"gitlab.com/boyang-hu/bosun/internal/panel/xboard"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "render":
		err = cmdRender(os.Args[2:])
	case "core":
		err = cmdCore(os.Args[2:])
	case "version":
		fmt.Println("bosun", version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "bosun:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  bosun run    -c config.yaml   start the agent
  bosun render -c config.yaml   fetch state from the panel and print rendered core configs
  bosun core list    [-c config.yaml]            show known core releases and what is installed
  bosun core install [-c config.yaml] <core> [version]   install a release (default: newest tested)
  bosun version`)
}

func setup(args []string) (*config.Config, *slog.Logger, panel.Driver, *core.Registry, error) {
	fs := flag.NewFlagSet("bosun", flag.ContinueOnError)
	cfgPath := fs.String("c", "/etc/bosun/config.yaml", "config file")
	if err := fs.Parse(args); err != nil {
		return nil, nil, nil, nil, err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("log_level: %w", err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	var driver panel.Driver
	switch cfg.Panel.Driver {
	case "xboard":
		x := cfg.Panel.Xboard
		driver, err = xboard.New(xboard.Config{URL: x.URL, Token: x.Token, NodeID: x.NodeID, NodeType: x.NodeType, Timeout: x.Timeout}, log)
	default:
		err = fmt.Errorf("unknown panel driver %q", cfg.Panel.Driver)
	}
	if err != nil {
		return nil, nil, nil, nil, err
	}

	reg := core.NewRegistry()
	inst := coreinstall.New(cfg.CoresDir(), log)
	if cfg.Cores.RegistryToken != "" {
		inst.Headers = map[string]string{"Deploy-Token": cfg.Cores.RegistryToken}
	}
	// binaryFor returns an explicit path as-is, otherwise the bosun-managed
	// release, installing it on first use.
	binaryFor := func(name, explicit, version string) (string, error) {
		if explicit != "" {
			return explicit, nil
		}
		return inst.Ensure(context.Background(), name, version)
	}
	build := map[string]func() (core.Core, error){
		"singbox": func() (core.Core, error) {
			sb := cfg.Cores.Singbox
			if sb == nil {
				return nil, nil
			}
			bin, err := binaryFor("singbox", sb.Binary, sb.Version)
			if err != nil {
				return nil, err
			}
			return singbox.New(singbox.Options{
				Binary:      bin,
				WorkDir:     filepath.Join(cfg.DataDir, "singbox"),
				StatsListen: sb.StatsListen,
				LogLevel:    sb.LogLevel,
			}, log)
		},
		"xray": func() (core.Core, error) {
			xr := cfg.Cores.Xray
			if xr == nil {
				return nil, nil
			}
			bin, err := binaryFor("xray", xr.Binary, xr.Version)
			if err != nil {
				return nil, err
			}
			return xray.New(xray.Options{
				Binary:    bin,
				WorkDir:   filepath.Join(cfg.DataDir, "xray"),
				APIListen: xr.APIListen,
				LogLevel:  xr.LogLevel,
			}, log)
		},
		"hysteria": func() (core.Core, error) {
			hy := cfg.Cores.Hysteria
			if hy == nil {
				return nil, nil
			}
			bin, err := binaryFor("hysteria", hy.Binary, hy.Version)
			if err != nil {
				return nil, err
			}
			return hysteria.New(hysteria.Options{
				Binary:      bin,
				WorkDir:     filepath.Join(cfg.DataDir, "hysteria"),
				AuthListen:  hy.AuthListen,
				StatsListen: hy.StatsListen,
				LogLevel:    hy.LogLevel,
			}, log)
		},
		"mita": func() (core.Core, error) {
			mt := cfg.Cores.Mita
			if mt == nil {
				return nil, nil
			}
			bin, err := binaryFor("mita", mt.Binary, mt.Version)
			if err != nil {
				return nil, err
			}
			return mita.New(mita.Options{
				Binary:   bin,
				WorkDir:  filepath.Join(cfg.DataDir, "mita"),
				LogLevel: mt.LogLevel,
			}, log)
		},
	}
	for _, name := range cfg.CoreOrder() {
		c, err := build[name]()
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if c != nil {
			reg.Register(c)
		}
	}
	return cfg, log, driver, reg, nil
}

func cmdRun(args []string) error {
	cfg, log, driver, reg, err := setup(args)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("bosun starting", "version", version, "panel", driver.Name(), "cores", reg.Names())
	var mreg *metrics.Registry
	if cfg.MetricsListen != "" {
		mreg = metrics.NewRegistry()
		mux := http.NewServeMux()
		mux.Handle("/metrics", mreg.Handler())
		srv := &http.Server{Addr: cfg.MetricsListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("metrics server", "err", err)
			}
		}()
		defer srv.Close()
		log.Info("metrics endpoint", "listen", cfg.MetricsListen)
	}
	return agent.New(cfg, driver, reg, mreg, log).Run(ctx)
}

func cmdRender(args []string) error {
	cfg, log, driver, reg, err := setup(args)
	if err != nil {
		return err
	}
	ctx := context.Background()
	node, _, err := driver.Node(ctx)
	if err != nil {
		return err
	}
	agent.ResolveCerts(cfg, node, log)
	users, _, err := driver.Users(ctx)
	if err != nil {
		return err
	}
	assign, err := reg.Assign(node.Inbounds)
	if err != nil {
		return err
	}
	for _, name := range reg.Names() {
		if len(assign[name]) == 0 {
			continue
		}
		c, _ := reg.Get(name)
		b, err := c.Render(node, assign[name], users)
		if err != nil {
			return err
		}
		for file, content := range b.Files {
			fmt.Printf("### %s/%s\n%s\n", name, file, content)
		}
	}
	return nil
}

// cmdCore implements `bosun core list|install`. The config file is optional
// here; without it the default data dir is used.
func cmdCore(args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("core: missing subcommand")
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("bosun core", flag.ContinueOnError)
	cfgPath := fs.String("c", "/etc/bosun/config.yaml", "config file")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	rest = fs.Args()
	dataDir := "/var/lib/bosun"
	if cfg, err := config.Load(*cfgPath); err == nil {
		dataDir = cfg.DataDir
	} else if !os.IsNotExist(err) {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	inst := coreinstall.New(filepath.Join(dataDir, "cores"), log)
	if cfg, err := config.Load(*cfgPath); err == nil && cfg.Cores.RegistryToken != "" {
		inst.Headers = map[string]string{"Deploy-Token": cfg.Cores.RegistryToken}
	}

	switch sub {
	case "list":
		for _, name := range coreinstall.Cores() {
			for _, r := range coreinstall.Releases(name) {
				state := "-"
				if inst.Installed(name, r.Version) {
					state = "installed"
				}
				fmt.Printf("%-9s %-9s %-8s %-10s %s\n", name, r.Version, r.Status, state, r.Note)
			}
		}
		return nil
	case "install":
		if len(rest) == 0 {
			return fmt.Errorf("core install: <core> is required (one of %v)", coreinstall.Cores())
		}
		version := ""
		if len(rest) > 1 {
			version = rest[1]
		}
		path, err := inst.Ensure(context.Background(), rest[0], version)
		if err != nil {
			return err
		}
		fmt.Println(path)
		return nil
	}
	usage()
	return fmt.Errorf("core: unknown subcommand %q", sub)
}
