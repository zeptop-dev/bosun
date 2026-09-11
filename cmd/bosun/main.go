// Command bosun is the node agent. Managed mode only for now: it pulls its
// desired state from a panel and drives proxy cores as child processes.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"gitlab.com/zeptop-group/bosun/internal/agent"
	"gitlab.com/zeptop-group/bosun/internal/config"
	"gitlab.com/zeptop-group/bosun/internal/core"
	"gitlab.com/zeptop-group/bosun/internal/core/mita"
	"gitlab.com/zeptop-group/bosun/internal/core/singbox"
	"gitlab.com/zeptop-group/bosun/internal/core/xray"
	"gitlab.com/zeptop-group/bosun/internal/panel"
	"gitlab.com/zeptop-group/bosun/internal/panel/xboard"
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
	build := map[string]func() (core.Core, error){
		"singbox": func() (core.Core, error) {
			sb := cfg.Cores.Singbox
			if sb == nil {
				return nil, nil
			}
			return singbox.New(singbox.Options{
				Binary:      sb.Binary,
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
			return xray.New(xray.Options{
				Binary:    xr.Binary,
				WorkDir:   filepath.Join(cfg.DataDir, "xray"),
				APIListen: xr.APIListen,
				LogLevel:  xr.LogLevel,
			}, log)
		},
		"mita": func() (core.Core, error) {
			mt := cfg.Cores.Mita
			if mt == nil {
				return nil, nil
			}
			return mita.New(mita.Options{
				Binary:   mt.Binary,
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
	return agent.New(cfg, driver, reg, log).Run(ctx)
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
