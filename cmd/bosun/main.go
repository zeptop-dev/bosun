// Command bosun is the node agent. It drives proxy cores as child processes
// from desired state that comes either from its own web panel (local mode)
// or from a management panel (managed mode).
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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/zeptop-dev/bosun/internal/agent"
	"github.com/zeptop-dev/bosun/internal/authutil"
	"github.com/zeptop-dev/bosun/internal/certs"
	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/core/hysteria"
	"github.com/zeptop-dev/bosun/internal/core/mita"
	"github.com/zeptop-dev/bosun/internal/core/singbox"
	"github.com/zeptop-dev/bosun/internal/core/xray"
	"github.com/zeptop-dev/bosun/internal/coreinstall"
	"github.com/zeptop-dev/bosun/internal/local"
	"github.com/zeptop-dev/bosun/internal/logring"
	"github.com/zeptop-dev/bosun/internal/metrics"
	"github.com/zeptop-dev/bosun/internal/panel"
	"github.com/zeptop-dev/bosun/internal/panel/captain"
	"github.com/zeptop-dev/bosun/internal/panel/xboard"
	"github.com/zeptop-dev/bosun/internal/ui"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/selfupdate"
)

// newUpdater returns the self-update client for this binary.
func newUpdater() *selfupdate.Client {
	return &selfupdate.Client{Repo: "zeptop-dev/bosun", Binary: "bosun", Version: version}
}

// upgradeHook applies a panel-requested release and restarts. In a container
// it only logs: the image has to be pulled by the operator.
func upgradeHook(log *slog.Logger, upd *selfupdate.Client) func(string) {
	return func(v string) {
		if v == version {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		got, err := upd.Apply(ctx, v)
		if err != nil {
			log.Error("panel-requested upgrade failed", "version", v, "err", err)
			return
		}
		log.Warn("upgraded on panel request; restarting", "from", version, "to", got)
		selfupdate.Restart(2 * time.Second)
	}
}

// watchUpdates logs when a newer release appears (every 6h check).
func watchUpdates(ctx context.Context, log *slog.Logger, upd *selfupdate.Client) {
	if !upd.ReleaseBuild() {
		return
	}
	upd.Watch(ctx, 6*time.Hour, func(info selfupdate.Info) {
		log.Info("a newer bosun release is available", "current", info.Current, "latest", info.Latest, "url", info.URL)
	})
}

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
	case "admin":
		err = cmdAdmin(os.Args[2:])
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
  bosun admin reset-password [-c config.yaml]   set a new random password for the local web panel
  bosun admin set [-c config.yaml] -user U -password P   set the web panel login (blank password = generated)
  bosun version`)
}

// env is everything a command needs after the config is loaded.
type env struct {
	cfg    *config.Config
	log    *slog.Logger
	logs   *logring.Ring
	driver panel.Driver // nil for driver "local"
	reg    *core.Registry
	inst   *coreinstall.Installer
}

func setup(args []string) (*env, error) {
	fs := flag.NewFlagSet("bosun", flag.ContinueOnError)
	cfgPath := fs.String("c", "/etc/bosun/config.yaml", "config file")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return nil, err
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		return nil, fmt.Errorf("log_level: %w", err)
	}
	ring := logring.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}), 500)
	log := slog.New(ring)

	var driver panel.Driver
	switch cfg.Panel.Driver {
	case "local":
	case "captain":
		cp := cfg.Panel.Captain
		driver, err = captain.New(captain.Config{URL: cp.URL, PairCode: cp.PairCode, TokenFile: cp.TokenFile, Version: version, Timeout: cp.Timeout}, log)
	case "xboard":
		x := cfg.Panel.Xboard
		driver, err = xboard.New(xboard.Config{URL: x.URL, Token: x.Token, NodeID: x.NodeID, NodeType: x.NodeType, Timeout: x.Timeout}, log)
	default:
		err = fmt.Errorf("unknown panel driver %q", cfg.Panel.Driver)
	}
	if err != nil {
		return nil, err
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
			return nil, err
		}
		if c != nil {
			reg.Register(c)
		}
	}
	return &env{cfg: cfg, log: log, logs: ring, driver: driver, reg: reg, inst: inst}, nil
}

func cmdRun(args []string) error {
	e, err := setup(args)
	if err != nil {
		return err
	}
	cfg, log := e.cfg, e.log
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("bosun starting", "version", version, "panel", cfg.Panel.Driver, "cores", e.reg.Names())
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

	upd := newUpdater()
	go watchUpdates(ctx, log, upd)

	// Certificate automation for inbounds (and the panel). Renewals restart
	// the cores through whichever agent is current.
	var current struct {
		sync.Mutex
		ag *agent.Agent
	}
	cm, err := certs.New(certs.Options{Dir: filepath.Join(cfg.DataDir, "certs"), Log: log, OnChange: func(domain string) {
		current.Lock()
		ag := current.ag
		current.Unlock()
		if ag != nil {
			ag.ReloadCerts(domain)
		}
	}})
	if err != nil {
		return err
	}
	defer cm.Stop()

	// Headless managed mode without a web panel: the original single agent.
	if e.driver != nil && cfg.Web == nil {
		ag := agent.New(cfg, e.driver, e.reg, mreg, log)
		ag.Version = version
		ag.Upgrade = upgradeHook(log, upd)
		ag.Certs = cm
		current.ag = ag
		return ag.Run(ctx)
	}

	store, initialPassword, err := local.Open(cfg.Web.StateFile, log)
	if err != nil {
		return err
	}
	if initialPassword != "" {
		log.Warn("web panel login created; change it after signing in", "username", "admin", "password", initialPassword)
	}
	settings := store.Settings()
	panelTLS := cfg.Web.Cert != "" || settings.PanelDomain != ""
	sup := &supervisor{cfg: cfg, log: log, reg: e.reg, mreg: mreg, store: store, fixed: e.driver, upgrade: upgradeHook(log, upd), certs: cm,
		onAgent: func(ag *agent.Agent) { current.Lock(); current.ag = ag; current.Unlock() }}
	panelUI := ui.New(ui.Deps{
		Store: store, Version: version, Log: log, Logs: e.logs, Install: e.inst,
		Fixed: fixedName(e.driver), Adopt: sup.adopt, Detach: sup.detach, ManagedState: sup.managedState,
		Secure: panelTLS, Updater: upd, Certs: cm,
	})
	sup.ui = panelUI
	srv := &http.Server{Addr: cfg.Web.Listen, Handler: panelUI.Handler(), ReadHeaderTimeout: 10 * time.Second}
	if cfg.Web.Cert == "" && settings.PanelDomain != "" {
		// Automatic certificate for the panel itself. Obtained in the
		// background so a failed challenge does not block startup; until
		// then TLS handshakes fail and the log says why.
		cm.Configure(settings.ACMEEmail, settings.CloudflareToken)
		srv.TLSConfig = cm.TLSConfig()
		go func() {
			if _, _, err := cm.Ensure(ctx, settings.PanelDomain, settings.PanelACME); err != nil {
				log.Error("panel certificate", "domain", settings.PanelDomain, "err", err)
			}
		}()
	}
	go func() {
		var err error
		switch {
		case cfg.Web.Cert != "":
			err = srv.ListenAndServeTLS(cfg.Web.Cert, cfg.Web.Key)
		case settings.PanelDomain != "":
			err = srv.ListenAndServeTLS("", "")
		default:
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Error("web panel", "err", err)
		}
	}()
	defer srv.Close()
	log.Info("web panel", "listen", cfg.Web.Listen, "tls", panelTLS, "domain", settings.PanelDomain)
	return sup.run(ctx)
}

func fixedName(d panel.Driver) string {
	if d == nil {
		return ""
	}
	return d.Name()
}

// supervisor runs one agent at a time and restarts it on the other driver
// when the local store flips between local and managed mode.
type supervisor struct {
	cfg   *config.Config
	log   *slog.Logger
	reg   *core.Registry
	mreg  *metrics.Registry
	store *local.Store
	fixed panel.Driver // config-pinned headless driver, or nil
	ui    *ui.Server
	// upgrade handles a panel-requested release change.
	upgrade func(string)
	certs   *certs.Manager
	onAgent func(*agent.Agent)

	mu      sync.Mutex
	captain *captain.Client // current managed driver, when any
}

func (s *supervisor) tokenFile() string {
	if s.cfg.Panel.Captain != nil && s.cfg.Panel.Captain.TokenFile != "" {
		return s.cfg.Panel.Captain.TokenFile
	}
	return filepath.Join(s.cfg.DataDir, "captain.token")
}

// driver picks the driver for the current mode.
func (s *supervisor) driver() (panel.Driver, error) {
	if s.fixed != nil {
		return s.fixed, nil
	}
	mode, managed, _ := s.store.Mode()
	if mode == local.ModeManaged && managed != nil {
		c, err := captain.New(captain.Config{URL: managed.URL, TokenFile: s.tokenFile(), Version: version}, s.log)
		if err != nil {
			// Token gone: nothing to be managed by. Fall back to local mode
			// so the node stays operable.
			s.log.Error("managed mode has no token; returning to local mode", "err", err)
			_ = s.store.Detach(nil)
			return s.store, nil
		}
		s.mu.Lock()
		s.captain = c
		s.mu.Unlock()
		return c, nil
	}
	s.mu.Lock()
	s.captain = nil
	s.mu.Unlock()
	return s.store, nil
}

func (s *supervisor) run(ctx context.Context) error {
	for {
		d, err := s.driver()
		if err != nil {
			return err
		}
		if s.mreg != nil {
			s.mreg.Reset()
		}
		ag := agent.New(s.cfg, d, s.reg, s.mreg, s.log)
		ag.Upgrade = s.upgrade
		ag.Certs = s.certs
		if s.onAgent != nil {
			s.onAgent(ag)
		}
		s.ui.SetAgent(ag)
		actx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- ag.Run(actx) }()
		s.log.Info("agent started", "panel", d.Name())
		select {
		case <-ctx.Done():
			cancel()
			<-done
			return nil
		case m := <-s.store.ModeChanges():
			s.log.Info("mode changed; restarting agent", "mode", m)
			cancel()
			<-done
		case err := <-done:
			cancel()
			if ctx.Err() != nil {
				return nil
			}
			s.log.Error("agent stopped; restarting in 5s", "err", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(5 * time.Second):
			}
		}
	}
}

// adopt pairs with Captain first so a bad code fails before anything moves,
// then flips the store; run() notices and restarts the agent.
func (s *supervisor) adopt(ctx context.Context, url, pairCode string) error {
	tf := s.tokenFile()
	_ = os.Remove(tf)
	c, err := captain.New(captain.Config{URL: url, PairCode: pairCode, TokenFile: tf, Version: version}, s.log)
	if err != nil {
		return err
	}
	if err := c.Pair(ctx); err != nil {
		return err
	}
	return s.store.Adopt(url)
}

func (s *supervisor) managedState() *agentproto.State {
	s.mu.Lock()
	c := s.captain
	s.mu.Unlock()
	if c == nil {
		return nil
	}
	return c.State()
}

func (s *supervisor) detach(ctx context.Context, keep bool) error {
	var st *agentproto.State
	if keep {
		st = s.managedState()
		if st == nil {
			return fmt.Errorf("no panel state received yet; detach without keeping, or wait for the first pull")
		}
	}
	if err := s.store.Detach(st); err != nil {
		return err
	}
	_ = os.Remove(s.tokenFile())
	return nil
}

func cmdRender(args []string) error {
	e, err := setup(args)
	if err != nil {
		return err
	}
	cfg, log, driver, reg := e.cfg, e.log, e.driver, e.reg
	if driver == nil {
		store, _, err := local.Open(cfg.Web.StateFile, log)
		if err != nil {
			return err
		}
		driver = store
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

// cmdAdmin implements `bosun admin reset-password` (a way back in when the
// web panel password is lost) and `bosun admin set -user U -password P`
// (the installer's way to seed the login before the first start).
func cmdAdmin(args []string) error {
	if len(args) == 0 || (args[0] != "reset-password" && args[0] != "set") {
		usage()
		return fmt.Errorf("admin: unknown subcommand")
	}
	fs := flag.NewFlagSet("bosun admin", flag.ContinueOnError)
	cfgPath := fs.String("c", "/etc/bosun/config.yaml", "config file")
	user := fs.String("user", "", "panel username (set)")
	password := fs.String("password", "", "panel password (set; blank = generate)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.Web == nil {
		return fmt.Errorf("admin: no web panel configured")
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	store, initial, err := local.Open(cfg.Web.StateFile, log)
	if err != nil {
		return err
	}
	if args[0] == "set" {
		name := strings.TrimSpace(*user)
		if name == "" {
			name = store.Username()
		}
		pw := *password
		if pw == "" {
			pw = authutil.Password(16)
		}
		if err := store.SetAdmin(name, pw); err != nil {
			return err
		}
		fmt.Printf("username: %s\npassword: %s\n", name, pw)
		return nil
	}
	if initial == "" {
		initial = authutil.Password(16)
		if err := store.SetAdmin(store.Username(), initial); err != nil {
			return err
		}
	}
	fmt.Printf("username: %s\npassword: %s\n", store.Username(), initial)
	fmt.Println("restart bosun if it is running so the new password is loaded")
	return nil
}
