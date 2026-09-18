// Command bosun is the node agent. It drives proxy cores as child processes
// from desired state that comes either from its own web panel (local mode)
// or from a management panel (managed mode).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/zeptop-dev/bosun/internal/audit"

	"github.com/zeptop-dev/bosun/internal/connlog"

	"github.com/zeptop-dev/bosun/internal/egressguard"
	"github.com/zeptop-dev/bosun/internal/runas"

	"github.com/zeptop-dev/bosun/internal/agent"
	"github.com/zeptop-dev/bosun/internal/authutil"
	"github.com/zeptop-dev/bosun/internal/certs"
	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/core/hysteria"
	"github.com/zeptop-dev/bosun/internal/core/mita"
	"github.com/zeptop-dev/bosun/internal/core/singbox"
	"github.com/zeptop-dev/bosun/internal/core/snell"
	"github.com/zeptop-dev/bosun/internal/core/xray"
	"github.com/zeptop-dev/bosun/internal/coreinstall"
	"github.com/zeptop-dev/bosun/internal/decoy"
	"github.com/zeptop-dev/bosun/internal/firewall"
	"github.com/zeptop-dev/bosun/internal/forward"
	"github.com/zeptop-dev/bosun/internal/ingressguard"
	"github.com/zeptop-dev/bosun/internal/local"
	"github.com/zeptop-dev/bosun/internal/logring"
	"github.com/zeptop-dev/bosun/internal/metrics"
	"github.com/zeptop-dev/bosun/internal/panel"
	"github.com/zeptop-dev/bosun/internal/panel/captain"
	"github.com/zeptop-dev/bosun/internal/panel/xboard"
	"github.com/zeptop-dev/bosun/internal/shaper"
	"github.com/zeptop-dev/bosun/internal/telegram"
	"github.com/zeptop-dev/bosun/internal/ui"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/selfupdate"
)

// newUpdater returns the self-update client for this binary. minVersion
// (config min_version) is the floor no update or rollback may go below.
func newUpdater(minVersion string) *selfupdate.Client {
	return &selfupdate.Client{Repo: "zeptop-dev/bosun", Binary: "bosun", Version: version, MinVersion: minVersion}
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
	case "doctor":
		err = cmdDoctor(os.Args[2:])
	case "backup":
		err = cmdBackup(os.Args[2:])
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
  bosun doctor [-c config.yaml]                  read-only health checks (listeners, certs, disk, firewall); exit 1 on failure
  bosun backup create [-c config.yaml] [-o FILE]  archive the standalone configuration (default: bosun-backup-<date>.tar.gz)
  bosun backup restore [-c config.yaml] [--force] FILE   replace it from an archive (service must be stopped)
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
	conns  *connlog.Collector
	audits *audit.Collector
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

	if err := runas.Set(cfg.Cores.User); err != nil {
		// Degrade instead of refusing to start: a node whose agent will
		// not run cannot be fixed from the panel either. The doctor's
		// isolation check reports it.
		log.Error("cores.user unusable, running cores as bosun itself", "user", cfg.Cores.User, "err", err)
		runas.SetError(err.Error())
	} else if cfg.Cores.User != "" {
		log.Info("cores run as an unprivileged account", "user", cfg.Cores.User)
	}
	reg := core.NewRegistry()
	conns := &connlog.Collector{}
	audits := &audit.Collector{}
	// One log feed serves the connection log and the audit matcher.
	sink := func(user, clientIP, host string, port int, network string) {
		conns.Add(user, clientIP, host, port, network)
		audits.Check(user, clientIP, host, port, network)
	}
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
				ConnSink:    sink,
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
				ConnSink:  sink,
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
				ConnSink:    sink,
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
		"snell": func() (core.Core, error) {
			sn := cfg.Cores.Snell
			if sn == nil {
				return nil, nil
			}
			bin, err := binaryFor("snell", sn.Binary, sn.Version)
			if err != nil {
				return nil, err
			}
			return snell.New(snell.Options{Binary: bin, WorkDir: filepath.Join(cfg.DataDir, "snell")}, log)
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
	return &env{cfg: cfg, log: log, logs: ring, driver: driver, reg: reg, inst: inst, conns: conns, audits: audits}, nil
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

	upd := newUpdater(cfg.MinVersion)
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
	dc := decoy.New(cm, log)
	defer dc.Stop()
	shp := &shaper.Shaper{}
	guard := &ingressguard.Guard{}
	var fw *firewall.Manager
	var extraPorts []firewall.Port
	if cfg.FirewallAutoOpenEnabled() {
		fw = &firewall.Manager{StateFile: filepath.Join(cfg.DataDir, "firewall.json")}
		if cfg.Web != nil {
			if _, p, err := net.SplitHostPort(cfg.Web.Listen); err == nil {
				if n, err := strconv.Atoi(p); err == nil && n > 0 {
					extraPorts = append(extraPorts, firewall.Port{Proto: "tcp", Port: n})
				}
			}
		}
	}

	// Headless managed mode without a web panel: the original single agent.
	if e.driver != nil && cfg.Web == nil {
		ag := agent.New(cfg, e.driver, e.reg, mreg, log)
		ag.Version = version
		ag.Upgrade = upgradeHook(log, upd)
		if upd.ReleaseBuild() {
			ag.Rollback = upd.Rollback
		}
		ag.Certs = cm
		ag.Decoy = dc
		ag.Shaper = shp
		ag.Realm = &forward.Realm{Binary: func(ctx context.Context) (string, error) { return e.inst.Ensure(ctx, "realm", "") }, Dir: filepath.Join(cfg.DataDir, "realm"), Log: log}
		ag.Guard = guard
		ag.Conn = e.conns
		ag.Audit = e.audits
		if cfg.EgressGuardOn() {
			ag.Egress, ag.EgressAllow = &egressguard.Guard{}, cfg.Cores.EgressAllow
			ag.EgressLoopbackPorts = loopbackPorts(cfg)
			ag.EgressProtectedPorts = controlPorts(cfg)
		}
		ag.Firewall, ag.ExtraPorts = fw, extraPorts
		current.ag = ag
		return ag.Run(ctx)
	}

	store, initialPassword, err := local.Open(cfg.Web.StateFile, log)
	if err != nil {
		return err
	}
	if initialPassword != "" {
		// Printed, not logged: the log ring is readable from the panel and
		// journald keeps it forever.
		fmt.Fprintf(os.Stderr, "web panel login created: username admin, password %s (change it after signing in)\n", initialPassword)
		log.Warn("web panel login created; the password was printed on stderr at first start")
	}
	settings := store.Settings()
	panelTLS := cfg.Web.Cert != "" || settings.PanelDomain != ""
	for _, c := range cfg.Web.TrustedProxies {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil {
			ui.TrustedProxies = append(ui.TrustedProxies, n)
		} else if ip := net.ParseIP(strings.TrimSpace(c)); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			ui.TrustedProxies = append(ui.TrustedProxies, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	if !panelTLS {
		if host, _, err := net.SplitHostPort(cfg.Web.Listen); err == nil && host != "127.0.0.1" && host != "localhost" && host != "::1" {
			log.Warn("web panel serves plain HTTP on a non-loopback address; set a panel domain (Settings) or web.cert/key, or bind 127.0.0.1 behind a reverse proxy", "listen", cfg.Web.Listen)
		}
	}
	bot := &telegram.Bot{Log: log, Settings: func() telegram.Settings {
		st := store.Settings()
		return telegram.Settings{Token: st.TelegramToken, ChatID: st.TelegramChatID, Notify: st.TelegramNotify}
	}}
	sup := &supervisor{cfg: cfg, log: log, reg: e.reg, inst: e.inst, guard: guard, conns: e.conns, audits: e.audits, firewall: fw, extraPorts: extraPorts, mreg: mreg, store: store, fixed: e.driver, upgrade: upgradeHook(log, upd), certs: cm, decoy: dc, bot: bot, shaper: shp,
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
	inst  *coreinstall.Installer
	mreg  *metrics.Registry
	store *local.Store
	fixed panel.Driver // config-pinned headless driver, or nil
	ui    *ui.Server
	// upgrade handles a panel-requested release change.
	upgrade    func(string)
	certs      *certs.Manager
	decoy      *decoy.Server
	bot        *telegram.Bot
	shaper     *shaper.Shaper
	guard      *ingressguard.Guard
	conns      *connlog.Collector
	audits     *audit.Collector
	firewall   *firewall.Manager
	extraPorts []firewall.Port
	onAgent    func(*agent.Agent)

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
	if s.bot != nil {
		s.bot.Status = s.telegramStatus
		go s.bot.Run(ctx)
	}
	for {
		d, err := s.driver()
		if err != nil {
			return err
		}
		if s.mreg != nil {
			s.mreg.Reset()
		}
		ag := agent.New(s.cfg, d, s.reg, s.mreg, s.log)
		ag.Version = version
		ag.Upgrade = s.upgrade
		ag.Certs = s.certs
		ag.Decoy = s.decoy
		ag.Shaper = s.shaper
		ag.Realm = &forward.Realm{Binary: func(ctx context.Context) (string, error) { return s.inst.Ensure(ctx, "realm", "") }, Dir: filepath.Join(s.cfg.DataDir, "realm"), Log: s.log}
		ag.Guard = s.guard
		ag.Conn = s.conns
		ag.Audit = s.audits
		if s.cfg.EgressGuardOn() {
			ag.Egress, ag.EgressAllow = &egressguard.Guard{}, s.cfg.Cores.EgressAllow
			ag.EgressLoopbackPorts = loopbackPorts(s.cfg)
			ag.EgressProtectedPorts = controlPorts(s.cfg)
		}
		ag.Firewall, ag.ExtraPorts = s.firewall, s.extraPorts
		ag.WARPAccount, ag.SaveWARP = s.store.WARP, s.store.SetWARP
		if s.bot != nil {
			ag.Alert = func(text string) {
				actx, done := context.WithTimeout(context.Background(), 20*time.Second)
				defer done()
				if err := s.bot.Notify(actx, text); err != nil {
					s.log.Warn("telegram alert", "err", err)
				}
			}
		}
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

// telegramStatus is the /status reply: mode, cores, users, uptime.
func (s *supervisor) telegramStatus(ctx context.Context) string {
	rt := s.store.Runtime()
	mode, _, _ := s.store.Mode()
	var b strings.Builder
	fmt.Fprintf(&b, "<b>bosun</b> %s · %s\n", version, mode)
	users := s.store.ListUsers()
	online := 0
	for _, u := range users {
		if len(rt.Online[u.UUID]) > 0 {
			online++
		}
	}
	fmt.Fprintf(&b, "users: %d (%d online) · inbounds: %d\n", len(users), online, len(s.store.Inbounds()))
	for name, c := range rt.Cores {
		state := "stopped"
		if c.Running {
			state = "running"
		}
		fmt.Fprintf(&b, "%s: %s\n", name, state)
	}
	if !rt.LastReport.IsZero() {
		fmt.Fprintf(&b, "last report: %s ago", time.Since(rt.LastReport).Round(time.Second))
	}
	return b.String()
}

// loopbackPorts lists the local ports the egress guard keeps open for the
// cores: hysteria dials bosun's auth endpoint on every new client. The
// cores' own API sockets, bosun's metrics and the web panel are left
// closed on purpose (see internal/egressguard).
// controlPorts are the cores' own API sockets: unauthenticated gRPC on
// loopback that can add users, change inbounds and reset counters. The
// egress guard keeps every local account except root away from them.
func controlPorts(cfg *config.Config) []int {
	var out []int
	add := func(addr, def string) {
		if strings.TrimSpace(addr) == "" {
			addr = def
		}
		if _, port, err := net.SplitHostPort(addr); err == nil {
			if n, err := strconv.Atoi(port); err == nil {
				out = append(out, n)
			}
		}
	}
	if cfg.Cores.Singbox != nil {
		add(cfg.Cores.Singbox.StatsListen, "127.0.0.1:9101")
	}
	if cfg.Cores.Xray != nil {
		add(cfg.Cores.Xray.APIListen, "127.0.0.1:9102")
	}
	if cfg.Cores.Hysteria != nil {
		add(cfg.Cores.Hysteria.StatsListen, "")
	}
	return out
}

func loopbackPorts(cfg *config.Config) []int {
	var out []int
	if cfg.Cores.Hysteria != nil {
		if _, port, err := net.SplitHostPort(cfg.Cores.Hysteria.AuthListen); err == nil {
			if n, err := strconv.Atoi(port); err == nil {
				out = append(out, n)
			}
		}
	}
	return out
}
