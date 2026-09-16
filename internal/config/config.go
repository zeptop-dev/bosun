// Package config loads bosun's YAML configuration file.
package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Config is the on-disk configuration.
type Config struct {
	DataDir       string `yaml:"data_dir"`
	LogLevel      string `yaml:"log_level"`
	MetricsListen string `yaml:"metrics_listen"` // Prometheus endpoint; "" disables

	Cores struct {
		// Order is the preference when several cores can serve an inbound.
		// Unlisted enabled cores follow in the default order singbox, xray, mita.
		Order []string `yaml:"order"`
		// RegistryToken authenticates downloads from bosun's own package
		// registry (CI-built sing-box) when the GitLab project is private.
		// A Deploy Token with read_package_registry is enough.
		RegistryToken string        `yaml:"registry_token"`
		// User is the unprivileged system account the cores run under
		// (created if missing); "" runs them as bosun itself. Their work
		// dirs, configs and certificates are handed to this account.
		User string `yaml:"user"`
		// EgressGuard drops new connections from the core account to
		// link-local, metadata, RFC 1918 and CGNAT ranges (nftables);
		// default on when User is set. Ranges in EgressAllow stay open.
		EgressGuard *bool    `yaml:"egress_guard"`
		EgressAllow []string `yaml:"egress_allow"`
		Singbox       *SingboxCore  `yaml:"singbox"`
		Xray          *XrayCore     `yaml:"xray"`
		Mita          *MitaCore     `yaml:"mita"`
		Hysteria      *HysteriaCore `yaml:"hysteria"`
		Snell         *SnellCore    `yaml:"snell"`
	} `yaml:"cores"`

	// Probe runs the latency checks on a node that is not managed by
	// Captain (local or Xboard driver). Under Captain the panel's probe
	// settings replace this section entirely.
	Probe *ProbeConfig `yaml:"probe"`

	Panel struct {
		// Driver is "local" (standalone; the built-in web UI owns the
		// config and can hand the node to Captain later), "captain" or
		// "xboard" (headless managed mode fixed by this file).
		Driver  string        `yaml:"driver"`
		Xboard  *XboardPanel  `yaml:"xboard"`
		Captain *CaptainPanel `yaml:"captain"`
	} `yaml:"panel"`

	// Web is the built-in panel. Required for driver "local"; optional
	// (read-only diagnostics) for the headless drivers.
	Web *Web `yaml:"web"`

	// Certs maps server names to local certificate files for TLSStandard inbounds.
	Certs []Cert `yaml:"certs"`

	// Forwards are local relay rules, used when the panel does not manage
	// forwarding (Xboard). A panel that does supplies them instead.
	Forwards []ForwardRule `yaml:"forwards"`

	// FirewallAutoOpen lets bosun allow its own listening ports in ufw or
	// firewalld when one is active (default true). Ports it opened are
	// closed again when the inbound or forward goes away.
	FirewallAutoOpen *bool `yaml:"firewall_auto_open"`
}

// FirewallAutoOpenEnabled applies the default.
func (c *Config) FirewallAutoOpenEnabled() bool {
	return c.FirewallAutoOpen == nil || *c.FirewallAutoOpen
}

// ForwardRule is one relay rule in the config file.
type ForwardRule struct {
	Tag      string `yaml:"tag"`
	Listen   string `yaml:"listen"`
	Port     int    `yaml:"port"`
	Protocol string `yaml:"protocol"` // tcp, udp, both (default tcp)
	Target   string `yaml:"target"`   // host:port
}

// ForwardSpecs converts the configured rules into spec.Forward values.
func (c *Config) ForwardSpecs() []spec.Forward {
	out := make([]spec.Forward, 0, len(c.Forwards))
	for _, f := range c.Forwards {
		out = append(out, spec.Forward{Tag: f.Tag, Listen: f.Listen, Port: f.Port, Protocol: f.Protocol, Target: f.Target})
	}
	return out
}

// CoresDir is where bosun-managed core binaries live.
func (c *Config) CoresDir() string { return filepath.Join(c.DataDir, "cores") }

// CoreOrder returns the effective core preference order.
func (c *Config) CoreOrder() []string {
	def := []string{"singbox", "xray", "mita", "hysteria", "snell"}
	out := append([]string(nil), c.Cores.Order...)
	for _, d := range def {
		seen := false
		for _, o := range out {
			if o == d {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, d)
		}
	}
	return out
}

// SingboxCore enables the sing-box adapter.
type SingboxCore struct {
	Binary      string `yaml:"binary"`  // explicit path; empty = managed by bosun
	Version     string `yaml:"version"` // manifest version when managed; empty = newest tested
	StatsListen string `yaml:"stats_listen"`
	LogLevel    string `yaml:"log_level"`
}

// XrayCore enables the Xray-core adapter.
type XrayCore struct {
	Binary    string `yaml:"binary"`
	Version   string `yaml:"version"`
	APIListen string `yaml:"api_listen"`
	LogLevel  string `yaml:"log_level"`
}

// HysteriaCore enables the official Hysteria 2 server adapter.
type HysteriaCore struct {
	Binary      string `yaml:"binary"`
	Version     string `yaml:"version"`
	AuthListen  string `yaml:"auth_listen"`  // bosun's auth callback endpoint
	StatsListen string `yaml:"stats_listen"` // hysteria's traffic stats API
	LogLevel    string `yaml:"log_level"`
}

// MitaCore enables the official mieru server adapter.
type MitaCore struct {
	Binary   string `yaml:"binary"`
	Version  string `yaml:"version"`
	LogLevel string `yaml:"log_level"`
}

// SnellCore enables the Surge snell-server adapter (snell protocol only).
type SnellCore struct {
	Binary  string `yaml:"binary"`
	Version string `yaml:"version"` // manifest version when managed: "5.0.0" (default) or "4.1.1"
}

// CaptainPanel configures the Captain driver.
type CaptainPanel struct {
	URL       string        `yaml:"url"`
	PairCode  string        `yaml:"pair_code"`  // one-time; ignored once a token is stored
	TokenFile string        `yaml:"token_file"` // default <data_dir>/captain.token
	Timeout   time.Duration `yaml:"timeout"`
	// AllowInsecure permits a plain-http panel URL (lab use only): the
	// node token and every config the panel pushes would travel in clear.
	AllowInsecure bool `yaml:"allow_insecure"`
}

// XboardPanel configures the Xboard driver.
type XboardPanel struct {
	URL      string        `yaml:"url"`
	Token    string        `yaml:"token"`
	NodeID   int           `yaml:"node_id"`
	NodeType string        `yaml:"node_type"`
	Timeout  time.Duration `yaml:"timeout"`
}

// Web configures the built-in panel.
type Web struct {
	Listen string `yaml:"listen"` // default ":2053"
	Cert   string `yaml:"cert"`   // optional; plain HTTP without
	Key    string `yaml:"key"`
	// StateFile holds the local objects; default <data_dir>/local.json.
	StateFile string `yaml:"state_file"`
	// TrustedProxies are reverse proxies (CIDRs) whose X-Forwarded-For the
	// panel believes for the login limiter and the allow-list.
	TrustedProxies []string `yaml:"trusted_proxies"`
}

// Cert is one certificate/key pair.
type Cert struct {
	ServerName string `yaml:"server_name"`
	Cert       string `yaml:"cert"`
	Key        string `yaml:"key"`
}

// Load reads and validates a config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if c.DataDir == "" {
		c.DataDir = "/var/lib/bosun"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.Cores.Singbox == nil && c.Cores.Xray == nil && c.Cores.Mita == nil && c.Cores.Hysteria == nil && c.Cores.Snell == nil {
		return nil, fmt.Errorf("config: at least one core must be enabled (cores.singbox, cores.xray, cores.mita, cores.hysteria, cores.snell)")
	}
	// BOSUN_CAPTAIN / BOSUN_PAIR (the docker one-liner Captain prints) select
	// the Captain driver without editing the baked-in config. The pair code is
	// only used until a token is stored, so leaving the variables set is fine.
	if u := os.Getenv("BOSUN_CAPTAIN"); u != "" {
		c.Panel.Driver = "captain"
		c.Panel.Captain = &CaptainPanel{URL: u, PairCode: os.Getenv("BOSUN_PAIR")}
		c.Web = nil
	}
	if c.Panel.Driver == "" {
		c.Panel.Driver = "local"
	}
	if c.Panel.Driver == "local" && c.Web == nil {
		c.Web = &Web{}
	}
	if c.Web != nil {
		if c.Web.Listen == "" {
			c.Web.Listen = ":2053"
		}
		if c.Web.StateFile == "" {
			c.Web.StateFile = filepath.Join(c.DataDir, "local.json")
		}
		if (c.Web.Cert == "") != (c.Web.Key == "") {
			return nil, fmt.Errorf("config: web.cert and web.key go together")
		}
	}
	if c.Panel.Driver == "local" && c.Panel.Captain != nil && c.Panel.Captain.TokenFile == "" {
		c.Panel.Captain.TokenFile = filepath.Join(c.DataDir, "captain.token")
	}
	if c.Panel.Driver == "xboard" && c.Panel.Xboard == nil {
		return nil, fmt.Errorf("config: panel.xboard is required when driver is xboard")
	}
	if c.Panel.Driver == "captain" {
		if c.Panel.Captain == nil || c.Panel.Captain.URL == "" {
			return nil, fmt.Errorf("config: panel.captain.url is required when driver is captain")
		}
		if strings.HasPrefix(strings.ToLower(c.Panel.Captain.URL), "http://") && !c.Panel.Captain.AllowInsecure {
			return nil, fmt.Errorf("config: panel.captain.url is plain http; use https or set panel.captain.allow_insecure: true")
		}
		if c.Panel.Captain.TokenFile == "" {
			c.Panel.Captain.TokenFile = filepath.Join(c.DataDir, "captain.token")
		}
	}
	for _, name := range c.Cores.Order {
		switch name {
		case "singbox", "xray", "mita", "hysteria", "snell":
		default:
			return nil, fmt.Errorf("config: cores.order: unknown core %q", name)
		}
	}
	for i := range c.Forwards {
		f := &c.Forwards[i]
		if f.Protocol == "" {
			f.Protocol = "tcp"
		}
		if f.Tag == "" {
			f.Tag = fmt.Sprintf("forward-%d", f.Port)
		}
	}
	for i, cert := range c.Certs {
		if cert.ServerName == "" || cert.Cert == "" || cert.Key == "" {
			return nil, fmt.Errorf("config: certs[%d]: server_name, cert and key are required", i)
		}
		c.Certs[i].Cert = filepath.Clean(cert.Cert)
		c.Certs[i].Key = filepath.Clean(cert.Key)
	}
	return &c, nil
}

// CertFor returns the certificate paths for a server name, or false.
func (c *Config) CertFor(serverName string) (certPath, keyPath string, ok bool) {
	for _, cert := range c.Certs {
		if cert.ServerName == serverName {
			return cert.Cert, cert.Key, true
		}
	}
	if len(c.Certs) == 1 && c.Certs[0].ServerName == "*" {
		return c.Certs[0].Cert, c.Certs[0].Key, true
	}
	return "", "", false
}

// ProbeConfig is the standalone probe section.
type ProbeConfig struct {
	Enabled     bool            `yaml:"enabled"`
	CarrierPing *bool           `yaml:"carrier_ping"` // default true
	Carriers    []spec.Carrier  `yaml:"carriers"`     // empty = the default CT/CU/CM points
	Tasks       []spec.PingTask `yaml:"tasks"`
}

// Spec converts the section into what the probe runner takes.
func (p *ProbeConfig) Spec() *spec.Probe {
	if p == nil || !p.Enabled {
		return nil
	}
	out := &spec.Probe{Enabled: true, CarrierPing: p.CarrierPing == nil || *p.CarrierPing, Carriers: p.Carriers}
	for i, t := range p.Tasks {
		if t.ID == 0 {
			t.ID = int64(i + 1)
		}
		out.Tasks = append(out.Tasks, t)
	}
	return out
}

// EgressGuardOn reports whether the core egress guard should be installed:
// explicit setting, else on whenever the cores run as their own account.
func (c *Config) EgressGuardOn() bool {
	if c.Cores.EgressGuard != nil {
		return *c.Cores.EgressGuard
	}
	return c.Cores.User != ""
}
