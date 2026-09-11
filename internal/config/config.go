// Package config loads bosun's YAML configuration file.
package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"gitlab.com/boyang-hu/bosun/pkg/spec"
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
		Singbox       *SingboxCore  `yaml:"singbox"`
		Xray          *XrayCore     `yaml:"xray"`
		Mita          *MitaCore     `yaml:"mita"`
		Hysteria      *HysteriaCore `yaml:"hysteria"`
	} `yaml:"cores"`

	Panel struct {
		Driver  string        `yaml:"driver"` // "captain" or "xboard"
		Xboard  *XboardPanel  `yaml:"xboard"`
		Captain *CaptainPanel `yaml:"captain"`
	} `yaml:"panel"`

	// Certs maps server names to local certificate files for TLSStandard inbounds.
	Certs []Cert `yaml:"certs"`

	// Forwards are local relay rules, used when the panel does not manage
	// forwarding (Xboard). A panel that does supplies them instead.
	Forwards []ForwardRule `yaml:"forwards"`
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
	def := []string{"singbox", "xray", "mita", "hysteria"}
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

// CaptainPanel configures the Captain driver.
type CaptainPanel struct {
	URL       string        `yaml:"url"`
	PairCode  string        `yaml:"pair_code"`  // one-time; ignored once a token is stored
	TokenFile string        `yaml:"token_file"` // default <data_dir>/captain.token
	Timeout   time.Duration `yaml:"timeout"`
}

// XboardPanel configures the Xboard driver.
type XboardPanel struct {
	URL      string        `yaml:"url"`
	Token    string        `yaml:"token"`
	NodeID   int           `yaml:"node_id"`
	NodeType string        `yaml:"node_type"`
	Timeout  time.Duration `yaml:"timeout"`
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
	if c.Cores.Singbox == nil && c.Cores.Xray == nil && c.Cores.Mita == nil && c.Cores.Hysteria == nil {
		return nil, fmt.Errorf("config: at least one core must be enabled (cores.singbox, cores.xray, cores.mita, cores.hysteria)")
	}
	if c.Panel.Driver == "" {
		return nil, fmt.Errorf("config: panel.driver is required")
	}
	if c.Panel.Driver == "xboard" && c.Panel.Xboard == nil {
		return nil, fmt.Errorf("config: panel.xboard is required when driver is xboard")
	}
	if c.Panel.Driver == "captain" {
		if c.Panel.Captain == nil || c.Panel.Captain.URL == "" {
			return nil, fmt.Errorf("config: panel.captain.url is required when driver is captain")
		}
		if c.Panel.Captain.TokenFile == "" {
			c.Panel.Captain.TokenFile = filepath.Join(c.DataDir, "captain.token")
		}
	}
	for _, name := range c.Cores.Order {
		switch name {
		case "singbox", "xray", "mita", "hysteria":
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
