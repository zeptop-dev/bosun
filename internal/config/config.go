// Package config loads bosun's YAML configuration file.
package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the on-disk configuration.
type Config struct {
	DataDir  string `yaml:"data_dir"`
	LogLevel string `yaml:"log_level"`

	Cores struct {
		Singbox *SingboxCore `yaml:"singbox"`
	} `yaml:"cores"`

	Panel struct {
		Driver string       `yaml:"driver"`
		Xboard *XboardPanel `yaml:"xboard"`
	} `yaml:"panel"`

	// Certs maps server names to local certificate files for TLSStandard inbounds.
	Certs []Cert `yaml:"certs"`
}

// SingboxCore enables the sing-box adapter.
type SingboxCore struct {
	Binary      string `yaml:"binary"`
	StatsListen string `yaml:"stats_listen"`
	LogLevel    string `yaml:"log_level"`
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
	if c.Cores.Singbox == nil {
		return nil, fmt.Errorf("config: at least one core must be enabled (cores.singbox)")
	}
	if c.Panel.Driver == "" {
		return nil, fmt.Errorf("config: panel.driver is required")
	}
	if c.Panel.Driver == "xboard" && c.Panel.Xboard == nil {
		return nil, fmt.Errorf("config: panel.xboard is required when driver is xboard")
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
