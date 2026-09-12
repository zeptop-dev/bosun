package mita

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// serverConfig is mita's JSON server configuration (protojson of
// mieru.appctl.ServerConfig). Only the fields bosun manages are present.
type serverConfig struct {
	PortBindings   []portBinding   `json:"portBindings"`
	Users          []user          `json:"users"`
	LoggingLevel   string          `json:"loggingLevel,omitempty"`
	DNS            *dnsConfig      `json:"dns,omitempty"`
	TrafficPattern json.RawMessage `json:"trafficPattern,omitempty"`
}

type portBinding struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "TCP" or "UDP"
}

type user struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type dnsConfig struct {
	DualStack string `json:"dualStack"`
}

// render builds the mita config for the given mieru inbounds. Every inbound
// becomes one port binding; all users are shared across bindings, which is
// how mita works (users are global, not per port).
func render(inbounds []spec.Inbound, users []spec.User, logLevel string) ([]byte, error) {
	cfg := serverConfig{
		LoggingLevel: strings.ToUpper(logLevel),
		DNS:          &dnsConfig{DualStack: "PREFER_IPv4"},
	}
	for _, ib := range inbounds {
		if ib.Protocol != spec.Mieru {
			return nil, fmt.Errorf("mita: inbound %q: unsupported protocol %s", ib.Tag, ib.Protocol)
		}
		if ib.Port <= 0 {
			return nil, fmt.Errorf("mita: inbound %q: port is required", ib.Tag)
		}
		proto := strings.ToUpper(ib.MieruTransport)
		if proto == "" {
			proto = "TCP"
		}
		if proto != "TCP" && proto != "UDP" {
			return nil, fmt.Errorf("mita: inbound %q: transport must be TCP or UDP, got %q", ib.Tag, ib.MieruTransport)
		}
		cfg.PortBindings = append(cfg.PortBindings, portBinding{Port: ib.Port, Protocol: proto})
		if cfg.TrafficPattern == nil && ib.TrafficPattern != "" {
			tp := strings.TrimSpace(ib.TrafficPattern)
			if json.Valid([]byte(tp)) && strings.HasPrefix(tp, "{") {
				cfg.TrafficPattern = json.RawMessage(tp)
			}
		}
	}
	if len(cfg.PortBindings) == 0 {
		return nil, fmt.Errorf("mita: nothing to render")
	}
	for _, u := range users {
		cfg.Users = append(cfg.Users, user{Name: u.Name, Password: u.Password})
	}
	if cfg.Users == nil {
		cfg.Users = []user{}
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// bindingsKey identifies the port-binding set so Apply can tell a users-only
// change (hot reload) from a port change (proxy restart).
func bindingsKey(inbounds []spec.Inbound) string {
	parts := make([]string, 0, len(inbounds))
	for _, ib := range inbounds {
		parts = append(parts, fmt.Sprintf("%d/%s", ib.Port, strings.ToUpper(ib.MieruTransport)))
	}
	return strings.Join(parts, ",")
}
