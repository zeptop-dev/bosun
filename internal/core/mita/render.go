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
	MTU            int             `json:"mtu,omitempty"`
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
		switch proto {
		case "TCP", "UDP":
			cfg.PortBindings = append(cfg.PortBindings, portBinding{Port: ib.Port, Protocol: proto})
		case "BOTH":
			// TCP at the port, UDP right after it (nobrand's convention).
			if ib.Port+1 > 65535 {
				return nil, fmt.Errorf("mita: inbound %q: BOTH needs port+1 (%d) to be valid", ib.Tag, ib.Port+1)
			}
			cfg.PortBindings = append(cfg.PortBindings, portBinding{Port: ib.Port, Protocol: "TCP"}, portBinding{Port: ib.Port + 1, Protocol: "UDP"})
		default:
			return nil, fmt.Errorf("mita: inbound %q: transport must be TCP, UDP or BOTH, got %q", ib.Tag, ib.MieruTransport)
		}
		if ib.MieruMTU > 0 {
			if ib.MieruMTU < 1280 || ib.MieruMTU > 1500 {
				return nil, fmt.Errorf("mita: inbound %q: mtu must be 1280-1500", ib.Tag)
			}
			cfg.MTU = ib.MieruMTU
		}
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
		parts = append(parts, fmt.Sprintf("%d/%s/%d", ib.Port, strings.ToUpper(ib.MieruTransport), ib.MieruMTU))
	}
	return strings.Join(parts, ",")
}
