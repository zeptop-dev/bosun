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
	// ListenIPAddress binds every port to one address (mita >= 3.37.0);
	// empty listens everywhere. Older mita rejects the field, so it is
	// only written when the binary is known to support it.
	ListenIPAddress string          `json:"listenIPAddress,omitempty"`
	PortBindings    []portBinding   `json:"portBindings"`
	Users           []user          `json:"users"`
	LoggingLevel    string          `json:"loggingLevel,omitempty"`
	MTU             int             `json:"mtu,omitempty"`
	DNS             *dnsConfig      `json:"dns,omitempty"`
	TrafficPattern  json.RawMessage `json:"trafficPattern,omitempty"`
}

type portBinding struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "TCP" or "UDP"
}

type user struct {
	Name     string  `json:"name"`
	Password string  `json:"password"`
	Quotas   []quota `json:"quotas,omitempty"`
}

// quota is mita's rolling allowance: megabytes within the last days.
type quota struct {
	Days      int32 `json:"days"`
	Megabytes int32 `json:"megabytes"`
}

type dnsConfig struct {
	DualStack string `json:"dualStack"`
}

// render builds the mita config for the given mieru inbounds. Every inbound
// becomes one port binding; all users are shared across bindings, which is
// how mita works (users are global, not per port). nativeListen writes the
// inbound's bind address as listenIPAddress (one process serves one inbound,
// so the address is per inbound in practice); without it mita listens on
// every address and the agent's ingress guard drops the other ones.
func render(inbounds []spec.Inbound, users []spec.User, logLevel string, nativeListen bool) ([]byte, error) {
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
		if bind := bindAddress(ib); nativeListen && bind != "" {
			if cfg.ListenIPAddress != "" && cfg.ListenIPAddress != bind {
				return nil, fmt.Errorf("mita: inbound %q: one process cannot listen on both %s and %s", ib.Tag, cfg.ListenIPAddress, bind)
			}
			cfg.ListenIPAddress = bind
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
		mu := user{Name: u.Name, Password: u.Password}
		if u.QuotaBytes > 0 && u.QuotaDays > 0 {
			mb := u.QuotaBytes / (1 << 20)
			if mb < 1 {
				mb = 1
			}
			if mb > 1<<31-1 {
				mb = 1<<31 - 1
			}
			days := u.QuotaDays
			if days > 36500 {
				days = 36500
			}
			mu.Quotas = []quota{{Days: int32(days), Megabytes: int32(mb)}}
		}
		cfg.Users = append(cfg.Users, mu)
	}
	if cfg.Users == nil {
		cfg.Users = []user{}
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// bindAddress is the inbound's specific bind address, or "" when it
// listens everywhere (unset, 0.0.0.0 or ::).
func bindAddress(ib spec.Inbound) string {
	switch ib.Listen {
	case "", "0.0.0.0", "::":
		return ""
	}
	return ib.Listen
}

// bindingsKey identifies the listener set so Apply can tell a users-only
// change (hot reload) from a port or address change (proxy restart:
// mita's reload does not replace listeners).
func bindingsKey(inbounds []spec.Inbound, nativeListen bool) string {
	parts := make([]string, 0, len(inbounds))
	for _, ib := range inbounds {
		bind := ""
		if nativeListen {
			bind = bindAddress(ib)
		}
		parts = append(parts, fmt.Sprintf("%s@%d/%s/%d", bind, ib.Port, strings.ToUpper(ib.MieruTransport), ib.MieruMTU))
	}
	return strings.Join(parts, ",")
}
