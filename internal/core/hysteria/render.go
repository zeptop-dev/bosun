package hysteria

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/zeptop-dev/bosun/internal/core"
	"strconv"

	"gopkg.in/yaml.v3"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

type m = map[string]any

type renderOptions struct {
	AuthURL     string // bosun's auth endpoint, e.g. http://127.0.0.1:9103/auth
	StatsListen string // hysteria's traffic stats API listen address
	StatsSecret string
	// Override is the operator's JSON object merged into the config.
	Override json.RawMessage
}

// state carries Render results to Start/Apply.
type state struct {
	key   string               // hash of the server config; users are not part of it
	users map[string]spec.User // by password (the auth string), for the auth endpoint
}

// render builds the hysteria server YAML. The official server is one
// listener per process, so exactly one inbound is accepted.
func render(inbounds []spec.Inbound, users []spec.User, opt renderOptions) ([]byte, *state, error) {
	if len(inbounds) != 1 {
		return nil, nil, fmt.Errorf("hysteria: the official core serves exactly one inbound per node, got %d (use sing-box for several)", len(inbounds))
	}
	ib := inbounds[0]
	if ib.Protocol != spec.Hysteria2 {
		return nil, nil, fmt.Errorf("hysteria: inbound %q: unsupported protocol %s", ib.Tag, ib.Protocol)
	}
	if ib.TLS == nil || ib.TLS.Mode != spec.TLSStandard || ib.TLS.CertPath == "" || ib.TLS.KeyPath == "" {
		return nil, nil, fmt.Errorf("hysteria: inbound %q: certificate and key are required", ib.Tag)
	}
	listen := ib.Listen
	if listen == "" || listen == "0.0.0.0" || listen == "::" {
		listen = ""
	}
	cfg := m{
		"listen":       listen + ":" + strconv.Itoa(ib.Port),
		"tls":          m{"cert": ib.TLS.CertPath, "key": ib.TLS.KeyPath},
		"auth":         m{"type": "http", "http": m{"url": opt.AuthURL}},
		"trafficStats": m{"listen": opt.StatsListen, "secret": opt.StatsSecret},
		// Without masquerade hysteria answers 404 to probes; fine for now.
	}
	if ib.Obfs != "" {
		if ib.Obfs != "salamander" {
			return nil, nil, fmt.Errorf("hysteria: inbound %q: unsupported obfs %q", ib.Tag, ib.Obfs)
		}
		cfg["obfs"] = m{"type": "salamander", "salamander": m{"password": ib.ObfsPassword}}
	}
	if ib.UpMbps > 0 || ib.DownMbps > 0 {
		bw := m{}
		if ib.UpMbps > 0 {
			bw["up"] = strconv.Itoa(ib.UpMbps) + " mbps"
		}
		if ib.DownMbps > 0 {
			bw["down"] = strconv.Itoa(ib.DownMbps) + " mbps"
		}
		cfg["bandwidth"] = bw
	}
	if err := core.ApplyOverride("hysteria", cfg, opt.Override); err != nil {
		return nil, nil, fmt.Errorf("hysteria: %w", err)
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256(out)
	ibUsers := ib.EffectiveUsers(users)
	st := &state{key: hex.EncodeToString(sum[:8]), users: make(map[string]spec.User, len(ibUsers))}
	for _, u := range ibUsers {
		st.users[u.Password] = u
	}
	return out, st, nil
}
