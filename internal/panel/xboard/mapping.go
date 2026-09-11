package xboard

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"gitlab.com/zeptop-group/bosun/internal/spec"
)

// nodeConfig mirrors the JSON returned by GET /api/v1/server/UniProxy/config.
// Field names follow Xboard's ServerService::buildNodeConfig.
type nodeConfig struct {
	Protocol        string         `json:"protocol"`
	ListenIP        string         `json:"listen_ip"`
	ServerPort      int            `json:"server_port"`
	Network         string         `json:"network"`
	NetworkSettings map[string]any `json:"networkSettings"`

	Cipher     string `json:"cipher"`
	Plugin     string `json:"plugin"`
	PluginOpts string `json:"plugin_opts"`
	ServerKey  string `json:"server_key"`

	TLS         int            `json:"tls"`
	Flow        string         `json:"flow"`
	TLSSettings map[string]any `json:"tls_settings"`
	Multiplex   map[string]any `json:"multiplex"`

	Host       string `json:"host"`
	ServerName string `json:"server_name"`

	Version      int    `json:"version"`
	UpMbps       int    `json:"up_mbps"`
	DownMbps     int    `json:"down_mbps"`
	Obfs         string `json:"obfs"`
	ObfsPassword string `json:"obfs-password"`

	CongestionControl string `json:"congestion_control"`
	PaddingScheme     any    `json:"padding_scheme"`
	Transport         string `json:"transport"`
	TrafficPattern    string `json:"traffic_pattern"`

	CustomOutbounds []struct {
		Tag      string         `json:"tag"`
		Protocol string         `json:"protocol"`
		Settings map[string]any `json:"settings"`
		ProxyTag string         `json:"proxy_tag"`
	} `json:"custom_outbounds"`

	BaseConfig struct {
		PushInterval int `json:"push_interval"`
		PullInterval int `json:"pull_interval"`
	} `json:"base_config"`
}

type userList struct {
	Users []struct {
		ID          int64  `json:"id"`
		UUID        string `json:"uuid"`
		SpeedLimit  int    `json:"speed_limit"`
		DeviceLimit int    `json:"device_limit"`
	} `json:"users"`
}

// mapNode converts one Xboard node (which is always a single inbound) into a
// spec.Node.
func mapNode(nodeID int, raw *nodeConfig) (*spec.Node, error) {
	proto, err := mapProtocol(raw)
	if err != nil {
		return nil, err
	}
	ib := spec.Inbound{
		Tag:      fmt.Sprintf("xboard-%d", nodeID),
		Protocol: proto,
		Listen:   raw.ListenIP,
		Port:     raw.ServerPort,
	}
	if ib.Listen == "0.0.0.0" || ib.Listen == "" {
		ib.Listen = "::"
	}

	switch proto {
	case spec.Shadowsocks:
		ib.Cipher = raw.Cipher
		ib.ServerKey = raw.ServerKey
	case spec.VLESS:
		ib.Flow = raw.Flow
	case spec.Hysteria2:
		ib.UpMbps, ib.DownMbps = raw.UpMbps, raw.DownMbps
		if raw.Obfs != "" {
			ib.Obfs, ib.ObfsPassword = raw.Obfs, raw.ObfsPassword
		}
	case spec.TUIC:
		ib.CongestionControl = raw.CongestionControl
	case spec.AnyTLS:
		ib.PaddingScheme = toStringSlice(raw.PaddingScheme)
	case spec.Mieru:
		ib.MieruTransport = strings.ToUpper(raw.Transport)
		ib.TrafficPattern = raw.TrafficPattern
	}

	if tls, err := mapTLS(proto, raw); err != nil {
		return nil, err
	} else if tls != nil {
		ib.TLS = tls
	}
	ib.Transport = mapTransport(raw.Network, raw.NetworkSettings)
	ib.Multiplex = mapMultiplex(raw.Multiplex)

	node := &spec.Node{ID: strconv.Itoa(nodeID), Inbounds: []spec.Inbound{ib}}
	for _, o := range raw.CustomOutbounds {
		node.Outbounds = append(node.Outbounds, spec.Outbound{
			Tag: o.Tag, Protocol: o.Protocol, Settings: o.Settings, ProxyTag: o.ProxyTag,
		})
	}
	return node, nil
}

func mapProtocol(raw *nodeConfig) (spec.Protocol, error) {
	switch raw.Protocol {
	case "vless":
		return spec.VLESS, nil
	case "vmess":
		return spec.VMess, nil
	case "trojan":
		return spec.Trojan, nil
	case "shadowsocks":
		return spec.Shadowsocks, nil
	case "hysteria":
		if raw.Version == 2 {
			return spec.Hysteria2, nil
		}
		return "", fmt.Errorf("xboard: hysteria v%d is not supported (only v2)", raw.Version)
	case "tuic":
		return spec.TUIC, nil
	case "anytls":
		return spec.AnyTLS, nil
	case "mieru":
		return spec.Mieru, nil
	case "socks":
		return spec.SOCKS, nil
	case "http":
		return spec.HTTP, nil
	case "naive":
		return spec.Naive, nil
	}
	return "", fmt.Errorf("xboard: unknown protocol %q", raw.Protocol)
}

// mapTLS interprets Xboard's tls integer (0 none, 1 tls, 2 reality) and the
// tls_settings object, which carries reality fields when tls == 2. QUIC based
// protocols always use TLS and carry their settings in tls_settings too.
func mapTLS(proto spec.Protocol, raw *nodeConfig) (*spec.TLS, error) {
	mode := spec.TLSMode(raw.TLS)
	switch proto {
	case spec.Hysteria2, spec.TUIC, spec.AnyTLS, spec.Naive:
		mode = spec.TLSStandard
	}
	if mode == spec.TLSNone {
		return nil, nil
	}
	s := raw.TLSSettings
	t := &spec.TLS{Mode: mode, ServerName: str(s["server_name"])}
	if t.ServerName == "" {
		t.ServerName = raw.ServerName
	}
	if mode == spec.TLSReality {
		r := &spec.Reality{
			PrivateKey:      str(s["private_key"]),
			HandshakeServer: str(s["server_name"]),
			HandshakePort:   toInt(s["server_port"], 443),
		}
		if sid := str(s["short_id"]); sid != "" {
			r.ShortIDs = []string{sid}
		} else {
			r.ShortIDs = []string{""}
		}
		if r.PrivateKey == "" {
			return nil, fmt.Errorf("xboard: reality enabled but private_key is empty")
		}
		t.Reality = r
	}
	return t, nil
}

func mapTransport(network string, s map[string]any) *spec.Transport {
	switch network {
	case "ws", "websocket":
		t := &spec.Transport{Type: "ws", Path: str(s["path"])}
		if h, ok := s["headers"].(map[string]any); ok {
			t.Host = str(h["Host"])
		}
		return t
	case "grpc":
		return &spec.Transport{Type: "grpc", ServiceName: str(s["serviceName"])}
	case "httpupgrade":
		return &spec.Transport{Type: "httpupgrade", Path: str(s["path"]), Host: str(s["host"])}
	case "http", "h2":
		t := &spec.Transport{Type: "http", Path: str(s["path"])}
		if hosts := toStringSlice(s["host"]); len(hosts) > 0 {
			t.Host = hosts[0]
		}
		return t
	}
	return nil
}

func mapMultiplex(m map[string]any) *spec.Multiplex {
	if m == nil || !toBool(m["enabled"]) {
		return nil
	}
	mx := &spec.Multiplex{Enabled: true, Padding: toBool(m["padding"])}
	if b, ok := m["brutal"].(map[string]any); ok && toBool(b["enabled"]) {
		mx.Brutal = &spec.Brutal{UpMbps: toInt(b["up_mbps"], 0), DownMbps: toInt(b["down_mbps"], 0)}
	}
	return mx
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatInt(int64(x), 10)
	}
	return ""
}

func toInt(v any, def int) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case string:
		if n, err := strconv.Atoi(x); err == nil {
			return n
		}
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return int(n)
		}
	}
	return def
}

func toBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		return x == "1" || x == "true"
	}
	return false
}

func toStringSlice(v any) []string {
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s := str(e); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return x
	case string:
		if x == "" {
			return nil
		}
		return []string{x}
	}
	return nil
}
