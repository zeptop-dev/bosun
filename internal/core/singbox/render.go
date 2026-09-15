package singbox

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

type m = map[string]any

type renderOptions struct {
	LogLevel    string
	StatsListen string
}

// render produces a sing-box JSON configuration for the given inbounds.
func render(node *spec.Node, inbounds []spec.Inbound, users []spec.User, opt renderOptions) ([]byte, error) {
	if len(inbounds) == 0 {
		return nil, fmt.Errorf("singbox: nothing to render")
	}
	// Stats counters are per user name across all inbounds.
	seen := map[string]bool{}
	names := []string{}
	ins := make([]any, 0, len(inbounds))
	for _, ib := range inbounds {
		ibUsers := ib.EffectiveUsers(users)
		for _, u := range ibUsers {
			if !seen[u.Name] {
				seen[u.Name] = true
				names = append(names, u.Name)
			}
		}
		in, err := renderInbound(ib, ibUsers)
		if err != nil {
			return nil, err
		}
		ins = append(ins, in)
	}

	outs := []any{m{"type": "direct", "tag": "direct"}}
	var endpoints []any
	for _, o := range node.Outbounds {
		if o.WARP != nil {
			endpoints = append(endpoints, renderWARP(o))
			continue
		}
		if o.Balancer != nil {
			outs = append(outs, m{"type": "urltest", "tag": o.Tag, "outbounds": o.Balancer.Members, "url": "https://www.gstatic.com/generate_204", "interval": "1m"})
			continue
		}
		if o.Remote != nil {
			ro, err := renderRemote(o)
			if err != nil {
				return nil, err
			}
			outs = append(outs, ro)
			continue
		}
		outs = append(outs, renderOutbound(o))
	}
	final := "direct"
	if node.DefaultOutbound != "" {
		final = node.DefaultOutbound
	}

	cfg := m{
		"log": m{"level": opt.LogLevel, "timestamp": true},
		"experimental": m{
			"v2ray_api": m{
				"listen": opt.StatsListen,
				"stats":  m{"enabled": true, "users": names, "inbounds": inboundTags(inbounds)},
			},
		},
		"inbounds":  ins,
		"outbounds": outs,
	}
	rules, sets := renderRoutes(node.Routes)
	route := m{"rules": append(sniffRules(inbounds), rules...), "final": final}
	if len(sets) > 0 {
		route["rule_set"] = sets
	}
	cfg["route"] = route
	if len(endpoints) > 0 {
		cfg["endpoints"] = endpoints
	}
	if len(node.DNS) > 0 {
		cfg["dns"] = renderDNS(node.DNS)
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func renderInbound(ib spec.Inbound, users []spec.User) (m, error) {
	in := m{
		"tag":         ib.Tag,
		"listen":      listenAddr(ib.Listen),
		"listen_port": ib.Port,
	}
	switch ib.Protocol {
	case spec.VLESS:
		in["type"] = "vless"
		in["users"] = mapUsers(users, func(u spec.User) m {
			x := m{"name": u.Name, "uuid": u.UUID}
			if ib.Flow != "" && ib.TLS != nil {
				x["flow"] = ib.Flow
			}
			return x
		})
	case spec.VMess:
		in["type"] = "vmess"
		in["users"] = mapUsers(users, func(u spec.User) m { return m{"name": u.Name, "uuid": u.UUID, "alterId": 0} })
	case spec.Trojan:
		in["type"] = "trojan"
		in["users"] = mapUsers(users, func(u spec.User) m { return m{"name": u.Name, "password": u.Password} })
	case spec.Shadowsocks:
		in["type"] = "shadowsocks"
		in["method"] = ib.Cipher
		keyLen := ss2022KeyLen(ib.Cipher)
		if keyLen > 0 {
			if ib.ServerKey == "" {
				return nil, fmt.Errorf("singbox: inbound %q: %s requires a server key", ib.Tag, ib.Cipher)
			}
			in["password"] = ib.ServerKey
		}
		in["users"] = mapUsers(users, func(u spec.User) m {
			pw := u.Password
			if keyLen > 0 {
				pw = ss2022UserKey(u.UUID, keyLen)
			}
			return m{"name": u.Name, "password": pw}
		})
	case spec.Hysteria2:
		in["type"] = "hysteria2"
		if ib.UpMbps > 0 {
			in["up_mbps"] = ib.UpMbps
		}
		if ib.DownMbps > 0 {
			in["down_mbps"] = ib.DownMbps
		}
		if ib.Obfs != "" {
			in["obfs"] = m{"type": ib.Obfs, "password": ib.ObfsPassword}
		}
		in["users"] = mapUsers(users, func(u spec.User) m { return m{"name": u.Name, "password": u.Password} })
	case spec.TUIC:
		in["type"] = "tuic"
		if ib.CongestionControl != "" {
			in["congestion_control"] = ib.CongestionControl
		}
		in["users"] = mapUsers(users, func(u spec.User) m { return m{"name": u.Name, "uuid": u.UUID, "password": u.Password} })
	case spec.AnyTLS:
		in["type"] = "anytls"
		if len(ib.PaddingScheme) > 0 {
			in["padding_scheme"] = ib.PaddingScheme
		}
		in["users"] = mapUsers(users, func(u spec.User) m { return m{"name": u.Name, "password": u.Password} })
	case spec.SOCKS:
		in["type"] = "socks"
		in["users"] = mapUsers(users, func(u spec.User) m { return m{"username": u.Name, "password": u.Password} })
	case spec.HTTP:
		in["type"] = "http"
		in["users"] = mapUsers(users, func(u spec.User) m { return m{"username": u.Name, "password": u.Password} })
	case spec.Naive:
		in["type"] = "naive"
		in["users"] = mapUsers(users, func(u spec.User) m { return m{"username": u.Name, "password": u.Password} })
	default:
		return nil, fmt.Errorf("singbox: inbound %q: unsupported protocol %s", ib.Tag, ib.Protocol)
	}

	if tls := renderTLS(ib.TLS); tls != nil {
		in["tls"] = tls
	} else if requiresTLS(ib.Protocol) {
		return nil, fmt.Errorf("singbox: inbound %q: %s requires TLS", ib.Tag, ib.Protocol)
	}
	if tr := renderTransport(ib.Transport); tr != nil && supportsTransport(ib.Protocol) {
		in["transport"] = tr
	}
	if mx := renderMultiplex(ib.Multiplex); mx != nil && supportsMultiplex(ib.Protocol) {
		in["multiplex"] = mx
	}
	return in, nil
}

func listenAddr(l string) string {
	if l == "" || l == "0.0.0.0" {
		return "::"
	}
	return l
}

func mapUsers(users []spec.User, f func(spec.User) m) []any {
	out := make([]any, 0, len(users))
	for _, u := range users {
		out = append(out, f(u))
	}
	return out
}

func requiresTLS(p spec.Protocol) bool {
	switch p {
	case spec.Hysteria2, spec.TUIC, spec.AnyTLS, spec.Naive:
		return true
	}
	return false
}

func supportsTransport(p spec.Protocol) bool {
	switch p {
	case spec.VLESS, spec.VMess, spec.Trojan:
		return true
	}
	return false
}

func supportsMultiplex(p spec.Protocol) bool {
	switch p {
	case spec.VLESS, spec.VMess, spec.Trojan, spec.Shadowsocks:
		return true
	}
	return false
}

func renderTLS(t *spec.TLS) m {
	if t == nil || t.Mode == spec.TLSNone {
		return nil
	}
	out := m{"enabled": true}
	if t.ServerName != "" {
		out["server_name"] = t.ServerName
	}
	if len(t.ALPN) > 0 {
		out["alpn"] = t.ALPN
	}
	if t.Mode == spec.TLSReality && t.Reality != nil {
		r := t.Reality
		out["reality"] = m{
			"enabled":     true,
			"handshake":   m{"server": r.HandshakeServer, "server_port": r.HandshakePort},
			"private_key": r.PrivateKey,
			"short_id":    r.ShortIDs,
		}
		return out
	}
	out["certificate_path"] = t.CertPath
	out["key_path"] = t.KeyPath
	return out
}

func renderTransport(t *spec.Transport) m {
	if t == nil {
		return nil
	}
	switch t.Type {
	case "ws":
		out := m{"type": "ws", "path": t.Path}
		if t.Host != "" {
			out["headers"] = m{"Host": t.Host}
		}
		return out
	case "grpc":
		return m{"type": "grpc", "service_name": t.ServiceName}
	case "httpupgrade":
		out := m{"type": "httpupgrade", "path": t.Path}
		if t.Host != "" {
			out["host"] = t.Host
		}
		return out
	case "http":
		out := m{"type": "http", "path": t.Path}
		if t.Host != "" {
			out["host"] = []string{t.Host}
		}
		return out
	}
	return nil
}

func renderMultiplex(x *spec.Multiplex) m {
	if x == nil || !x.Enabled {
		return nil
	}
	out := m{"enabled": true, "padding": x.Padding}
	if x.Brutal != nil {
		out["brutal"] = m{"enabled": true, "up_mbps": x.Brutal.UpMbps, "down_mbps": x.Brutal.DownMbps}
	}
	return out
}

// renderOutbound passes panel-defined outbounds through. sing-box's flat
// layout means Settings already are the outbound body; we add type/tag and the
// chain reference.
func renderOutbound(o spec.Outbound) m {
	out := m{}
	for k, v := range o.Settings {
		out[k] = v
	}
	out["type"] = o.Protocol
	out["tag"] = o.Tag
	if o.ProxyTag != "" {
		out["detour"] = o.ProxyTag
	}
	return out
}

func renderRoutes(rules []spec.RouteRule) (out []any, sets []any) {
	out = make([]any, 0, len(rules))
	seen := map[string]bool{}
	for _, r := range rules {
		rule := m{}
		for _, match := range r.Match {
			addMatch(rule, match)
		}
		for _, rs := range ruleSetsOf(rule) {
			if !seen[rs] {
				seen[rs] = true
				sets = append(sets, ruleSet(rs))
			}
		}
		switch r.Action {
		case "block":
			rule["action"] = "reject"
		case "outbound":
			rule["outbound"] = r.Value
		default:
			rule["outbound"] = "direct"
		}
		out = append(out, rule)
	}
	return out, sets
}

// sniffRules asks sing-box to sniff destinations (a route action since
// 1.11) on every inbound that has not opted out.
func sniffRules(inbounds []spec.Inbound) []any {
	var tags []string
	for _, ib := range inbounds {
		if !ib.NoSniff {
			tags = append(tags, ib.Tag)
		}
	}
	if len(tags) == 0 {
		return nil
	}
	return []any{m{"inbound": tags, "action": "sniff"}}
}

func ruleSetsOf(rule m) []string {
	list, _ := rule["rule_set"].([]string)
	return list
}

// ruleSet is a remote binary rule set from MetaCubeX's geo data.
func ruleSet(tag string) m {
	kind, name, _ := cut(tag, "-")
	return m{"tag": tag, "type": "remote", "format": "binary", "download_detour": "direct",
		"url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/" + kind + "/" + name + ".srs"}
}

// renderDNS turns "1.1.1.1", "tls://1.1.1.1", "https://dns.google/dns-query"
// into typed sing-box servers, the first one being the default.
func renderDNS(list []string) m {
	var servers []any
	for i, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		srv := m{"tag": "dns-" + strconv.Itoa(i)}
		switch {
		case strings.HasPrefix(s, "https://"):
			u := strings.TrimPrefix(s, "https://")
			host, path, _ := cut(u, "/")
			srv["type"] = "https"
			srv["server"] = host
			if path != "" {
				srv["path"] = "/" + path
			}
		case strings.HasPrefix(s, "tls://"):
			srv["type"] = "tls"
			srv["server"] = strings.TrimPrefix(s, "tls://")
		default:
			srv["type"] = "udp"
			srv["server"] = s
		}
		servers = append(servers, srv)
	}
	if len(servers) == 0 {
		return nil
	}
	return m{"servers": servers, "final": servers[0].(m)["tag"]}
}

func addMatch(rule m, match string) {
	key, val, ok := cut(match, ":")
	if !ok {
		rule["domain_suffix"] = appendStr(rule["domain_suffix"], match)
		return
	}
	switch key {
	case "inbound":
		rule["inbound"] = appendStr(rule["inbound"], val)
	case "domain":
		rule["domain_suffix"] = appendStr(rule["domain_suffix"], val)
	case "full":
		rule["domain"] = appendStr(rule["domain"], val)
	case "ip", "ip_cidr":
		rule["ip_cidr"] = appendStr(rule["ip_cidr"], val)
	case "protocol":
		rule["protocol"] = appendStr(rule["protocol"], val)
	case "port":
		rule["port_range"] = appendStr(rule["port_range"], val)
	case "geosite":
		rule["rule_set"] = appendStr(rule["rule_set"], "geosite-"+val)
	case "geoip":
		rule["rule_set"] = appendStr(rule["rule_set"], "geoip-"+val)
	default:
		rule["domain_suffix"] = appendStr(rule["domain_suffix"], match)
	}
}

func appendStr(cur any, s string) []string {
	list, _ := cur.([]string)
	return append(list, s)
}

func cut(s, sep string) (string, string, bool) {
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return s[:i], s[i+len(sep):], true
		}
	}
	return s, "", false
}

func ss2022KeyLen(cipher string) int {
	switch cipher {
	case "2022-blake3-aes-128-gcm":
		return 16
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return 32
	}
	return 0
}

// ss2022UserKey derives the per-user PSK the way Xboard's subscription does:
// the first n bytes of the UUID string, zero padded, base64 encoded.
func ss2022UserKey(uuid string, n int) string {
	buf := make([]byte, n)
	copy(buf, uuid)
	return base64.StdEncoding.EncodeToString(buf)
}

// renderWARP is a sing-box WireGuard endpoint to Cloudflare WARP; route
// rules and the final outbound may name its tag like any outbound.
func renderWARP(o spec.Outbound) m {
	w := o.WARP
	host, port := "engage.cloudflareclient.com", 2408
	if w.Endpoint != "" {
		if h, p, err := net.SplitHostPort(w.Endpoint); err == nil {
			host = h
			if n, err := strconv.Atoi(p); err == nil {
				port = n
			}
		}
	}
	peer := m{"address": host, "port": port, "public_key": w.PeerPublicKey, "allowed_ips": []string{"0.0.0.0/0", "::/0"}, "persistent_keepalive_interval": 25}
	if len(w.Reserved) == 3 {
		peer["reserved"] = w.Reserved
	}
	out := m{"type": "wireguard", "tag": o.Tag, "mtu": 1280, "address": w.Addresses, "private_key": w.PrivateKey, "peers": []m{peer}}
	if o.ProxyTag != "" {
		out["detour"] = o.ProxyTag
	}
	return out
}

func inboundTags(list []spec.Inbound) []string {
	out := make([]string, 0, len(list))
	for _, ib := range list {
		out = append(out, ib.Tag)
	}
	return out
}
