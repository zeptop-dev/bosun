package singbox

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/zeptop-dev/bosun/internal/core"
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
	// Stats counters are per user *and inbound*: each inbound's users
	// carry the inbound tag in their name (spec.InboundUser), and the
	// same names go into the stats list and the speed-limit rules.
	names := []string{}
	authNames := map[int64][]string{} // user id -> per-inbound names
	ins := make([]any, 0, len(inbounds))
	for _, ib := range inbounds {
		ibUsers := ib.EffectiveUsers(users)
		for _, u := range ibUsers {
			n := spec.InboundUser(u.Name, ib.Tag)
			names = append(names, n)
			authNames[u.ID] = append(authNames[u.ID], n)
		}
		in, err := renderInbound(ib, ibUsers)
		if err != nil {
			return nil, err
		}
		// ShadowTLS: the operator's tag belongs to the public listener, and
		// the real protocol moves to a loopback inbound it hands
		// authenticated connections to. Statistics stay on the inner
		// inbound, which is where the users are.
		if ib.ShadowTLS != nil {
			inner, ok := in["tag"].(string)
			if !ok {
				return nil, fmt.Errorf("singbox: inbound %q: missing tag", ib.Tag)
			}
			in["tag"] = spec.ShadowTLSTag(inner)
			in["listen"], in["listen_port"] = "127.0.0.1", 0
			ins = append(ins, renderShadowTLS(ib, ibUsers, in["tag"].(string)))
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
	var limitRules []any
	for _, u := range users {
		l := node.EffectiveSpeedLimit(u)
		if l <= 0 {
			continue
		}
		var base m
		if node.DefaultOutbound != "" {
			for _, o := range outs {
				if om, ok := o.(m); ok && om["tag"] == node.DefaultOutbound {
					base = cloneM(om)
				}
			}
		}
		if base == nil {
			base = m{"type": "direct"}
		}
		base["tag"] = spec.SpeedTag(u.ID)
		base["routing_mark"] = spec.SpeedMark(u.ID)
		outs = append(outs, base)
		au := authNames[u.ID]
		if len(au) == 0 {
			au = []string{u.Name}
		}
		limitRules = append(limitRules, m{"auth_user": au, "outbound": spec.SpeedTag(u.ID)})
	}

	cfg := m{
		// Always info: the online tracker (device limits) reads the
		// per-connection lines sing-box only writes at that level. The
		// operator's log_level decides what reaches bosun's journal (see
		// Core.keepLine).
		"log": m{"level": "info", "timestamp": true},
		"experimental": m{
			"v2ray_api": m{
				"listen": opt.StatsListen,
				"stats":  m{"enabled": true, "users": names, "inbounds": inboundTags(inbounds), "outbounds": outboundTags(node)},
			},
		},
		"inbounds":  ins,
		"outbounds": outs,
	}
	// The node's own neighbourhood is refused before anything else; the
	// nft egress guard is the backstop for destinations reached by name.
	privRules, _ := renderRoutes(node.PrivateDestRules())
	rules, sets := renderRoutes(node.Routes)
	rules = append(privRules, rules...)
	rules = append(rules, limitRules...)
	// Egress follows ingress: a direct exit bound to each inbound's own
	// address, after the explicit rules and the speed-limited users.
	for _, ip := range sortedKeys(node.BoundInbounds(inbounds)) {
		tags := node.BoundInbounds(inbounds)[ip]
		bo := m{"type": "direct", "tag": "direct@" + ip}
		// Resolve to the bound family only: with just one bind address set,
		// the other family would silently leave from the default address.
		if spec.IsIPv6(ip) {
			bo["inet6_bind_address"], bo["domain_strategy"] = ip, "ipv6_only"
		} else {
			bo["inet4_bind_address"], bo["domain_strategy"] = ip, "ipv4_only"
		}
		outs = append(outs, bo)
		rules = append(rules, m{"inbound": tags, "outbound": "direct@" + ip})
	}
	cfg["outbounds"] = outs
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
	if err := core.ApplyOverride("singbox", cfg, node.Overrides["singbox"]); err != nil {
		return nil, fmt.Errorf("sing-box: %w", err)
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
			x := m{"name": spec.InboundUser(u.Name, ib.Tag), "uuid": u.UUID}
			if ib.Flow != "" && ib.TLS != nil {
				x["flow"] = ib.Flow
			}
			return x
		})
	case spec.VMess:
		in["type"] = "vmess"
		in["users"] = mapUsers(users, func(u spec.User) m { return m{"name": spec.InboundUser(u.Name, ib.Tag), "uuid": u.UUID, "alterId": 0} })
	case spec.Trojan:
		in["type"] = "trojan"
		in["users"] = mapUsers(users, func(u spec.User) m { return m{"name": spec.InboundUser(u.Name, ib.Tag), "password": u.Password} })
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
			return m{"name": spec.InboundUser(u.Name, ib.Tag), "password": pw}
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
		in["users"] = mapUsers(users, func(u spec.User) m { return m{"name": spec.InboundUser(u.Name, ib.Tag), "password": u.Password} })
	case spec.TUIC:
		in["type"] = "tuic"
		if ib.CongestionControl != "" {
			in["congestion_control"] = ib.CongestionControl
		}
		in["users"] = mapUsers(users, func(u spec.User) m {
			return m{"name": spec.InboundUser(u.Name, ib.Tag), "uuid": u.UUID, "password": u.Password}
		})
	case spec.AnyTLS:
		in["type"] = "anytls"
		if len(ib.PaddingScheme) > 0 {
			in["padding_scheme"] = ib.PaddingScheme
		}
		in["users"] = mapUsers(users, func(u spec.User) m { return m{"name": spec.InboundUser(u.Name, ib.Tag), "password": u.Password} })
	case spec.SOCKS:
		in["type"] = "socks"
		in["users"] = mapUsers(users, func(u spec.User) m { return m{"username": u.Name, "password": u.Password} })
	case spec.HTTP:
		in["type"] = "http"
		in["users"] = mapUsers(users, func(u spec.User) m { return m{"username": u.Name, "password": u.Password} })
	case spec.Naive:
		in["type"] = "naive"
		in["users"] = mapUsers(users, func(u spec.User) m { return m{"username": u.Name, "password": u.Password} })
	case spec.Snell:
		// sing-box speaks snell v5 (v4 is the same wire protocol without
		// the QUIC mode nobody implements), with one server psk and, in
		// multi-user mode, a key per user that the subscription hands out
		// as that user's psk.
		in["type"] = "snell"
		in["version"] = 5
		in["psk"] = ib.SnellPSK
		if strings.EqualFold(ib.SnellObfs, "http") {
			in["obfs_mode"] = "http"
		}
		if ib.SnellMultiUser {
			if len(users) == 0 {
				// Without users sing-box falls back to the shared-PSK
				// server, which every former subscriber can still use.
				return nil, fmt.Errorf("singbox: inbound %q: multi-user snell has no users yet", ib.Tag)
			}
			seen := map[string]bool{}
			for _, u := range users {
				if u.Password == "" {
					return nil, fmt.Errorf("singbox: inbound %q: user %q has no key", ib.Tag, u.Name)
				}
				if seen[u.Password] {
					return nil, fmt.Errorf("singbox: inbound %q: two users share a key", ib.Tag)
				}
				seen[u.Password] = true
			}
			in["users"] = mapUsers(users, func(u spec.User) m {
				return m{"name": spec.InboundUser(u.Name, ib.Tag), "userkey": u.Password}
			})
		}
	default:
		return nil, fmt.Errorf("singbox: inbound %q: unsupported protocol %s", ib.Tag, ib.Protocol)
	}

	if tls := renderTLS(ib.TLS); tls != nil {
		// TUIC clients (mihomo, sing-box, Stash) offer only "h3"; unlike
		// its hysteria2 inbound, sing-box's tuic inbound does not add it
		// by itself and the QUIC handshake fails with "server did not
		// select an ALPN protocol".
		if ib.Protocol == spec.TUIC && tls["alpn"] == nil {
			tls["alpn"] = []string{"h3"}
		}
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
	match = strings.TrimSpace(match)
	if match == "" {
		return
	}
	key, val, ok := cut(match, ":")
	if ok && strings.TrimSpace(val) == "" {
		return // an empty value would match every destination
	}
	val = strings.TrimSpace(val)
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
	case "keyword":
		rule["domain_keyword"] = appendStr(rule["domain_keyword"], val)
	case "regexp":
		rule["domain_regex"] = appendStr(rule["domain_regex"], val)
	case "ip", "ip_cidr":
		rule["ip_cidr"] = appendStr(rule["ip_cidr"], val)
	case "protocol":
		rule["protocol"] = appendStr(rule["protocol"], val)
	case "port":
		// sing-box wants single ports in "port" and ranges as "a:b".
		for _, part := range strings.Split(val, ",") {
			from, to, err := spec.ParsePortMatch(part)
			if err != nil {
				continue // refused by spec.ValidateMatch before it gets here
			}
			if from == to {
				list, _ := rule["port"].([]int)
				rule["port"] = append(list, from)
			} else {
				rule["port_range"] = appendStr(rule["port_range"], fmt.Sprintf("%d:%d", from, to))
			}
		}
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

func outboundTags(node *spec.Node) []string {
	out := []string{"direct"}
	for _, o := range node.Outbounds {
		if o.WARP == nil { // endpoints have no stats entry
			out = append(out, o.Tag)
		}
	}
	return out
}

func cloneM(src m) m {
	out := m{}
	for k, v := range src {
		if sub, ok := v.(m); ok {
			out[k] = cloneM(sub)
		} else {
			out[k] = v
		}
	}
	return out
}

func sortedKeys(mm map[string][]string) []string {
	keys := make([]string, 0, len(mm))
	for k := range mm {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// renderShadowTLS is the public listener: it speaks TLS to a real site and
// passes an authenticated client through to the inbound behind it
// (detour). Version 3 with one password per user, so the panel can tell
// users apart and revoke one of them.
func renderShadowTLS(ib spec.Inbound, users []spec.User, detour string) m {
	host, port := ib.ShadowTLS.HandshakeHostPort()
	return m{
		"type":        "shadowtls",
		"tag":         ib.Tag,
		"listen":      listenAddr(ib.Listen),
		"listen_port": ib.Port,
		"detour":      detour,
		"version":     3,
		"strict_mode": ib.ShadowTLS.StrictMode,
		"handshake":   m{"server": host, "server_port": port},
		"users": mapUsers(users, func(u spec.User) m {
			return m{"name": spec.InboundUser(u.Name, ib.Tag), "password": spec.ShadowTLSUserKey(u.UUID)}
		}),
	}
}
