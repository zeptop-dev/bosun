package xray

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"github.com/zeptop-dev/bosun/pkg/wg"
)

type m = map[string]any

type renderOptions struct {
	LogLevel  string
	APIListen string
}

// state is carried from Render to Start/Apply so Apply can decide between a
// hot user update and a restart.
type state struct {
	inboundsKey string                          // hash of inbounds without users
	users       map[string]map[string]spec.User // tag -> user name -> user
	inbounds    map[string]spec.Protocol        // tag -> protocol
	flows       map[string]string               // tag -> vless flow
}

// render produces an Xray JSON configuration for the given inbounds.
func render(node *spec.Node, inbounds []spec.Inbound, users []spec.User, opt renderOptions) ([]byte, *state, error) {
	if len(inbounds) == 0 {
		return nil, nil, fmt.Errorf("xray: nothing to render")
	}
	st := &state{
		users:    make(map[string]map[string]spec.User, len(inbounds)),
		inbounds: make(map[string]spec.Protocol, len(inbounds)),
		flows:    map[string]string{},
	}

	ins := make([]any, 0, len(inbounds))
	keyParts := make([]string, 0, len(inbounds))
	for _, ib := range inbounds {
		ibUsers := ib.EffectiveUsers(users)
		in, err := renderInbound(ib, ibUsers)
		if err != nil {
			return nil, nil, err
		}
		ins = append(ins, in)
		st.inbounds[ib.Tag] = ib.Protocol
		st.flows[ib.Tag] = ib.Flow
		byName := make(map[string]spec.User, len(ibUsers))
		for _, u := range ibUsers {
			byName[u.Name] = u
		}
		st.users[ib.Tag] = byName
		// Key excludes users: same key means only users may have changed.
		noUsers, err := renderInbound(ib, nil)
		if err != nil {
			return nil, nil, err
		}
		kb, _ := json.Marshal(noUsers)
		keyParts = append(keyParts, string(kb))
	}
	// Outbounds, routing, DNS and the per-user limits also need a restart
	// when they change; users alone can be hot-swapped.
	if kb, err := json.Marshal(m{"o": node.Outbounds, "r": node.Routes, "d": node.DefaultOutbound, "dns": node.DNS, "lim": limitedUsers(node, users)}); err == nil {
		keyParts = append(keyParts, string(kb))
	}
	sum := sha256.Sum256([]byte(strings.Join(keyParts, "\n")))
	st.inboundsKey = hex.EncodeToString(sum[:8])

	// Xray routes unmatched traffic to the first outbound, so the default
	// outbound (a landing server) goes first when one is set.
	direct := m{"tag": "direct", "protocol": "freedom"}
	block := m{"tag": "block", "protocol": "blackhole"}
	var custom []any
	var def m
	for _, o := range node.Outbounds {
		if o.Balancer != nil {
			continue // rendered under routing.balancers
		}
		var ro m
		switch {
		case o.WARP != nil:
			ro = renderWARP(o)
		case o.Remote != nil:
			var err error
			if ro, err = renderRemote(o); err != nil {
				return nil, nil, err
			}
		default:
			ro = renderOutbound(o)
		}
		if node.DefaultOutbound != "" && o.Tag == node.DefaultOutbound {
			def = ro
			continue
		}
		custom = append(custom, ro)
	}
	outs := []any{}
	if def != nil {
		outs = append(outs, def)
	}
	outs = append(outs, direct, block)
	outs = append(outs, custom...)
	// Per-user speed limits: a marking clone of the default exit per user
	// plus a rule that sends that user's traffic through it.
	var limitRules []any
	for _, lu := range limitedUsers(node, users) {
		base := m{"protocol": "freedom"}
		if def != nil {
			base = cloneM(def)
		}
		base["tag"] = spec.SpeedTag(lu.ID)
		ss, _ := base["streamSettings"].(m)
		if ss == nil {
			ss = m{}
		}
		ss["sockopt"] = m{"mark": spec.SpeedMark(lu.ID)}
		base["streamSettings"] = ss
		outs = append(outs, base)
		// Routing matches the email, which carries the inbound tag: one
		// entry per inbound the user is on.
		var emails []string
		for _, ib := range inbounds {
			for _, u := range ib.EffectiveUsers(users) {
				if u.ID == lu.ID {
					emails = append(emails, spec.InboundUser(u.Name, ib.Tag))
				}
			}
		}
		if len(emails) == 0 {
			emails = []string{lu.Name}
		}
		limitRules = append(limitRules, m{"type": "field", "user": emails, "outboundTag": spec.SpeedTag(lu.ID)})
	}

	cfg := m{
		"log": m{"loglevel": opt.LogLevel},
		"api": m{
			"tag":      "api",
			"listen":   opt.APIListen,
			"services": []string{"HandlerService", "StatsService"},
		},
		"stats": m{},
		"policy": m{
			"levels": m{"0": m{"statsUserUplink": true, "statsUserDownlink": true, "statsUserOnline": true}},
			"system": m{"statsInboundUplink": true, "statsInboundDownlink": true, "statsOutboundUplink": true, "statsOutboundDownlink": true},
		},
		"inbounds":  ins,
		"outbounds": outs,
		"routing":   m{"domainStrategy": "AsIs", "rules": renderRoutes(node.Routes, balancerTags(node), node.DefaultOutbound, limitRules)},
	}
	if bal := renderBalancers(node); len(bal) > 0 {
		cfg["routing"].(m)["balancers"] = bal
		cfg["observatory"] = m{"subjectSelector": balancerMembers(node), "probeUrl": "https://www.gstatic.com/generate_204", "probeInterval": "1m", "enableConcurrency": true}
	}
	if len(node.DNS) > 0 {
		cfg["dns"] = m{"servers": dnsServers(node.DNS)}
	}
	if err := core.ApplyOverride("xray", cfg, node.Overrides["xray"]); err != nil {
		return nil, nil, fmt.Errorf("xray: %w", err)
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	return b, st, err
}

func renderInbound(ib spec.Inbound, users []spec.User) (m, error) {
	in := m{
		"tag":      ib.Tag,
		"listen":   listenAddr(ib.Listen),
		"port":     ib.Port,
		"sniffing": m{"enabled": !ib.NoSniff, "destOverride": []string{"http", "tls", "quic"}},
	}
	switch ib.Protocol {
	case spec.VLESS:
		in["protocol"] = "vless"
		in["settings"] = m{"decryption": "none", "clients": mapUsers(users, func(u spec.User) m {
			return vlessClient(u, ib)
		})}
	case spec.VMess:
		in["protocol"] = "vmess"
		in["settings"] = m{"clients": mapUsers(users, func(u spec.User) m { return m{"id": u.UUID, "email": spec.InboundUser(u.Name, ib.Tag)} })}
	case spec.Trojan:
		in["protocol"] = "trojan"
		in["settings"] = m{"clients": mapUsers(users, func(u spec.User) m { return m{"password": u.Password, "email": spec.InboundUser(u.Name, ib.Tag)} })}
	case spec.Shadowsocks:
		if strings.HasPrefix(ib.Cipher, "2022-") {
			return nil, fmt.Errorf("xray: inbound %q: shadowsocks 2022 multi-user is served by sing-box, not xray", ib.Tag)
		}
		in["protocol"] = "shadowsocks"
		in["settings"] = m{
			"network": "tcp,udp",
			"clients": mapUsers(users, func(u spec.User) m {
				return m{"method": ib.Cipher, "password": u.Password, "email": spec.InboundUser(u.Name, ib.Tag)}
			}),
		}
	case spec.SOCKS:
		in["protocol"] = "socks"
		in["settings"] = m{"auth": "password", "udp": true, "accounts": mapUsers(users, func(u spec.User) m {
			return m{"user": u.Name, "pass": u.Password}
		})}
	case spec.HTTP:
		in["protocol"] = "http"
		in["settings"] = m{"accounts": mapUsers(users, func(u spec.User) m { return m{"user": u.Name, "pass": u.Password} })}
	case spec.WireGuard:
		if ib.WGPrivateKey == "" {
			return nil, fmt.Errorf("xray: inbound %q: wireguard needs a private key", ib.Tag)
		}
		mtu := ib.WGMTU
		if mtu <= 0 {
			mtu = wg.DefaultMTU
		}
		peers := []m{}
		for _, u := range users {
			_, pub, err := wg.DerivePeer(ib.WGPrivateKey, u.UUID)
			if err != nil {
				return nil, fmt.Errorf("xray: inbound %q: %w", ib.Tag, err)
			}
			peers = append(peers, m{"publicKey": pub, "allowedIPs": []string{wg.ClientAddress(u.ID)}, "email": u.Name})
		}
		in["protocol"] = "wireguard"
		in["settings"] = m{"secretKey": ib.WGPrivateKey, "mtu": mtu, "peers": peers, "noKernelTun": true}
		delete(in, "sniffing")
		return in, nil
	default:
		return nil, fmt.Errorf("xray: inbound %q: unsupported protocol %s", ib.Tag, ib.Protocol)
	}

	if len(ib.Fallbacks) > 0 {
		if ib.Protocol != spec.VLESS && ib.Protocol != spec.Trojan {
			return nil, fmt.Errorf("xray: inbound %q: fallbacks need VLESS or Trojan", ib.Tag)
		}
		if ib.TransportType() != "tcp" || ib.TLS == nil || ib.TLS.Mode != spec.TLSStandard {
			return nil, fmt.Errorf("xray: inbound %q: fallbacks need TCP with standard TLS", ib.Tag)
		}
		var fbs []m
		for _, f := range ib.Fallbacks {
			if strings.Contains(f.Dest, "/") || strings.Contains(f.Dest, "\\") {
				// A unix socket dest would hand every failed handshake to
				// that socket as root (think docker.sock); ports only.
				return nil, fmt.Errorf("xray: inbound %q: fallback dest must be a port or host:port", ib.Tag)
			}
			fb := m{"dest": fallbackDest(f.Dest)}
			if f.Name != "" {
				fb["name"] = f.Name
			}
			if f.ALPN != "" {
				fb["alpn"] = f.ALPN
			}
			if f.Path != "" {
				fb["path"] = f.Path
			}
			if f.Xver > 0 {
				fb["xver"] = f.Xver
			}
			fbs = append(fbs, fb)
		}
		in["settings"].(m)["fallbacks"] = fbs
	}
	ss, err := renderStream(ib)
	if err != nil {
		return nil, fmt.Errorf("xray: inbound %q: %w", ib.Tag, err)
	}
	in["streamSettings"] = ss
	return in, nil
}

// fallbackDest keeps a bare port numeric (xray wants an int there) and
// passes host:port or a socket path through.
func fallbackDest(d string) any {
	if n, err := strconv.Atoi(strings.TrimSpace(d)); err == nil {
		return n
	}
	return strings.TrimSpace(d)
}

func vlessClient(u spec.User, ib spec.Inbound) m {
	c := m{"id": u.UUID, "email": spec.InboundUser(u.Name, ib.Tag)}
	if ib.Flow != "" && ib.TLS != nil && ib.TransportType() == "tcp" {
		c["flow"] = ib.Flow
	}
	return c
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

func renderStream(ib spec.Inbound) (m, error) {
	ss := m{}
	tr := ib.Transport
	switch ib.TransportType() {
	case "tcp":
		ss["network"] = "raw"
	case "ws":
		ss["network"] = "ws"
		w := m{"path": tr.Path}
		if tr.Host != "" {
			w["host"] = tr.Host
		}
		ss["wsSettings"] = w
	case "grpc":
		ss["network"] = "grpc"
		ss["grpcSettings"] = m{"serviceName": tr.ServiceName}
	case "httpupgrade":
		ss["network"] = "httpupgrade"
		h := m{"path": tr.Path}
		if tr.Host != "" {
			h["host"] = tr.Host
		}
		ss["httpupgradeSettings"] = h
	case "xhttp":
		ss["network"] = "xhttp"
		x := m{"path": tr.Path}
		if tr.Host != "" {
			x["host"] = tr.Host
		}
		if tr.Mode != "" {
			x["mode"] = tr.Mode
		}
		ss["xhttpSettings"] = x
	default:
		return nil, fmt.Errorf("unsupported transport %q", ib.TransportType())
	}

	t := ib.TLS
	switch {
	case t == nil || t.Mode == spec.TLSNone:
		ss["security"] = "none"
	case t.Mode == spec.TLSReality:
		if t.Reality == nil || t.Reality.PrivateKey == "" {
			return nil, fmt.Errorf("reality requires a private key")
		}
		r := t.Reality
		ss["security"] = "reality"
		rs := m{
			"show":        false,
			"target":      r.HandshakeServer + ":" + strconv.Itoa(r.HandshakePort),
			"serverNames": []string{t.ServerName},
			"privateKey":  r.PrivateKey,
			"shortIds":    r.ShortIDs,
		}
		if lim, on := r.EffectiveFallbackLimit(); on {
			bucket := m{"afterBytes": lim.AfterBytes, "bytesPerSec": lim.BytesPerSec, "burstBytesPerSec": lim.BurstBytesPerSec}
			rs["limitFallbackUpload"] = bucket
			rs["limitFallbackDownload"] = bucket
		}
		ss["realitySettings"] = rs
	default:
		if t.CertPath == "" || t.KeyPath == "" {
			return nil, fmt.Errorf("tls requires certificate and key paths")
		}
		tls := m{
			"certificates": []any{m{"certificateFile": t.CertPath, "keyFile": t.KeyPath}},
		}
		if t.ServerName != "" {
			tls["serverName"] = t.ServerName
		}
		if len(t.ALPN) > 0 {
			tls["alpn"] = t.ALPN
		}
		ss["security"] = "tls"
		ss["tlsSettings"] = tls
	}
	if ib.AcceptProxyProtocol {
		// Relays in front send a PROXY protocol header; xray reads the
		// client address from it (device counting, access logs).
		so, _ := ss["sockopt"].(m)
		if so == nil {
			so = m{}
		}
		so["acceptProxyProtocol"] = true
		ss["sockopt"] = so
	}
	return ss, nil
}

// renderOutbound passes a panel-defined outbound through in Xray's layout.
// Settings is the outbound's "settings" body; a "streamSettings" key inside
// it is lifted to the outbound level.
func renderOutbound(o spec.Outbound) m {
	out := m{"tag": o.Tag, "protocol": o.Protocol}
	settings := m{}
	for k, v := range o.Settings {
		if k == "streamSettings" {
			out["streamSettings"] = v
			continue
		}
		settings[k] = v
	}
	out["settings"] = settings
	if o.ProxyTag != "" {
		out["proxySettings"] = m{"tag": o.ProxyTag}
	}
	return out
}

// limitedUsers lists users with an effective speed limit.
func limitedUsers(node *spec.Node, users []spec.User) []spec.User {
	var out []spec.User
	for _, u := range users {
		if l := node.EffectiveSpeedLimit(u); l > 0 {
			u.SpeedLimitMbps = l
			out = append(out, u)
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

func renderRoutes(rules []spec.RouteRule, balancers map[string]bool, def string, limitRules []any) []any {
	out := []any{
		m{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"},
	}
	for _, r := range rules {
		rule := m{"type": "field"}
		for _, match := range r.Match {
			addMatch(rule, match)
		}
		switch r.Action {
		case "block":
			rule["outboundTag"] = "block"
		case "outbound":
			if balancers[r.Value] {
				rule["balancerTag"] = r.Value
			} else {
				rule["outboundTag"] = r.Value
			}
		default:
			rule["outboundTag"] = "direct"
		}
		out = append(out, rule)
	}
	// Limited users come after the explicit split rules (those keep their
	// exits) and before any catch-all.
	out = append(out, limitRules...)
	// xray has no "default balancer": a catch-all rule does the job.
	if def != "" && balancers[def] {
		out = append(out, m{"type": "field", "network": "tcp,udp", "balancerTag": def})
	}
	return out
}

func balancerTags(node *spec.Node) map[string]bool {
	out := map[string]bool{}
	for _, o := range node.Outbounds {
		if o.Balancer != nil {
			out[o.Tag] = true
		}
	}
	return out
}

func balancerMembers(node *spec.Node) []string {
	seen := map[string]bool{}
	var out []string
	for _, o := range node.Outbounds {
		if o.Balancer == nil {
			continue
		}
		for _, mbr := range o.Balancer.Members {
			if !seen[mbr] {
				seen[mbr] = true
				out = append(out, mbr)
			}
		}
	}
	return out
}

func renderBalancers(node *spec.Node) []any {
	var out []any
	for _, o := range node.Outbounds {
		if o.Balancer == nil {
			continue
		}
		strategy := m{"type": "leastPing"}
		if o.Balancer.Strategy == "random" {
			strategy = m{"type": "random"}
		}
		out = append(out, m{"tag": o.Tag, "selector": o.Balancer.Members, "strategy": strategy})
	}
	return out
}

// dnsServers maps "1.1.1.1", "tls://host", "https://host/path" to xray's
// server addresses (xray takes the URL forms as-is).
func dnsServers(list []string) []any {
	out := make([]any, 0, len(list))
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "tls://") {
			s = "tcp+" + s
		}
		out = append(out, s)
	}
	return out
}

func addMatch(rule m, match string) {
	key, val, ok := strings.Cut(match, ":")
	if !ok {
		rule["domain"] = appendStr(rule["domain"], "domain:"+match)
		return
	}
	switch key {
	case "inbound":
		rule["inboundTag"] = appendStr(rule["inboundTag"], val)
	case "domain":
		rule["domain"] = appendStr(rule["domain"], "domain:"+val)
	case "full":
		rule["domain"] = appendStr(rule["domain"], "full:"+val)
	case "ip", "ip_cidr":
		rule["ip"] = appendStr(rule["ip"], val)
	case "protocol":
		rule["protocol"] = appendStr(rule["protocol"], val)
	case "port":
		rule["port"] = val
	case "geosite":
		rule["domain"] = appendStr(rule["domain"], "geosite:"+val)
	case "geoip":
		rule["ip"] = appendStr(rule["ip"], "geoip:"+val)
	default:
		rule["domain"] = appendStr(rule["domain"], "domain:"+match)
	}
}

func appendStr(cur any, s string) []string {
	list, _ := cur.([]string)
	return append(list, s)
}

// renderWARP is a WireGuard outbound to Cloudflare WARP.
func renderWARP(o spec.Outbound) m {
	w := o.WARP
	ep := w.Endpoint
	if ep == "" {
		ep = "engage.cloudflareclient.com:2408"
	}
	// gVisor, not the kernel TUN: with kernel TUN the tunnel came up but
	// nothing came back (live test on Debian 13, Xray 26.3.27); gVisor is
	// also what the WireGuard inbound uses. IPv4 first inside the tunnel.
	out := m{"tag": o.Tag, "protocol": "wireguard", "settings": m{
		"secretKey": w.PrivateKey, "address": w.Addresses, "mtu": 1280, "domainStrategy": "ForceIPv4v6", "noKernelTun": true,
		"peers": []m{{"publicKey": w.PeerPublicKey, "endpoint": ep, "allowedIPs": []string{"0.0.0.0/0", "::/0"}}},
	}}
	if len(w.Reserved) == 3 {
		out["settings"].(m)["reserved"] = w.Reserved
	}
	if o.ProxyTag != "" {
		out["streamSettings"] = m{"sockopt": m{"dialerProxy": o.ProxyTag}}
	}
	return out
}
