package xray

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"gitlab.com/zeptop-group/bosun/internal/spec"
)

type m = map[string]any

type renderOptions struct {
	LogLevel  string
	APIListen string
}

// state is carried from Render to Start/Apply so Apply can decide between a
// hot user update and a restart.
type state struct {
	inboundsKey string                   // hash of inbounds without users
	users       map[string]spec.User     // by name
	inbounds    map[string]spec.Protocol // tag -> protocol
	flows       map[string]string        // tag -> vless flow
}

// render produces an Xray JSON configuration for the given inbounds.
func render(node *spec.Node, inbounds []spec.Inbound, users []spec.User, opt renderOptions) ([]byte, *state, error) {
	if len(inbounds) == 0 {
		return nil, nil, fmt.Errorf("xray: nothing to render")
	}
	st := &state{
		users:    make(map[string]spec.User, len(users)),
		inbounds: make(map[string]spec.Protocol, len(inbounds)),
		flows:    map[string]string{},
	}
	for _, u := range users {
		st.users[u.Name] = u
	}

	ins := make([]any, 0, len(inbounds))
	keyParts := make([]string, 0, len(inbounds))
	for _, ib := range inbounds {
		in, err := renderInbound(ib, users)
		if err != nil {
			return nil, nil, err
		}
		ins = append(ins, in)
		st.inbounds[ib.Tag] = ib.Protocol
		st.flows[ib.Tag] = ib.Flow
		// Key excludes users: same key means only users may have changed.
		noUsers, err := renderInbound(ib, nil)
		if err != nil {
			return nil, nil, err
		}
		kb, _ := json.Marshal(noUsers)
		keyParts = append(keyParts, string(kb))
	}
	sum := sha256.Sum256([]byte(strings.Join(keyParts, "\n")))
	st.inboundsKey = hex.EncodeToString(sum[:8])

	outs := []any{
		m{"tag": "direct", "protocol": "freedom"},
		m{"tag": "block", "protocol": "blackhole"},
	}
	for _, o := range node.Outbounds {
		outs = append(outs, renderOutbound(o))
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
			"levels": m{"0": m{"statsUserUplink": true, "statsUserDownlink": true}},
			"system": m{"statsInboundUplink": false, "statsInboundDownlink": false},
		},
		"inbounds":  ins,
		"outbounds": outs,
		"routing":   m{"domainStrategy": "AsIs", "rules": renderRoutes(node.Routes)},
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	return b, st, err
}

func renderInbound(ib spec.Inbound, users []spec.User) (m, error) {
	in := m{
		"tag":      ib.Tag,
		"listen":   listenAddr(ib.Listen),
		"port":     ib.Port,
		"sniffing": m{"enabled": true, "destOverride": []string{"http", "tls", "quic"}},
	}
	switch ib.Protocol {
	case spec.VLESS:
		in["protocol"] = "vless"
		in["settings"] = m{"decryption": "none", "clients": mapUsers(users, func(u spec.User) m {
			return vlessClient(u, ib)
		})}
	case spec.VMess:
		in["protocol"] = "vmess"
		in["settings"] = m{"clients": mapUsers(users, func(u spec.User) m { return m{"id": u.UUID, "email": u.Name} })}
	case spec.Trojan:
		in["protocol"] = "trojan"
		in["settings"] = m{"clients": mapUsers(users, func(u spec.User) m { return m{"password": u.Password, "email": u.Name} })}
	case spec.Shadowsocks:
		if strings.HasPrefix(ib.Cipher, "2022-") {
			return nil, fmt.Errorf("xray: inbound %q: shadowsocks 2022 multi-user is served by sing-box, not xray", ib.Tag)
		}
		in["protocol"] = "shadowsocks"
		in["settings"] = m{
			"network": "tcp,udp",
			"clients": mapUsers(users, func(u spec.User) m {
				return m{"method": ib.Cipher, "password": u.Password, "email": u.Name}
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
	default:
		return nil, fmt.Errorf("xray: inbound %q: unsupported protocol %s", ib.Tag, ib.Protocol)
	}

	ss, err := renderStream(ib)
	if err != nil {
		return nil, fmt.Errorf("xray: inbound %q: %w", ib.Tag, err)
	}
	in["streamSettings"] = ss
	return in, nil
}

func vlessClient(u spec.User, ib spec.Inbound) m {
	c := m{"id": u.UUID, "email": u.Name}
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
		ss["realitySettings"] = m{
			"show":        false,
			"target":      r.HandshakeServer + ":" + strconv.Itoa(r.HandshakePort),
			"serverNames": []string{t.ServerName},
			"privateKey":  r.PrivateKey,
			"shortIds":    r.ShortIDs,
		}
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

func renderRoutes(rules []spec.RouteRule) []any {
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
			rule["outboundTag"] = r.Value
		default:
			rule["outboundTag"] = "direct"
		}
		out = append(out, rule)
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
	default:
		rule["domain"] = appendStr(rule["domain"], "domain:"+match)
	}
}

func appendStr(cur any, s string) []string {
	list, _ := cur.([]string)
	return append(list, s)
}
