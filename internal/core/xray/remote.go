package xray

import (
	"fmt"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// renderRemote turns a core-agnostic Remote into an Xray outbound. Xray has
// no hysteria2/tuic/anytls client, so those are refused here and should be
// served by sing-box instead.
func renderRemote(o spec.Outbound) (m, error) {
	r := o.Remote
	s := r.Settings
	out := m{"tag": o.Tag}
	if o.ProxyTag != "" {
		out["proxySettings"] = m{"tag": o.ProxyTag}
	}
	switch s.Protocol {
	case spec.VLESS:
		user := m{"id": r.UUID, "encryption": "none"}
		if s.Flow != "" {
			user["flow"] = s.Flow
		}
		out["protocol"] = "vless"
		out["settings"] = m{"vnext": []any{m{"address": r.Host, "port": r.Port, "users": []any{user}}}}
	case spec.VMess:
		out["protocol"] = "vmess"
		out["settings"] = m{"vnext": []any{m{"address": r.Host, "port": r.Port, "users": []any{m{"id": r.UUID, "security": "auto"}}}}}
	case spec.Trojan:
		out["protocol"] = "trojan"
		out["settings"] = m{"servers": []any{m{"address": r.Host, "port": r.Port, "password": r.Password}}}
	case spec.Shadowsocks:
		out["protocol"] = "shadowsocks"
		out["settings"] = m{"servers": []any{m{"address": r.Host, "port": r.Port, "method": s.Cipher, "password": r.Password}}}
	case spec.SOCKS, spec.HTTP:
		srv := m{"address": r.Host, "port": r.Port}
		if r.Username != "" {
			srv["users"] = []any{m{"user": r.Username, "pass": r.Password}}
		}
		out["protocol"] = string(s.Protocol)
		out["settings"] = m{"servers": []any{srv}}
	default:
		return nil, fmt.Errorf("xray: outbound %q: protocol %q has no Xray client; serve it with sing-box", o.Tag, s.Protocol)
	}
	ss := m{"network": s.TransportType()}
	switch tr := s.Transport; s.TransportType() {
	case "ws":
		w := m{"path": tr.Path}
		if tr.Host != "" {
			w["headers"] = m{"Host": tr.Host}
		}
		ss["wsSettings"] = w
	case "grpc":
		ss["grpcSettings"] = m{"serviceName": tr.ServiceName}
	case "httpupgrade":
		h := m{"path": tr.Path}
		if tr.Host != "" {
			h["host"] = tr.Host
		}
		ss["httpupgradeSettings"] = h
	case "xhttp":
		x := m{"path": tr.Path}
		if tr.Host != "" {
			x["host"] = tr.Host
		}
		if tr.Mode != "" {
			x["mode"] = tr.Mode
		}
		ss["xhttpSettings"] = x
	case "http":
		ss["network"] = "h2"
		h := m{"path": tr.Path}
		if tr.Host != "" {
			h["host"] = []string{tr.Host}
		}
		ss["httpSettings"] = h
	}
	if t := s.TLS; t != nil && t.Mode != spec.TLSNone {
		fp := r.Fingerprint
		if fp == "" {
			fp = "chrome"
		}
		if t.Mode == spec.TLSReality && t.Reality != nil {
			ss["security"] = "reality"
			rl := m{"serverName": t.ServerName, "fingerprint": fp, "publicKey": t.Reality.PublicKey}
			if len(t.Reality.ShortIDs) > 0 {
				rl["shortId"] = t.Reality.ShortIDs[0]
			}
			ss["realitySettings"] = rl
		} else {
			ss["security"] = "tls"
			tls := m{"serverName": t.ServerName, "fingerprint": fp, "allowInsecure": r.Insecure}
			if len(t.ALPN) > 0 {
				tls["alpn"] = t.ALPN
			}
			ss["tlsSettings"] = tls
		}
	}
	out["streamSettings"] = ss
	return out, nil
}
