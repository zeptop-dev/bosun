package singbox

import (
	"fmt"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// renderRemote turns a core-agnostic Remote into a sing-box outbound.
func renderRemote(o spec.Outbound) (m, error) {
	r := o.Remote
	s := r.Settings
	out := m{"tag": o.Tag, "server": r.Host, "server_port": r.Port}
	if o.ProxyTag != "" {
		out["detour"] = o.ProxyTag
	}
	switch s.Protocol {
	case spec.VLESS:
		out["type"], out["uuid"] = "vless", r.UUID
		if s.Flow != "" {
			out["flow"] = s.Flow
		}
	case spec.VMess:
		out["type"], out["uuid"], out["security"], out["alter_id"] = "vmess", r.UUID, "auto", 0
	case spec.Trojan:
		out["type"], out["password"] = "trojan", r.Password
	case spec.Shadowsocks:
		out["type"], out["method"], out["password"] = "shadowsocks", s.Cipher, r.Password
	case spec.Hysteria2:
		out["type"], out["password"] = "hysteria2", r.Password
		if s.Obfs != "" {
			out["obfs"] = m{"type": s.Obfs, "password": s.ObfsPassword}
		}
		if s.UpMbps > 0 {
			out["up_mbps"] = s.UpMbps
		}
		if s.DownMbps > 0 {
			out["down_mbps"] = s.DownMbps
		}
	case spec.TUIC:
		out["type"], out["uuid"], out["password"] = "tuic", r.UUID, r.Password
		if s.CongestionControl != "" {
			out["congestion_control"] = s.CongestionControl
		}
		out["udp_relay_mode"] = "native"
	case spec.AnyTLS:
		out["type"], out["password"] = "anytls", r.Password
	case spec.SOCKS:
		out["type"] = "socks"
		if r.Username != "" {
			out["username"], out["password"] = r.Username, r.Password
		}
	case spec.HTTP:
		out["type"] = "http"
		if r.Username != "" {
			out["username"], out["password"] = r.Username, r.Password
		}
	default:
		return nil, fmt.Errorf("singbox: outbound %q: unsupported remote protocol %q", o.Tag, s.Protocol)
	}
	if tls := remoteTLS(r); tls != nil {
		out["tls"] = tls
	}
	if tr := renderTransport(s.Transport); tr != nil {
		out["transport"] = tr
	}
	if mx := renderMultiplex(s.Multiplex); mx != nil {
		out["multiplex"] = mx
	}
	return out, nil
}

// remoteTLS is the client side of TLS: SNI, uTLS fingerprint, REALITY
// public key / short id, optional insecure.
func remoteTLS(r *spec.Remote) m {
	t := r.Settings.TLS
	quic := r.Settings.Protocol == spec.Hysteria2 || r.Settings.Protocol == spec.TUIC
	if (t == nil || t.Mode == spec.TLSNone) && !quic {
		return nil
	}
	out := m{"enabled": true}
	if t != nil && t.ServerName != "" {
		out["server_name"] = t.ServerName
	}
	if t != nil && len(t.ALPN) > 0 {
		out["alpn"] = t.ALPN
	}
	if r.Insecure {
		out["insecure"] = true
	}
	if !quic {
		fp := r.Fingerprint
		if fp == "" {
			fp = "chrome"
		}
		out["utls"] = m{"enabled": true, "fingerprint": fp}
	}
	if t != nil && t.Mode == spec.TLSReality && t.Reality != nil {
		rl := m{"enabled": true, "public_key": t.Reality.PublicKey}
		if len(t.Reality.ShortIDs) > 0 {
			rl["short_id"] = t.Reality.ShortIDs[0]
		}
		out["reality"] = rl
	}
	return out
}
