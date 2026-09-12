package ui

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/zeptop-dev/bosun/internal/local"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Link is one share URI for a user on an inbound.
type Link struct {
	Tag  string `json:"tag"`
	Name string `json:"name"`
	URI  string `json:"uri"`
}

// linksFor renders share URIs for every enabled inbound the user may use.
func linksFor(u local.User, inbounds []local.Inbound, settings local.Settings, fallbackHost string) []Link {
	out := []Link{}
	for _, ib := range inbounds {
		if !ib.Enabled || !userAllowed(u, ib.Tag) {
			continue
		}
		// Connection address: the inbound's own override, else the node's
		// public host, else the TLS domain (it must point here anyway),
		// else whatever address the panel was reached on.
		h, p := settings.PublicHost, ib.Port
		if ib.DisplayHost != "" {
			h = ib.DisplayHost
		}
		if h == "" && ib.TLS != nil && ib.TLS.Mode == spec.TLSStandard && ib.TLS.ServerName != "" {
			h = ib.TLS.ServerName
		}
		if h == "" {
			h = fallbackHost
		}
		if ib.DisplayPort != 0 {
			p = ib.DisplayPort
		}
		name := ib.Tag
		if ib.Remark != "" {
			name = ib.Remark
		}
		if settings.NodeName != "" {
			name = settings.NodeName + " " + name
		}
		if uri := shareURI(ib.Inbound, h, p, name, u.Spec()); uri != "" {
			out = append(out, Link{Tag: ib.Tag, Name: name, URI: uri})
		}
	}
	return out
}

func userAllowed(u local.User, tag string) bool {
	if len(u.InboundTags) == 0 {
		return true
	}
	for _, t := range u.InboundTags {
		if t == tag {
			return true
		}
	}
	return false
}

func hasTLS(ib spec.Inbound) bool { return ib.TLS != nil && ib.TLS.Mode != spec.TLSNone }
func isReality(ib spec.Inbound) bool {
	return ib.TLS != nil && ib.TLS.Mode == spec.TLSReality && ib.TLS.Reality != nil
}
func serverName(ib spec.Inbound) string {
	if ib.TLS != nil {
		return ib.TLS.ServerName
	}
	return ""
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

// ss2022UserKey mirrors the cores' derivation: first n bytes of the UUID
// string, zero padded, base64.
func ss2022UserKey(uuid string, n int) string {
	buf := make([]byte, n)
	copy(buf, uuid)
	return base64.StdEncoding.EncodeToString(buf)
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func shareURI(ib spec.Inbound, host string, port int, name string, u spec.User) string {
	hostPort := hostPortOf(host, port)
	frag := "#" + url.PathEscape(name)
	switch ib.Protocol {
	case spec.VLESS:
		q := url.Values{}
		q.Set("encryption", "none")
		if ib.Flow != "" && hasTLS(ib) && ib.TransportType() == "tcp" {
			q.Set("flow", ib.Flow)
		}
		uriTLS(q, ib)
		uriTransport(q, ib)
		return "vless://" + u.UUID + "@" + hostPort + "?" + q.Encode() + frag
	case spec.VMess:
		v := map[string]string{"v": "2", "ps": name, "add": host, "port": strconv.Itoa(port), "id": u.UUID, "aid": "0", "scy": "auto",
			"net": vmessNet(ib), "type": "none", "host": "", "path": "", "tls": ""}
		if tr := ib.Transport; tr != nil {
			v["host"], v["path"] = tr.Host, tr.Path
			if tr.Type == "grpc" {
				v["path"] = tr.ServiceName
			}
		}
		if hasTLS(ib) {
			v["tls"] = "tls"
			v["sni"] = serverName(ib)
			v["fp"] = "chrome"
		}
		b, _ := json.Marshal(v)
		return "vmess://" + b64(string(b))
	case spec.Trojan:
		q := url.Values{}
		uriTLS(q, ib)
		uriTransport(q, ib)
		return "trojan://" + url.PathEscape(u.Password) + "@" + hostPort + "?" + q.Encode() + frag
	case spec.Shadowsocks:
		pw := u.Password
		if n := ss2022KeyLen(ib.Cipher); n > 0 {
			pw = ib.ServerKey + ":" + ss2022UserKey(u.UUID, n)
		}
		return "ss://" + b64(ib.Cipher+":"+pw) + "@" + hostPort + frag
	case spec.Hysteria2:
		q := url.Values{}
		if sn := serverName(ib); sn != "" {
			q.Set("sni", sn)
		}
		if ib.Obfs != "" {
			q.Set("obfs", ib.Obfs)
			q.Set("obfs-password", ib.ObfsPassword)
		}
		return "hysteria2://" + url.PathEscape(u.Password) + "@" + hostPort + "/?" + q.Encode() + frag
	case spec.TUIC:
		q := url.Values{}
		if sn := serverName(ib); sn != "" {
			q.Set("sni", sn)
		}
		if ib.CongestionControl != "" {
			q.Set("congestion_control", ib.CongestionControl)
		}
		q.Set("udp_relay_mode", "native")
		return "tuic://" + u.UUID + ":" + url.PathEscape(u.Password) + "@" + hostPort + "?" + q.Encode() + frag
	case spec.AnyTLS:
		q := url.Values{}
		if sn := serverName(ib); sn != "" {
			q.Set("sni", sn)
		}
		return "anytls://" + url.PathEscape(u.Password) + "@" + hostPort + "?" + q.Encode() + frag
	case spec.Mieru:
		q := url.Values{}
		q.Set("port", strconv.Itoa(port))
		proto := ib.MieruTransport
		if proto == "" {
			proto = "TCP"
		}
		q.Set("protocol", proto)
		q.Set("profile", name)
		return "mierus://" + url.PathEscape(u.UUID) + ":" + url.PathEscape(u.Password) + "@" + host + "?" + q.Encode()
	}
	return ""
}

func hostPortOf(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(port)
}

func vmessNet(ib spec.Inbound) string {
	switch ib.TransportType() {
	case "ws", "grpc", "httpupgrade", "xhttp":
		return ib.TransportType()
	case "http":
		return "h2"
	}
	return "tcp"
}

func uriTLS(q url.Values, ib spec.Inbound) {
	if !hasTLS(ib) {
		q.Set("security", "none")
		return
	}
	if isReality(ib) {
		r := ib.TLS.Reality
		q.Set("security", "reality")
		q.Set("pbk", r.PublicKey)
		if len(r.ShortIDs) > 0 {
			q.Set("sid", r.ShortIDs[0])
		}
	} else {
		q.Set("security", "tls")
	}
	if sn := serverName(ib); sn != "" {
		q.Set("sni", sn)
	}
	q.Set("fp", "chrome")
}

func uriTransport(q url.Values, ib spec.Inbound) {
	tr := ib.Transport
	t := ib.TransportType()
	switch t {
	case "tcp":
		q.Set("type", "tcp")
	case "ws", "httpupgrade", "xhttp":
		q.Set("type", t)
		if tr.Path != "" {
			q.Set("path", tr.Path)
		}
		if tr.Host != "" {
			q.Set("host", tr.Host)
		}
		if t == "xhttp" && tr.Mode != "" {
			q.Set("mode", tr.Mode)
		}
	case "grpc":
		q.Set("type", "grpc")
		q.Set("serviceName", tr.ServiceName)
	case "http":
		q.Set("type", "http")
		if tr.Path != "" {
			q.Set("path", tr.Path)
		}
		if tr.Host != "" {
			q.Set("host", tr.Host)
		}
	}
}
