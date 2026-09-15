package subscription

import (
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Egern renders the Egern (iOS) YAML: a `proxies:` list where each entry
// is `- <type>: {fields}` per https://egernapp.com/docs/configuration/proxies,
// optionally inside a full config template whose policy_groups carry the
// {{proxy_names}} placeholder. Written from the documentation only; mieru
// has no Egern client.
type Egern struct{}

func (Egern) Name() string        { return "egern" }
func (Egern) ContentType() string { return "text/yaml; charset=utf-8" }

func (e Egern) Render(lines []Line, acct Account) ([]byte, error) {
	return e.RenderWith(lines, acct, "")
}

func (Egern) RenderWith(lines []Line, _ Account, tpl string) ([]byte, error) {
	proxies := []any{}
	names := []Named{}
	for _, l := range lines {
		if p := egernProxy(l); p != nil {
			proxies = append(proxies, p)
			names = append(names, Named{Name: l.Name, Tags: l.Tags})
		}
	}
	if tpl == "" {
		tpl = DefaultTemplate("egern")
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(tpl), &doc); err != nil {
		return nil, err
	}
	if doc == nil {
		doc = map[string]any{}
	}
	doc["proxies"] = proxies
	// policy_groups: [- select: {name, policies: [..., "{{proxy_names}}"]}]
	if groups, ok := doc["policy_groups"].([]any); ok {
		for _, g := range groups {
			gm, ok := g.(map[string]any)
			if !ok {
				continue
			}
			for _, body := range gm {
				bm, ok := body.(map[string]any)
				if !ok {
					continue
				}
				list, ok := bm["policies"].([]any)
				if !ok {
					continue
				}
				expanded := make([]any, 0, len(list)+len(names))
				for _, item := range list {
					if s, ok := item.(string); ok {
						if list, ok := expandNames(s, names); ok {
							for _, n := range list {
								expanded = append(expanded, n)
							}
							continue
						}
					}
					expanded = append(expanded, item)
				}
				bm["policies"] = expanded
			}
		}
	}
	return yaml.Marshal(doc)
}

// egernProxy maps one line; nil when Egern cannot dial it.
func egernProxy(l Line) m {
	ib := l.Inbound
	base := m{"name": l.Name, "server": l.Host, "port": l.Port}
	var kind string
	switch ib.Protocol {
	case spec.Shadowsocks:
		kind = "shadowsocks"
		method := ib.Cipher
		if method == "chacha20-ietf-poly1305" {
			method = "chacha20-poly1305"
		}
		base["method"] = method
		base["password"] = ssPassword(l)
		base["udp_relay"] = true
	case spec.Trojan:
		if !hasTLS(l) || isReality(l) {
			return nil
		}
		kind = "trojan"
		base["password"] = l.Password
		base["sni"] = serverName(l)
		base["udp_relay"] = true
		switch transportType(l) {
		case "ws":
			base["websocket"] = m{"path": ib.Transport.Path, "host": firstNonEmpty(ib.Transport.Host, serverName(l))}
		case "tcp":
		default:
			return nil
		}
	case spec.VLESS:
		kind = "vless"
		base["user_id"] = l.UUID
		base["udp_relay"] = true
		tr := egernTransport(l, true)
		if tr == nil {
			return nil
		}
		if len(tr) > 0 {
			base["transport"] = tr
		}
		if ib.Flow != "" && transportType(l) == "tcp" && hasTLS(l) {
			base["flow"] = ib.Flow
		}
	case spec.VMess:
		kind = "vmess"
		base["user_id"] = l.UUID
		base["security"] = "auto"
		base["udp_relay"] = true
		tr := egernTransport(l, false)
		if tr == nil {
			return nil
		}
		if len(tr) > 0 {
			base["transport"] = tr
		}
	case spec.Hysteria2:
		kind = "hysteria2"
		base["auth"] = l.Password
		if sn := serverName(l); sn != "" {
			base["sni"] = sn
		}
		if ib.Obfs != "" {
			base["obfs"] = ib.Obfs
			base["obfs_password"] = ib.ObfsPassword
		}
	case spec.TUIC:
		kind = "tuic"
		base["uuid"] = l.UUID
		base["password"] = l.Password
		base["alpn"] = []string{"h3"}
		base["udp_relay_mode"] = "native"
		if sn := serverName(l); sn != "" {
			base["sni"] = sn
		}
	case spec.AnyTLS:
		kind = "anytls"
		base["password"] = l.Password
		if sn := serverName(l); sn != "" {
			base["sni"] = sn
		}
	case spec.Snell:
		kind = "snell"
		base["psk"] = ib.SnellPSK
		v := ib.SnellVersion
		if v == 0 {
			v = 5
		}
		base["version"] = v
		base["udp_relay"] = true
		if ib.SnellObfs != "" && ib.SnellObfs != "off" {
			base["obfs"] = ib.SnellObfs
			if ib.SnellObfsHost != "" {
				base["obfs_host"] = ib.SnellObfsHost
			}
		}
	case spec.SOCKS, spec.HTTP:
		kind = "socks5"
		if ib.Protocol == spec.HTTP {
			kind = "http"
		}
		base["username"] = l.UUID
		base["password"] = l.Password
		if ib.Protocol == spec.SOCKS {
			base["udp_relay"] = true
		}
	case spec.WireGuard:
		c, ok := WGClient(l)
		if !ok {
			return nil
		}
		kind = "wireguard"
		base["private_key"] = c.PrivateKey
		base["peer_public_key"] = c.ServerPublicKey
		base["local_ipv4"] = strings.TrimSuffix(c.Address, "/32")
		base["mtu"] = c.MTU
	default:
		return nil
	}
	return m{kind: base}
}

// egernTransport builds the vmess/vless transport block: {} for plain TCP,
// nil for transports Egern cannot do.
func egernTransport(l Line, allowReality bool) m {
	ib := l.Inbound
	tls := m{}
	if hasTLS(l) {
		if sn := serverName(l); sn != "" {
			tls["sni"] = sn
		}
		if isReality(l) {
			if !allowReality {
				return nil
			}
			r := ib.TLS.Reality
			rl := m{"public_key": r.PublicKey}
			if len(r.ShortIDs) > 0 {
				rl["short_id"] = r.ShortIDs[0]
			}
			tls["reality"] = rl
		}
	}
	switch transportType(l) {
	case "tcp":
		if !hasTLS(l) {
			return m{}
		}
		return m{"tls": tls}
	case "ws":
		w := m{"path": ib.Transport.Path}
		if ib.Transport.Host != "" {
			w["headers"] = m{"Host": ib.Transport.Host}
		}
		if hasTLS(l) {
			for k, v := range tls {
				w[k] = v
			}
			return m{"wss": w}
		}
		return m{"ws": w}
	case "grpc":
		g := m{"service_name": ib.Transport.ServiceName}
		for k, v := range tls {
			g[k] = v
		}
		return m{"grpc": g}
	case "http":
		h := m{"path": firstNonEmpty(ib.Transport.Path, "/")}
		if ib.Transport.Host != "" {
			h["headers"] = m{"Host": ib.Transport.Host}
		}
		for k, v := range tls {
			h[k] = v
		}
		return m{"http2": h}
	}
	return nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
