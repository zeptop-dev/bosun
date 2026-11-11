package subscription

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// surgeVLESSLine follows https://manual.nssurge.com/policies/vless.html.
// Unsupported combinations are omitted, never downgraded to plain TCP/TLS.
func surgeVLESSLine(l Line) string {
	ib := l.Inbound
	transport := transportType(l)
	tls := ib.TLS != nil && ib.TLS.Mode == spec.TLSStandard
	reality := isReality(l)
	if ib.TLS != nil && ib.TLS.Mode != spec.TLSNone && !tls && !reality {
		return ""
	}
	switch transport {
	case "tcp":
	case "ws":
		if reality {
			return ""
		}
	case "grpc":
		if !tls && !reality {
			return ""
		}
	default:
		return ""
	}
	if ib.Flow != "" && (transport != "tcp" || (!tls && !reality) || (ib.Flow != "xtls-rprx-vision" && ib.Flow != "xtls-rprx-vision-udp443")) {
		return ""
	}
	// INI fields cannot safely carry field/line delimiters. Do not sanitize
	// credentials, hostnames or transport paths into different values.
	fields := []string{l.Host, l.UUID, serverName(l)}
	if l.Host == "" || l.UUID == "" || l.Port < 1 || l.Port > 65535 {
		return ""
	}
	parts := []string{"username=" + l.UUID}
	if l.IPVersion != "" {
		parts = append(parts, "ip-version="+map[string]string{"ipv4": "v4-only", "ipv6": "v6-only", "dual": "dual"}[l.IPVersion])
	}
	if tls {
		parts = append(parts, "tls=true")
	}
	if sn := serverName(l); sn != "" {
		parts = append(parts, "sni="+sn)
	}
	if reality {
		r := ib.TLS.Reality
		fields = append(fields, r.PublicKey)
		key, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(r.PublicKey, "="))
		if err != nil || len(key) != 32 || serverName(l) == "" {
			return ""
		}
		sid := ""
		if len(r.ShortIDs) > 0 {
			sid = r.ShortIDs[0]
		}
		if _, err := hex.DecodeString(sid); err != nil || len(sid) > 16 {
			return ""
		}
		parts = append(parts, "reality-public-key="+r.PublicKey, "reality-short-id="+sid)
	}
	if ib.Flow != "" {
		parts = append(parts, "flow="+ib.Flow)
	}
	if ib.TLS != nil && (tls || reality) && len(ib.TLS.ALPN) > 0 {
		fields = append(fields, ib.TLS.ALPN...)
		parts = append(parts, "alpn=\""+strings.Join(ib.TLS.ALPN, ",")+"\"")
	}
	if tr := ib.Transport; tr != nil {
		switch transport {
		case "ws":
			fields = append(fields, tr.Path, tr.Host)
			if strings.Contains(tr.Host, "|") {
				return ""
			}
			parts = append(parts, "ws=true")
			if tr.Path != "" {
				parts = append(parts, "ws-path="+tr.Path)
			}
			if tr.Host != "" {
				parts = append(parts, "ws-headers=Host:"+tr.Host)
			}
		case "grpc":
			fields = append(fields, tr.ServiceName, tr.Host)
			parts = append(parts, "grpc=true")
			if tr.ServiceName != "" {
				parts = append(parts, "grpc-service-name="+tr.ServiceName)
			}
			// Transport.Host is a WebSocket host in the current server renderers;
			// it does not define a gRPC authority. Do not invent a mapping.
		}
	}
	for _, field := range fields {
		if strings.ContainsAny(field, ",;\"\\") || strings.IndexFunc(field, unicode.IsControl) >= 0 || strings.TrimSpace(field) != field {
			return ""
		}
	}
	return fmt.Sprintf("%s = vless, %s, %d, %s", iniName(l.Name), l.Host, l.Port, strings.Join(parts, ", "))
}
