package subscription

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Surge renders a Surge 5 proxy list. Surge speaks ss, vmess, trojan,
// hysteria2 and tuic; other protocols are skipped.
type Surge struct{}

// ErrSurgeDNSHostname prevents Surge's documented DIRECT fallback when an
// encrypted DNS connection uses a proxy whose hostname itself needs DNS.
var ErrSurgeDNSHostname = errors.New("Surge DNS protection requires IP-address proxy endpoints")

func (Surge) Name() string        { return "surge" }
func (Surge) ContentType() string { return "text/plain; charset=utf-8" }

func (s Surge) Render(lines []Line, acct Account) ([]byte, error) {
	return s.RenderWith(lines, acct, "")
}

func (Surge) RenderWith(lines []Line, _ Account, tpl string) ([]byte, error) {
	body, names := iniLines(lines, surgeLine)
	out := applyINI(tpl, "surge", body, names)
	if strings.Contains(tpl, "# captain-dns-protection: surge-ip-only") && !surgeDNSHasLiteralProxyEndpoints(string(out)) {
		return nil, ErrSurgeDNSHostname
	}
	return out, nil
}

// Inspect the final profile as well as generated proxies: an operator may edit
// a designer template to add static or remote candidates while keeping its DNS
// marker. Remote providers cannot be verified at subscription delivery time.
func surgeDNSHasLiteralProxyEndpoints(profile string) bool {
	section := ""
	for _, raw := range strings.Split(profile, "\n") {
		line := strings.TrimSpace(raw)
		// Includes and managed-profile directives can introduce candidates
		// after this validation. Their contents are deliberately not fetched.
		if strings.HasPrefix(line, "#!") {
			return false
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			// Designer sections never contain trailing comments. Fail closed
			// on edited headers rather than interpreting their rows as part
			// of a preceding non-proxy section.
			if !strings.HasSuffix(line, "]") {
				return false
			}
			section = strings.ToLower(line)
			switch section {
			case "[general]", "[proxy]", "[proxy group]", "[rule]", "[host]":
			default:
				return false
			}
			continue
		}
		if section != "[proxy]" && section != "[proxy group]" {
			continue
		}
		_, value, ok := strings.Cut(line, "=")
		if !ok {
			return false
		}
		parts := strings.Split(value, ",")
		if section == "[proxy group]" {
			for _, part := range parts[1:] {
				key, _, _ := strings.Cut(strings.TrimSpace(part), "=")
				if strings.EqualFold(strings.TrimSpace(key), "policy-path") {
					return false
				}
			}
			continue
		}
		if len(parts) < 3 {
			return false
		}
		switch strings.ToLower(strings.TrimSpace(parts[0])) {
		case "ss", "vmess", "trojan", "hysteria2", "tuic", "snell":
		default:
			return false
		}
		host := strings.TrimSpace(parts[1])
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
		if _, err := netip.ParseAddr(host); err != nil {
			return false
		}
	}
	return true
}

// iniLines renders each line with fn, skipping the ones it cannot express.
func iniLines(lines []Line, fn func(Line) string) (string, []Named) {
	var b strings.Builder
	names := []Named{}
	for _, l := range lines {
		if s := fn(l); s != "" {
			b.WriteString(s + "\n")
			names = append(names, Named{Name: l.Name, Tags: l.Tags})
		}
	}
	return strings.TrimRight(b.String(), "\n"), names
}

func surgeLine(l Line) string {
	ib := l.Inbound
	// The name is data: a "%" in it (a remark variable such as
	// {{USED_PERCENT}}) must not be read as a verb.
	line := func(kind string) string { return fmt.Sprintf("%s = %s, %s, %d", iniName(l.Name), kind, l.Host, l.Port) }
	var parts []string
	switch ib.Protocol {
	case spec.Shadowsocks:
		if ss2022KeyLen(ib.Cipher) > 0 {
			return "" // Surge does not support SS2022 multi-user keys
		}
		parts = append(parts, "encrypt-method="+ib.Cipher, "password="+l.Password, "udp-relay=true")
		if st := ib.ShadowTLS; st != nil {
			host, _ := st.HandshakeHostPort()
			parts = append(parts, "shadow-tls-password="+spec.ShadowTLSUserKey(l.UUID), "shadow-tls-sni="+host, "shadow-tls-version=3")
		}
		return line("ss") + ", " + strings.Join(parts, ", ")
	case spec.VMess:
		parts = append(parts, "username="+l.UUID)
		if hasTLS(l) {
			parts = append(parts, "tls=true", "sni="+serverName(l))
		}
		if transportType(l) == "ws" {
			parts = append(parts, "ws=true", "ws-path="+ib.Transport.Path)
			if ib.Transport.Host != "" {
				parts = append(parts, "ws-headers=Host:"+ib.Transport.Host)
			}
		} else if transportType(l) != "tcp" {
			return ""
		}
		return line("vmess") + ", " + strings.Join(parts, ", ")
	case spec.Trojan:
		if transportType(l) != "tcp" && transportType(l) != "ws" {
			return ""
		}
		parts = append(parts, "password="+l.Password, "sni="+serverName(l))
		if transportType(l) == "ws" {
			parts = append(parts, "ws=true", "ws-path="+ib.Transport.Path)
		}
		return line("trojan") + ", " + strings.Join(parts, ", ")
	case spec.Hysteria2:
		parts = append(parts, "password="+l.Password, "sni="+serverName(l))
		if ib.DownMbps > 0 {
			parts = append(parts, fmt.Sprintf("download-bandwidth=%d", ib.DownMbps))
		}
		return line("hysteria2") + ", " + strings.Join(parts, ", ")
	case spec.TUIC:
		parts = append(parts, "uuid="+l.UUID, "password="+l.Password, "sni="+serverName(l), "alpn=h3", "version=5")
		return line("tuic") + ", " + strings.Join(parts, ", ")
	case spec.Snell:
		if ib.SnellMultiUser {
			return "" // needs the user key too; only sing-box's client has it
		}
		parts = append(parts, "psk="+ib.SnellPSK, fmt.Sprintf("version=%d", snellVersion(ib)))
		if ib.SnellObfs != "" && ib.SnellObfs != "off" {
			parts = append(parts, "obfs="+ib.SnellObfs)
			if ib.SnellObfsHost != "" {
				parts = append(parts, "obfs-host="+ib.SnellObfsHost)
			}
		}
		return line("snell") + ", " + strings.Join(parts, ", ")
	}
	return ""
}
