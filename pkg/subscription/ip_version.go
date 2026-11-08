package subscription

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode"

	"github.com/zeptop-dev/bosun/pkg/spec"
	"gopkg.in/yaml.v3"
)

// ErrIPVersionTemplateConflict means an explicit node policy needs IPv6 but
// the administrator's profile explicitly disables it. Never rewrite that choice.
var ErrIPVersionTemplateConflict = errors.New("node IP policy conflicts with template IPv6 setting")

// ValidateIPVersion checks a client connection policy without resolving its
// hostname or modifying the listener, TLS name, DNS records or server egress.
// Empty is deliberately the legacy behavior, including legacy Extra fields.
func ValidateIPVersion(host, mode string, extra map[string]any) error {
	if mode == "" {
		return nil
	}
	if mode != "ipv4" && mode != "ipv6" && mode != "dual" {
		return errors.New("invalid connection IP version")
	}
	if strings.IndexFunc(host, unicode.IsControl) >= 0 {
		return errors.New("connection host contains a control character")
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return errors.New("connection IP version requires a host")
	}
	if ip, err := netip.ParseAddr(ipVersionLiteralHost(host)); err == nil {
		if ip.Zone() != "" {
			return errors.New("connection IP version does not support scoped addresses")
		}
		ip = ip.Unmap()
		if mode == "dual" {
			return errors.New("dual stack requires a hostname")
		}
		if (mode == "ipv4") != ip.Is4() {
			return errors.New("connection IP version does not match address")
		}
	} else if strings.ContainsAny(host, ":/[] \t\r\n") {
		return errors.New("connection IP version requires a hostname or IP address")
	}
	// Extra is intentionally client-specific. Once a typed policy is selected,
	// reject fields that could redirect the endpoint, replace its resolver or
	// perform remote resolution through a different proxy.
	reserved := map[string]bool{}
	for _, key := range []string{"ip-version", "ip_version", "domain_strategy", "domain_resolver", "inet4_bind_address", "inet6_bind_address", "dialer-proxy", "detour", "underlying-proxy", "server", "server_port", "port", "peers", "type", "plugin", "plugin-opts", "transport", "realm", "name", "tag"} {
		reserved[strings.ReplaceAll(key, "_", "-")] = true
	}
	for key := range extra {
		canonical := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "_", "-"))
		if reserved[canonical] {
			return fmt.Errorf("connection IP version conflicts with client field %s", key)
		}
	}

	return nil
}

// Native selectors follow Mihomo common fields, Surge common policy parameters,
// and sing-box shared dial domain_resolver (1.12+). Other formats keep dual
// client-native and only accept forced families on literal endpoints.
//
// IPVersionSupport returns a stable omission reason, or "" when the IP policy
// can be rendered. This does not replace a format's protocol support checks.
func IPVersionSupport(format string, l Line) string {
	if l.IPVersion == "" {
		return ""
	}
	if ValidateIPVersion(l.Host, l.IPVersion, l.Extra) != nil {
		return "invalid_policy"
	}
	format = Pick(format, "").Name()
	if l.IPVersion == "dual" {
		return ""
	}
	if _, err := netip.ParseAddr(normalizeIPVersionHost(l.Host)); err == nil {
		return ""
	}
	// WG endpoint and tunneled target DNS do not have independent verified
	// selectors in these clients; a literal endpoint is safe without a field.
	if l.Inbound.Protocol == spec.WireGuard {
		return "unsupported_family_policy"
	}
	switch format {
	case "clash", "surge":
		return ""
	case "singbox":
		return ""
	}
	return "unsupported_family_policy"
}

// IPVersionUsesClientDefault identifies dual-stack formats without a verified
// per-node selector. They preserve the domain and rely on the client's network
// settings; dual never promises parallel racing.
func IPVersionUsesClientDefault(format string, l Line) bool {
	if l.IPVersion != "dual" {
		return false
	}
	if l.Inbound.Protocol == spec.WireGuard {
		return true
	}
	switch Pick(format, "").Name() {
	case "clash", "surge":
		return false
	case "singbox":
		return false
	default:
		return true
	}
}

func filterIPVersions(format string, lines []Line) []Line {
	out := make([]Line, 0, len(lines))
	for _, l := range lines {
		if IPVersionSupport(format, l) == "" {
			if l.IPVersion != "" {
				l.Host = normalizeIPVersionHost(l.Host)
			}
			out = append(out, l)
		}
	}
	return out
}

func singboxIPVersion(o m, l Line) {
	if l.IPVersion == "" || l.Inbound.Protocol == spec.WireGuard {
		return
	}
	resolver := m{"server": "local"}
	switch l.IPVersion {
	case "ipv4":
		resolver["strategy"] = "ipv4_only"
	case "ipv6":
		resolver["strategy"] = "ipv6_only"
	}
	o["domain_resolver"] = resolver
}

func ipVersionNeedsIPv6(lines []Line) bool {
	for _, l := range lines {
		if l.IPVersion == "ipv6" || l.IPVersion == "dual" {
			return true
		}
	}
	return false
}

func yamlIPVersionTemplate(tpl, format string, lines []Line) (string, error) {
	if !ipVersionNeedsIPv6(lines) {
		return tpl, nil
	}
	if tpl == "" {
		tpl = DefaultTemplate(format)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(tpl), &doc); err != nil {
		return "", err
	}
	if value, exists := doc["ipv6"]; exists {
		if enabled, ok := value.(bool); !ok || !enabled {
			return "", ErrIPVersionTemplateConflict
		}
		return tpl, nil
	}
	// Prepending keeps designer attribution markers and literal template text.
	return "ipv6: true\n" + tpl, nil
}

func surgeIPVersionTemplate(tpl string, lines []Line) (string, error) {
	if !ipVersionNeedsIPv6(lines) {
		return tpl, nil
	}
	if tpl == "" {
		tpl = DefaultTemplate("surge")
	}
	rows := strings.Split(tpl, "\n")
	general, generalIndex, found := false, -1, false
	for i, row := range rows {
		s := strings.TrimSpace(row)
		if strings.HasPrefix(s, "[") {
			general = strings.EqualFold(s, "[General]")
			if general {
				generalIndex = i
			}
			continue
		}
		if !general || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") || strings.HasPrefix(s, "//") {
			continue
		}
		key, value, ok := strings.Cut(s, "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "ipv6") {
			found = true
			if !strings.EqualFold(strings.TrimSpace(value), "true") {
				return "", ErrIPVersionTemplateConflict
			}
		}
	}
	if found {
		return tpl, nil
	}
	if generalIndex < 0 {
		return "[General]\nipv6 = true\n" + tpl, nil
	}
	rows[generalIndex] += "\nipv6 = true"
	return strings.Join(rows, "\n"), nil
}

// Only nodes actually emitted by this protocol renderer affect its global flags.
func emittedIPVersionLines(lines []Line, names []Named) []Line {
	present := map[string]bool{}
	for _, n := range names {
		present[n.Name] = true
	}
	var out []Line
	for _, l := range lines {
		if present[l.Name] {
			out = append(out, l)
		}
	}
	return out
}

func ipVersionLiteralHost(host string) string {
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host[1 : len(host)-1]
	}
	return host
}

func normalizeIPVersionHost(host string) string {
	host = ipVersionLiteralHost(strings.TrimSpace(host))
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String()
	}
	return host
}
