package spec

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Validate checks that an inbound is complete enough for some core to
// serve it: the shape every panel and the agent agree on, before any
// core-specific rendering. It says what is missing in operator terms so
// the panel can show it on the form and the agent in the doctor. Fields a
// core fills later (certificate paths for auto_cert) are not required.
func (i Inbound) Validate() error {
	if !ValidTag(i.Tag) {
		return fmt.Errorf("tag may only contain letters, digits, . _ : - (max 64)")
	}
	if !ValidListen(i.Listen) {
		return fmt.Errorf("listen must be an IP address")
	}
	if i.Port <= 0 || i.Port > 65535 {
		return fmt.Errorf("port must be 1-65535")
	}
	switch i.TransportType() {
	case "tcp", "ws", "grpc", "httpupgrade", "http", "xhttp":
	default:
		return fmt.Errorf("transport must be tcp, ws, grpc, httpupgrade, http or xhttp")
	}
	if i.Transport != nil && i.TransportType() != "tcp" && !transportProtocol(i.Protocol) {
		return fmt.Errorf("%s does not take a %s transport", i.Protocol, i.TransportType())
	}
	plain := []string{i.SnellObfsHost, i.Cipher, i.Flow, i.Obfs, i.Core}
	if i.Transport != nil {
		plain = append(plain, i.Transport.Host, i.Transport.Path, i.Transport.ServiceName, i.Transport.Mode)
	}
	if i.TLS != nil {
		plain = append(plain, i.TLS.ServerName)
		if i.TLS.Reality != nil {
			plain = append(plain, i.TLS.Reality.HandshakeServer)
		}
	}
	for _, v := range plain {
		if !Plain(v) {
			return fmt.Errorf("fields may not contain control characters")
		}
	}
	if err := i.validateTLS(); err != nil {
		return err
	}
	if i.AcceptProxyProtocol && i.Core != "" && i.Core != "xray" {
		return fmt.Errorf("accept_proxy_protocol is served by xray only")
	}
	if i.ShadowTLS != nil {
		if i.Protocol != Shadowsocks {
			return fmt.Errorf("shadow_tls wraps a shadowsocks inbound (got %s)", i.Protocol)
		}
		if i.Core != "" && i.Core != "singbox" {
			return fmt.Errorf("shadow_tls is served by sing-box; core %q cannot", i.Core)
		}
		host, port := i.ShadowTLS.HandshakeHostPort()
		if host == "" || strings.ContainsAny(host, " \t\"") {
			return fmt.Errorf("shadow_tls needs a handshake server, e.g. www.apple.com:443")
		}
		if port < 1 || port > 65535 {
			return fmt.Errorf("shadow_tls handshake port out of range")
		}
		if i.TLS != nil && i.TLS.Mode != TLSNone {
			return fmt.Errorf("shadow_tls provides the TLS itself; leave the inbound's own TLS off")
		}
	}
	switch i.Protocol {
	case VLESS, VMess, Trojan, HTTP, SOCKS:
	case Shadowsocks:
		if strings.TrimSpace(i.Cipher) == "" {
			return fmt.Errorf("shadowsocks needs a cipher")
		}
		if n := SS2022KeyLen(i.Cipher); n > 0 {
			raw, err := base64.StdEncoding.DecodeString(i.ServerKey)
			if err != nil || len(raw) != n {
				return fmt.Errorf("%s needs a %d-byte base64 server key", i.Cipher, n)
			}
		}
	case Hysteria2, TUIC, AnyTLS, Naive:
		if i.TLS == nil || i.TLS.Mode != TLSStandard {
			return fmt.Errorf("%s needs standard TLS (certificate)", i.Protocol)
		}
		if i.Protocol == Hysteria2 && i.Obfs != "" && i.Obfs != "salamander" {
			return fmt.Errorf("hysteria2 obfs must be empty or salamander")
		}
		if i.Protocol == Hysteria2 && i.Obfs == "salamander" && i.ObfsPassword == "" {
			return fmt.Errorf("hysteria2 salamander obfs needs a password")
		}
	case Mieru:
		switch strings.ToUpper(i.MieruTransport) {
		case "", "TCP", "UDP":
		case "BOTH":
			if i.Port+1 > 65535 {
				return fmt.Errorf("mieru BOTH needs port+1 to be valid")
			}
		default:
			return fmt.Errorf("mieru transport must be TCP, UDP or BOTH")
		}
		if i.MieruMTU != 0 && (i.MieruMTU < 1280 || i.MieruMTU > 1500) {
			return fmt.Errorf("mieru mtu must be 1280-1500")
		}
	case Snell:
		if strings.TrimSpace(i.SnellPSK) == "" {
			return fmt.Errorf("snell needs a psk")
		}
		if strings.ContainsAny(i.SnellPSK, "\r\n") {
			return fmt.Errorf("snell psk may not contain line breaks")
		}
		if i.SnellVersion != 0 && i.SnellVersion != 4 && i.SnellVersion != 5 {
			return fmt.Errorf("snell version must be 4 or 5")
		}
		if i.SnellMultiUser && i.SnellObfs == "tls" {
			return fmt.Errorf("multi-user snell (sing-box) supports obfs http only, not tls")
		}
		if i.SnellObfs != "" && i.SnellObfs != "http" && i.SnellObfs != "tls" {
			return fmt.Errorf("snell obfs must be off, http or tls")
		}
	case WireGuard:
		if raw, err := base64.StdEncoding.DecodeString(i.WGPrivateKey); err != nil || len(raw) != 32 {
			return fmt.Errorf("wireguard needs a 32-byte base64 private key")
		}
		if i.WGAddress != "" {
			if _, _, err := net.ParseCIDR(i.WGAddress); err != nil {
				return fmt.Errorf("wireguard address must be a CIDR like 10.66.0.1/16")
			}
		}
		if i.WGMTU != 0 && (i.WGMTU < 1280 || i.WGMTU > 1500) {
			return fmt.Errorf("wireguard mtu must be 1280-1500")
		}
	case "":
		return fmt.Errorf("protocol is required")
	default:
		return fmt.Errorf("unknown protocol %q", i.Protocol)
	}
	for _, f := range i.Fallbacks {
		if i.Protocol != VLESS && i.Protocol != Trojan {
			return fmt.Errorf("fallbacks need VLESS or Trojan")
		}
		if i.TransportType() != "tcp" || i.TLS == nil || i.TLS.Mode != TLSStandard {
			return fmt.Errorf("fallbacks need TCP with standard TLS")
		}
		if strings.TrimSpace(f.Dest) == "" {
			return fmt.Errorf("fallback dest is required")
		}
	}
	return nil
}

func (i Inbound) validateTLS() error {
	t := i.TLS
	if t == nil || t.Mode == TLSNone {
		return nil
	}
	switch t.Mode {
	case TLSStandard:
		if t.AutoCert && strings.TrimSpace(t.ServerName) == "" {
			return fmt.Errorf("auto_cert needs a server name")
		}
		if t.AutoCert && t.ACME != "" && t.ACME != "http" && t.ACME != "dns" {
			return fmt.Errorf("acme must be http or dns")
		}
	case TLSReality:
		if i.Protocol != VLESS && i.Protocol != Trojan {
			return fmt.Errorf("REALITY needs VLESS or Trojan")
		}
		r := t.Reality
		if r == nil {
			return fmt.Errorf("REALITY settings are missing")
		}
		if raw, err := base64.RawURLEncoding.DecodeString(r.PrivateKey); err != nil || len(raw) != 32 {
			return fmt.Errorf("REALITY needs a 32-byte base64url private key")
		}
		if strings.TrimSpace(r.HandshakeServer) == "" {
			return fmt.Errorf("REALITY needs a handshake server (dest)")
		}
		if r.HandshakePort < 0 || r.HandshakePort > 65535 {
			return fmt.Errorf("REALITY handshake port must be 0-65535")
		}
		if len(r.ShortIDs) == 0 {
			return fmt.Errorf("REALITY needs at least one short id")
		}
		for _, s := range r.ShortIDs {
			if len(s) > 16 || len(s)%2 != 0 {
				return fmt.Errorf("REALITY short id must be 2-16 hex characters")
			}
			if _, err := hex.DecodeString(s); err != nil {
				return fmt.Errorf("REALITY short id must be hex")
			}
		}
	default:
		return fmt.Errorf("unknown tls mode %d", t.Mode)
	}
	return nil
}

// transportProtocol reports whether the protocol carries a stream transport.
func transportProtocol(p Protocol) bool {
	switch p {
	case VLESS, VMess, Trojan:
		return true
	}
	return false
}

// SS2022KeyLen is the PSK length a Shadowsocks 2022 cipher needs; 0 for
// the classic AEAD ciphers, which take any password.
func SS2022KeyLen(cipher string) int {
	switch strings.ToLower(strings.TrimSpace(cipher)) {
	case "2022-blake3-aes-128-gcm":
		return 16
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return 32
	}
	return 0
}

// matchKeys are the prefixes a route or audit match may use.
var matchKeys = map[string]bool{
	"domain": true, "full": true, "keyword": true, "regexp": true,
	"ip": true, "ip_cidr": true, "port": true, "inbound": true,
	"protocol": true, "geosite": true, "geoip": true,
}

// sniffProtocols are the protocol names both cores understand.
var sniffProtocols = map[string]bool{
	"http": true, "tls": true, "quic": true, "dns": true, "bittorrent": true,
	"stun": true, "dtls": true, "ssh": true, "rdp": true,
}

var geoNameRe = regexp.MustCompile(`^[a-z0-9._-]+$`)

// ParsePortMatch reads one entry of a "port:" match: a single port, or a
// range written "a-b" or "a:b". Both ends are inclusive.
func ParsePortMatch(entry string) (from, to int, err error) {
	entry = strings.TrimSpace(entry)
	lo, hi, isRange := strings.Cut(entry, "-")
	if !isRange {
		lo, hi, isRange = strings.Cut(entry, ":")
	}
	parse := func(s string) (int, error) {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || n < 1 || n > 65535 {
			return 0, fmt.Errorf("port %q must be 1-65535", s)
		}
		return n, nil
	}
	if !isRange {
		n, err := parse(lo)
		return n, n, err
	}
	if from, err = parse(lo); err != nil {
		return 0, 0, err
	}
	if to, err = parse(hi); err != nil {
		return 0, 0, err
	}
	if to < from {
		return 0, 0, fmt.Errorf("port range %q is backwards", entry)
	}
	return from, to, nil
}

// ValidateMatch checks one route or audit match entry. A value that passes
// here renders into a configuration both cores accept; anything else is
// refused at the panel and dropped by the agent, because one bad entry
// otherwise takes every inbound on the node down.
func ValidateMatch(match string) error {
	match = strings.TrimSpace(match)
	if match == "" {
		return fmt.Errorf("empty match")
	}
	if strings.ContainsAny(match, "\r\n\"") {
		return fmt.Errorf("match %q contains a line break or quote", match)
	}
	key, val, ok := strings.Cut(match, ":")
	if !ok {
		key, val = "domain", match
	}
	// An IPv6 CIDR contains colons: "ip:" is the only key that may.
	if key == "ip" || key == "ip_cidr" {
		val = strings.TrimSpace(val)
	} else if strings.Contains(val, ":") && key != "port" && key != "regexp" {
		return fmt.Errorf("match %q: unexpected colon in the value", match)
	}
	if !matchKeys[key] {
		return fmt.Errorf("match %q: unknown kind %q", match, key)
	}
	val = strings.TrimSpace(val)
	if val == "" {
		return fmt.Errorf("match %q: empty value (an empty pattern matches everything)", match)
	}
	switch key {
	case "ip", "ip_cidr":
		if _, _, err := net.ParseCIDR(val); err != nil && net.ParseIP(val) == nil {
			return fmt.Errorf("match %q: not an IP or CIDR", match)
		}
	case "port":
		for _, part := range strings.Split(val, ",") {
			if _, _, err := ParsePortMatch(part); err != nil {
				return fmt.Errorf("match %q: %w", match, err)
			}
		}
	case "regexp":
		if _, err := regexp.Compile(val); err != nil {
			return fmt.Errorf("match %q: %w", match, err)
		}
	case "protocol":
		if !sniffProtocols[strings.ToLower(val)] {
			return fmt.Errorf("match %q: unknown protocol (try http, tls, quic, dns, bittorrent)", match)
		}
	case "geosite", "geoip":
		if !geoNameRe.MatchString(strings.ToLower(val)) {
			return fmt.Errorf("match %q: a geo name is lowercase letters, digits, dot, dash", match)
		}
	case "domain", "full", "keyword", "inbound":
		if strings.ContainsAny(val, " \t") {
			return fmt.Errorf("match %q: contains a space", match)
		}
	}
	return nil
}

// ValidateRouteRule checks a rule's matches and action.
func ValidateRouteRule(r RouteRule) error {
	switch r.Action {
	case "", "direct", "block", "outbound":
	default:
		return fmt.Errorf("route action %q must be direct, block or outbound", r.Action)
	}
	if r.Action == "outbound" && strings.TrimSpace(r.Value) == "" {
		return fmt.Errorf("route action outbound needs a tag")
	}
	if len(r.Match) == 0 {
		return fmt.Errorf("route rule without a match would apply to everything")
	}
	for _, m := range r.Match {
		if err := ValidateMatch(m); err != nil {
			return err
		}
	}
	return nil
}

// ValidateAuditRule checks one panel audit rule.
func ValidateAuditRule(r AuditRule) error {
	if r.Action != "block" && r.Action != "log" {
		return fmt.Errorf("audit rule %q: action must be block or log", r.Name)
	}
	if len(r.Match) == 0 {
		return fmt.Errorf("audit rule %q: needs at least one match", r.Name)
	}
	for _, m := range r.Match {
		if err := ValidateMatch(m); err != nil {
			return fmt.Errorf("audit rule %q: %w", r.Name, err)
		}
	}
	return nil
}

// ValidateTargets checks a forward's further hops and balance mode against
// its backend. The panel and the agent run the same check, so a rule the
// node would refuse never reaches it.
func (f Forward) ValidateTargets() error {
	switch f.Balance {
	case "", BalanceFailover, BalanceRoundRobin:
	default:
		return fmt.Errorf("balance must be failover or roundrobin")
	}
	if f.Weight < 0 || f.Weight > 100 {
		return fmt.Errorf("weight must be between 0 and 100")
	}
	if len(f.Targets) == 0 {
		return nil
	}
	switch {
	case f.Backend == "nft":
		return fmt.Errorf("several targets need the built-in relay or realm; nft forwards to one address")
	case f.Backend == "realm" && f.BalanceMode() == BalanceFailover:
		return fmt.Errorf("failover needs the built-in relay; realm spreads connections (roundrobin) but does not retry another target")
	case 1+len(f.Targets) > MaxForwardHops:
		return fmt.Errorf("at most %d targets per rule", MaxForwardHops)
	}
	seen := map[string]bool{f.Target: true}
	for i, t := range f.Targets {
		n := i + 2
		if !Plain(t.Target) || strings.ContainsAny(t.Target, "\"' ") {
			return fmt.Errorf("target %d contains invalid characters", n)
		}
		host, port, err := net.SplitHostPort(t.Target)
		if err != nil || host == "" {
			return fmt.Errorf("target %d must be host:port", n)
		}
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("target %d has a bad port", n)
		}
		if t.Weight < 0 || t.Weight > 100 {
			return fmt.Errorf("target %d: weight must be between 0 and 100", n)
		}
		if seen[t.Target] {
			return fmt.Errorf("target %s is listed twice", t.Target)
		}
		seen[t.Target] = true
	}
	return nil
}
