// Package spec defines the core-agnostic model that every proxy core renders
// from and every panel driver maps into. Nothing in here may reference a
// specific core's configuration format.
package spec

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Protocol is a proxy protocol an inbound speaks.
type Protocol string

const (
	VLESS       Protocol = "vless"
	VMess       Protocol = "vmess"
	Trojan      Protocol = "trojan"
	Shadowsocks Protocol = "shadowsocks"
	Hysteria2   Protocol = "hysteria2"
	TUIC        Protocol = "tuic"
	AnyTLS      Protocol = "anytls"
	Mieru       Protocol = "mieru"
	Snell       Protocol = "snell" // snell-server (one shared PSK) or sing-box multi-user (SnellMultiUser)
	SOCKS       Protocol = "socks"
	HTTP        Protocol = "http"
	Naive       Protocol = "naive"
	// WireGuard is a whole-device VPN inbound (xray): clients get derived
	// per-user keys, see pkg/wg. Plain UDP, no obfuscation.
	WireGuard Protocol = "wireguard"
)

// TLSMode selects how an inbound terminates TLS.
type TLSMode int

const (
	TLSNone     TLSMode = iota // plaintext
	TLSStandard                // certificate + key
	TLSReality                 // REALITY handshake, no certificate
)

// TLS describes TLS termination for an inbound.
type TLS struct {
	Mode       TLSMode  `json:"mode,omitempty"`
	ServerName string   `json:"server_name,omitempty"`
	CertPath   string   `json:"cert_path,omitempty"` // TLSStandard only; resolved by the agent from local cert config
	KeyPath    string   `json:"key_path,omitempty"`
	ALPN       []string `json:"alpn,omitempty"`
	Reality    *Reality `json:"reality,omitempty"` // TLSReality only
	// AutoCert asks the agent to obtain and renew a certificate for
	// ServerName with ACME instead of using local files. ACME picks the
	// challenge: "http" (port 80 on this machine) or "dns" (Cloudflare).
	AutoCert bool   `json:"auto_cert,omitempty"`
	ACME     string `json:"acme,omitempty"`
}

// Certificate is a PEM pair pushed by the panel (uploaded by the operator
// or delivered by a certificate manager's webhook). Domain may be a
// wildcard; it takes precedence over ACME for inbounds it covers.
type Certificate struct {
	Domain  string `json:"domain"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// ACME holds node-wide certificate automation settings.
type ACME struct {
	Email           string `json:"email,omitempty"`            // account contact
	CloudflareToken string `json:"cloudflare_token,omitempty"` // enables DNS-01
}

// Reality holds REALITY server parameters.
type Reality struct {
	PrivateKey      string   `json:"private_key,omitempty"`
	PublicKey       string   `json:"public_key,omitempty"` // clients need it; servers ignore it
	ShortIDs        []string `json:"short_ids,omitempty"`
	HandshakeServer string   `json:"handshake_server,omitempty"`
	HandshakePort   int      `json:"handshake_port,omitempty"`
	// FallbackLimit throttles connections that fail REALITY authentication
	// and are relayed to the handshake target (xray limitFallbackUpload /
	// limitFallbackDownload), so a node found by "preferred IP" scanners
	// is useless as a free relay. nil = on with defaults; Off disables.
	FallbackLimit *FallbackLimit `json:"fallback_limit,omitempty"`
}

// FallbackLimit is a token bucket applied to unauthenticated REALITY
// connections after AfterBytes have passed in that direction.
type FallbackLimit struct {
	Off              bool  `json:"off,omitempty"`
	AfterBytes       int64 `json:"after_bytes,omitempty"`
	BytesPerSec      int64 `json:"bytes_per_sec,omitempty"`
	BurstBytesPerSec int64 `json:"burst_bytes_per_sec,omitempty"`
}

// Fallback limit defaults: the first megabyte flows freely so the target's
// front page still loads for a probe, then 64 KiB/s.
const (
	DefaultFallbackAfterBytes  int64 = 1 << 20
	DefaultFallbackBytesPerSec int64 = 64 << 10
	DefaultFallbackBurst       int64 = 256 << 10
)

// EffectiveFallbackLimit returns the limit to render and whether it is on.
func (r *Reality) EffectiveFallbackLimit() (FallbackLimit, bool) {
	lim := FallbackLimit{AfterBytes: DefaultFallbackAfterBytes, BytesPerSec: DefaultFallbackBytesPerSec, BurstBytesPerSec: DefaultFallbackBurst}
	if r == nil {
		return lim, false
	}
	if r.FallbackLimit != nil {
		if r.FallbackLimit.Off {
			return lim, false
		}
		if r.FallbackLimit.AfterBytes > 0 {
			lim.AfterBytes = r.FallbackLimit.AfterBytes
		}
		if r.FallbackLimit.BytesPerSec > 0 {
			lim.BytesPerSec = r.FallbackLimit.BytesPerSec
		}
		if r.FallbackLimit.BurstBytesPerSec > 0 {
			lim.BurstBytesPerSec = r.FallbackLimit.BurstBytesPerSec
		}
	}
	if lim.BurstBytesPerSec < lim.BytesPerSec {
		lim.BurstBytesPerSec = lim.BytesPerSec
	}
	return lim, true
}

// Transport is the stream transport under VLESS/VMess/Trojan.
type Transport struct {
	Type        string `json:"type,omitempty"` // "tcp", "ws", "grpc", "httpupgrade", "http", "xhttp"
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	Mode        string `json:"mode,omitempty"` // xhttp: "auto", "packet-up", "stream-up", "stream-one"
}

// TransportType returns the transport name, "tcp" when unset.
func (i Inbound) TransportType() string {
	if i.Transport == nil || i.Transport.Type == "" {
		return "tcp"
	}
	return i.Transport.Type
}

// Multiplex enables sing-mux style multiplexing on TCP-based protocols.
type Multiplex struct {
	Enabled bool    `json:"enabled,omitempty"`
	Padding bool    `json:"padding,omitempty"`
	Brutal  *Brutal `json:"brutal,omitempty"`
}

// Brutal is TCP Brutal congestion control settings.
type Brutal struct {
	UpMbps   int `json:"up_mbps,omitempty"`
	DownMbps int `json:"down_mbps,omitempty"`
}

// Inbound is one listener. A node may run many, possibly on different cores.
type Inbound struct {
	Tag      string   `json:"tag,omitempty"`
	Protocol Protocol `json:"protocol,omitempty"`
	Listen   string   `json:"listen,omitempty"` // "" means dual-stack any
	Port     int      `json:"port"`
	Core     string   `json:"core,omitempty"` // preferred core name; "" lets the registry choose

	TLS       *TLS       `json:"tls,omitempty"`
	Transport *Transport `json:"transport,omitempty"`
	Multiplex *Multiplex `json:"multiplex,omitempty"`

	// Protocol-specific fields. Unused ones stay zero.
	Flow              string   `json:"flow,omitempty"`               // vless
	Cipher            string   `json:"cipher,omitempty"`             // shadowsocks
	ServerKey         string   `json:"server_key,omitempty"`         // shadowsocks 2022 server PSK (base64)
	Obfs              string   `json:"obfs,omitempty"`               // hysteria2 obfs type ("salamander") or ""
	ObfsPassword      string   `json:"obfs_password,omitempty"`      // hysteria2
	UpMbps            int      `json:"up_mbps,omitempty"`            // hysteria2
	DownMbps          int      `json:"down_mbps,omitempty"`          // hysteria2
	CongestionControl string   `json:"congestion_control,omitempty"` // tuic
	PaddingScheme     []string `json:"padding_scheme,omitempty"`     // anytls
	MieruTransport    string   `json:"mieru_transport,omitempty"`    // mieru: "TCP", "UDP" or "BOTH" (TCP at Port, UDP at Port+1)
	TrafficPattern    string   `json:"traffic_pattern,omitempty"`    // mieru
	MieruMTU          int      `json:"mieru_mtu,omitempty"`          // mieru: server mtu and client link mtu; 0 = mita default
	MieruMultiplexing string   `json:"mieru_multiplexing,omitempty"` // mieru client: MULTIPLEXING_OFF|LOW|MIDDLE|HIGH ("" = client default)
	MieruHandshake    string   `json:"mieru_handshake,omitempty"`    // mieru client: HANDSHAKE_NO_WAIT|HANDSHAKE_STANDARD ("" = client default)
	// WireGuard: the server key pair, the tunnel network's server address
	// (default 10.66.0.1/16) and MTU. Peers are the users, keys derived.
	WGPrivateKey  string `json:"wg_private_key,omitempty"`
	WGPublicKey   string `json:"wg_public_key,omitempty"`
	WGAddress     string `json:"wg_address,omitempty"`
	WGMTU         int    `json:"wg_mtu,omitempty"`
	SnellPSK      string `json:"snell_psk,omitempty"`       // snell: shared pre-shared key
	SnellVersion  int    `json:"snell_version,omitempty"`   // snell: 4 or 5 (0 = 5)
	SnellObfs     string `json:"snell_obfs,omitempty"`      // snell: "", "http" or "tls"
	SnellObfsHost string `json:"snell_obfs_host,omitempty"` // snell: obfs host header
	// SnellMultiUser serves the inbound from sing-box's multi-user snell
	// server: SnellPSK stays the server key, and each user connects with
	// their own key (User.Password), so traffic is accounted per user.
	// Needs sing-box; obfs "tls" is not available there.
	SnellMultiUser bool `json:"snell_multi_user,omitempty"`

	// Users restricts who may use this inbound. When ScopedUsers is false the
	// node-level user list applies; when true only Users are provisioned,
	// even if that is nobody.
	ScopedUsers bool   `json:"scoped_users,omitempty"`
	Users       []User `json:"users,omitempty"`
	// NoSniff turns off destination sniffing on this inbound (on by
	// default: it lets domain rules see the real host behind an IP).
	NoSniff bool `json:"no_sniff,omitempty"`
	// AcceptProxyProtocol makes the listener expect a PROXY protocol
	// header on every connection (xray only): for inbounds reached only
	// through relays that send one, so device counting sees the client's
	// address. Direct clients cannot connect to such an inbound.
	AcceptProxyProtocol bool `json:"accept_proxy_protocol,omitempty"`
	// Fallbacks hand connections that are not this protocol (or match a
	// path / SNI / ALPN) to another local service, e.g. a real website on
	// port 80 so the inbound looks like one. VLESS/Trojan over TCP+TLS on
	// xray only.
	Fallbacks []Fallback `json:"fallbacks,omitempty"`
}

// Fallback is one xray fallback rule; empty matchers catch everything.
type Fallback struct {
	Name string `json:"name,omitempty"` // SNI
	ALPN string `json:"alpn,omitempty"`
	Path string `json:"path,omitempty"`
	Dest string `json:"dest"` // "80", "127.0.0.1:8080" or "/run/site.sock"
	Xver int    `json:"xver,omitempty"`
}

// EffectiveUsers returns the users to provision on this inbound given the
// node-level list.
func (i Inbound) EffectiveUsers(nodeUsers []User) []User {
	if i.ScopedUsers {
		return i.Users
	}
	return nodeUsers
}

// User is a subscriber allowed on every inbound of the node.
type User struct {
	ID             int64  `json:"id,omitempty"`
	Name           string `json:"name,omitempty"` // stable identity used for stats; panels usually use the UUID
	UUID           string `json:"uuid,omitempty"`
	Password       string `json:"password,omitempty"`
	SpeedLimitMbps int    `json:"speed_limit_mbps,omitempty"` // 0 = unlimited
	DeviceLimit    int    `json:"device_limit,omitempty"`     // 0 = unlimited
	// QuotaBytes and QuotaDays describe the user's traffic allowance as a
	// rolling window, for cores that enforce quotas themselves (mita). The
	// panel still does its own accounting; this is a second lock that holds
	// when the panel is unreachable. 0 = not enforced by the core.
	QuotaBytes int64 `json:"quota_bytes,omitempty"`
	QuotaDays  int   `json:"quota_days,omitempty"`
}

// deniedOverrideKeys are top-level config keys a per-core override may not
// touch: they would let a panel operator point the core at arbitrary
// files, replace the inbounds bosun manages or disable the stats it bills from.
var deniedOverrideKeys = map[string][]string{
	"xray":     {"log", "api", "stats", "inbounds", "metrics"},
	"singbox":  {"log", "experimental", "inbounds"},
	"hysteria": {"listen", "auth", "trafficStats", "tls", "acme"},
	"mita":     {"users", "portBindings"},
}

// CheckOverride validates a raw config override for the core: a JSON
// object with none of the denied keys. Empty is fine.
func CheckOverride(core string, patch json.RawMessage) error {
	if len(strings.TrimSpace(string(patch))) == 0 {
		return nil
	}
	var over map[string]any
	if err := json.Unmarshal(patch, &over); err != nil {
		return fmt.Errorf("config override is not a JSON object: %w", err)
	}
	for _, k := range deniedOverrideKeys[core] {
		if _, has := over[k]; has {
			return fmt.Errorf("%s override may not set %q", core, k)
		}
	}
	return nil
}

var tagRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// ValidTag reports whether an inbound/forward/outbound tag is safe to use
// as a file name, an nft comment and a core config key: letters, digits,
// dot, underscore, colon and dash, at most 64 characters.
func ValidTag(tag string) bool { return tagRE.MatchString(tag) }

// ValidListen reports whether a bind address is empty or a literal IP.
func ValidListen(listen string) bool { return listen == "" || net.ParseIP(listen) != nil }

// Plain reports whether s carries no control characters (safe to embed in
// generated INI/TOML/nft text).
func Plain(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// EffectiveSpeedLimit is the user's own limit, else the node default.
func (n *Node) EffectiveSpeedLimit(u User) int {
	if u.SpeedLimitMbps > 0 {
		return u.SpeedLimitMbps
	}
	if n != nil {
		return n.UserSpeedLimitMbps
	}
	return 0
}

// SpeedMark is the firewall mark stamped on a limited user's outbound
// sockets; SpeedClass the tc class minor id (16-bit) the shaper uses.
func SpeedMark(userID int64) int64  { return 0x10000 + userID }
func SpeedClass(userID int64) int64 { return userID%0xfffe + 1 }

// SpeedTag names the per-user marking outbound.
func SpeedTag(userID int64) string { return "limit-" + strconv.FormatInt(userID, 10) }

// Outbound is an extra egress the panel defines (e.g. relay to a landing node).
type Outbound struct {
	Tag      string         `json:"tag,omitempty"`
	Protocol string         `json:"protocol,omitempty"`
	Settings map[string]any `json:"settings,omitempty"`
	ProxyTag string         `json:"proxy_tag,omitempty"` // chain: dial through this outbound
	// Remote is the core-agnostic form: bosun renders it in each core's
	// dialect. When set, Protocol/Settings are ignored.
	Remote *Remote `json:"remote,omitempty"`
	// WARP is a Cloudflare WARP (WireGuard) exit; see WARP.
	WARP *WARP `json:"warp,omitempty"`
	// Balancer groups other outbounds: traffic routed to this tag takes
	// the member with the best probe (sing-box urltest, xray leastPing).
	Balancer *Balancer `json:"balancer,omitempty"`
}

// Balancer is a group of outbound tags picked by URL test.
type Balancer struct {
	Members  []string `json:"members"`
	Strategy string   `json:"strategy,omitempty"` // "urltest" (default) or "random"
}

// WARP configures a WireGuard tunnel to Cloudflare WARP as an outbound.
// FromNode uses the account registered on the node itself (the panel never
// sees the private key); otherwise the credentials are given here.
type WARP struct {
	FromNode      bool     `json:"from_node,omitempty"`
	PrivateKey    string   `json:"private_key,omitempty"`
	PeerPublicKey string   `json:"peer_public_key,omitempty"`
	Endpoint      string   `json:"endpoint,omitempty"`  // host:port, default engage.cloudflareclient.com:2408
	Addresses     []string `json:"addresses,omitempty"` // interface addresses with prefix
	Reserved      []int    `json:"reserved,omitempty"`  // 3 bytes from the client id
	License       string   `json:"license,omitempty"`   // WARP+ (informational)
}

// WARPAccount is a registered WARP identity kept on the node.
type WARPAccount struct {
	ID            string    `json:"id"`
	Token         string    `json:"token,omitempty"` // API token, never leaves the node
	License       string    `json:"license,omitempty"`
	PrivateKey    string    `json:"private_key,omitempty"` // never leaves the node
	PeerPublicKey string    `json:"peer_public_key"`
	Endpoint      string    `json:"endpoint"`
	Addresses     []string  `json:"addresses"`
	Reserved      []int     `json:"reserved,omitempty"`
	RegisteredAt  time.Time `json:"registered_at"`
}

// Remote is a proxy server to dial out through (a "landing" node), in the
// same vocabulary as Inbound so a share link maps onto it directly.
type Remote struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	UUID        string `json:"uuid,omitempty"`        // vless/vmess/tuic
	Password    string `json:"password,omitempty"`    // trojan/ss/hysteria2/tuic/anytls/socks/http
	Username    string `json:"username,omitempty"`    // socks/http
	Insecure    bool   `json:"insecure,omitempty"`    // skip certificate verification
	Fingerprint string `json:"fingerprint,omitempty"` // uTLS fingerprint, default "chrome" when TLS is on
	// Settings carries Protocol, TLS (ServerName, Mode, Reality.PublicKey +
	// ShortIDs), Transport, Multiplex, Flow, Cipher, Obfs..., i.e. the
	// client-relevant subset of an Inbound.
	Settings Inbound `json:"settings"`
}

// RouteRule directs matched traffic to an action.
type RouteRule struct {
	Match  []string `json:"match,omitempty"`  // e.g. "domain:example.com", "ip:1.1.1.1/32", "protocol:bittorrent"
	Action string   `json:"action,omitempty"` // "direct", "block", "outbound"
	Value  string   `json:"value,omitempty"`  // outbound tag when Action == "outbound"
}

// Forward is one relay rule: accept on Listen:Port and forward the raw
// stream or datagrams to Target. A chain (entry -> relay -> exit) is just
// one Forward per hop, each pointing at the next; the panel orchestrates.
type Forward struct {
	Tag      string `json:"tag,omitempty"`
	Listen   string `json:"listen,omitempty"` // "" = all interfaces
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"` // "tcp", "udp" or "both"
	Target   string `json:"target,omitempty"`   // host:port of the next hop
	// Backend is "" for bosun's userspace relay, "nft" for kernel DNAT or
	// "realm" for a zhboner/realm process bosun installs and runs; it is
	// through nftables (IPv4 targets, needs the nft binary).
	Backend string `json:"backend,omitempty"`
	// PreserveSource skips masquerading on the nft backend so the target
	// sees the client's address; the target must route replies back here.
	PreserveSource bool `json:"preserve_source,omitempty"`
	// ProxyProtocol prefixes every relayed TCP connection with a PROXY
	// protocol v2 header (built-in relay and realm) so the target inbound,
	// which must have AcceptProxyProtocol, sees the client's address for
	// online-device counting. Not for the nft backend (kernel DNAT keeps
	// the source anyway when PreserveSource is on).
	ProxyProtocol bool `json:"proxy_protocol,omitempty"`
}

// Node is the complete desired state for this server.
type Node struct {
	ID        string      `json:"id,omitempty"`
	Inbounds  []Inbound   `json:"inbounds,omitempty"`
	Outbounds []Outbound  `json:"outbounds,omitempty"`
	Routes    []RouteRule `json:"routes,omitempty"`
	Forwards  []Forward   `json:"forwards,omitempty"`
	ACME      *ACME       `json:"acme,omitempty"`
	// Certificates are operator-supplied PEM pairs; see Certificate.
	Certificates []Certificate `json:"certificates,omitempty"`
	// DefaultOutbound is the tag traffic takes when no route rule matches
	// ("" = direct): the whole node exits through a landing server.
	DefaultOutbound string `json:"default_outbound,omitempty"`
	// UserSpeedLimitMbps caps every user without a limit of their own
	// (0 = none). Enforced by the node's shaper for xray/sing-box traffic.
	UserSpeedLimitMbps int `json:"user_speed_limit_mbps,omitempty"`
	// DNS lists resolvers the cores use for outbound names ("1.1.1.1",
	// "tls://1.1.1.1", "https://dns.google/dns-query"); empty = system.
	DNS []string `json:"dns,omitempty"`
	// Overrides are JSON objects deep-merged into each core's rendered
	// config, keyed by core name ("xray", "singbox", "hysteria", "mita"):
	// an escape hatch for options the panel does not model.
	Overrides map[string]json.RawMessage `json:"overrides,omitempty"`
	// Decoy is a real HTTPS site the node serves for itself on loopback so
	// REALITY inbounds can "steal" their own domain instead of a third
	// party's (nothing is relayed off-box when the fallback fires).
	Decoy *Decoy `json:"decoy,omitempty"`
}

// Decoy configures the self-hosted site: bosun listens on 127.0.0.1:Port
// with an automatic certificate for Domain, serving its built-in page or
// reverse-proxying Upstream. REALITY inbounds point at 127.0.0.1:Port with
// Domain as the SNI.
type Decoy struct {
	Domain   string `json:"domain"`
	Port     int    `json:"port,omitempty"`     // default 4443
	Upstream string `json:"upstream,omitempty"` // e.g. http://127.0.0.1:8080
	ACME     string `json:"acme,omitempty"`     // "http" or "dns"
	// AllowPrivate lets Upstream point at loopback/private/link-local
	// addresses (the panel itself, docker services); off by default so a
	// panel operator cannot expose local services through the decoy.
	AllowPrivate bool `json:"allow_private,omitempty"`
	// Insecure skips TLS verification toward an https Upstream.
	Insecure bool `json:"insecure,omitempty"`
}

// DefaultDecoyPort is the loopback port the decoy site listens on.
const DefaultDecoyPort = 4443

// EffectivePort returns Port or the default.
func (d *Decoy) EffectivePort() int {
	if d == nil || d.Port <= 0 {
		return DefaultDecoyPort
	}
	return d.Port
}

// Traffic is a byte counter pair.
type Traffic struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// UserTraffic is traffic attributed to one user since the last report.
type UserTraffic struct {
	UserID int64 `json:"user_id,omitempty"`
	Up     int64 `json:"up"`
	Down   int64 `json:"down"`
	// Inbound is the tag the bytes went through when the core can tell
	// (xray, sing-box, hysteria, mita); "" when it cannot. A panel that
	// charges per inbound group needs it; older panels add the entries up.
	Inbound string `json:"inbound,omitempty"`
}

// InboundUser is the per-inbound identity a core gets for a user (xray's
// email, sing-box's user name): the stats counters and connection logs
// then say which inbound the bytes went through. Tags never contain "|".
func InboundUser(name, tag string) string {
	if tag == "" {
		return name
	}
	return name + "|" + tag
}

// SplitInboundUser undoes InboundUser; a plain name comes back with "".
func SplitInboundUser(s string) (name, tag string) {
	if i := strings.LastIndexByte(s, '|'); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// SystemStatus is a host resource snapshot.
type SystemStatus struct {
	CPUPercent float64 `json:"cpu_percent,omitempty"`
	MemTotal   uint64  `json:"mem_total,omitempty"`
	MemUsed    uint64  `json:"mem_used,omitempty"`
	SwapTotal  uint64  `json:"swap_total,omitempty"`
	SwapUsed   uint64  `json:"swap_used,omitempty"`
	DiskTotal  uint64  `json:"disk_total,omitempty"`
	DiskUsed   uint64  `json:"disk_used,omitempty"`

	// Probe fields (bosun >= 0.11); zero when the agent is older.
	Load1        float64      `json:"load1,omitempty"`
	Load5        float64      `json:"load5,omitempty"`
	Load15       float64      `json:"load15,omitempty"`
	NetUp        uint64       `json:"net_up,omitempty"`         // bytes/s averaged since the previous sample
	NetDown      uint64       `json:"net_down,omitempty"`       //
	NetTotalUp   uint64       `json:"net_total_up,omitempty"`   // interface counters since boot (all non-loopback)
	NetTotalDown uint64       `json:"net_total_down,omitempty"` //
	TCP          int          `json:"tcp,omitempty"`
	UDP          int          `json:"udp,omitempty"`
	Processes    int          `json:"processes,omitempty"`
	Uptime       uint64       `json:"uptime,omitempty"` // seconds
	IPv4         bool         `json:"ipv4,omitempty"`
	IPv6         bool         `json:"ipv6,omitempty"`
	Info         *HostInfo    `json:"info,omitempty"`  // static facts, sent with every beat (cheap)
	Pings        []PingResult `json:"pings,omitempty"` // carrier probes and panel-defined tasks
}

// HostInfo is what does not change between reboots.
type HostInfo struct {
	CPUModel string `json:"cpu_model,omitempty"`
	CPUCores int    `json:"cpu_cores,omitempty"`
	OS       string `json:"os,omitempty"` // "Ubuntu 24.04"
	Kernel   string `json:"kernel,omitempty"`
	Arch     string `json:"arch,omitempty"`
	Virt     string `json:"virt,omitempty"` // kvm, lxc, docker, ...
	BootTime uint64 `json:"boot_time,omitempty"`
}

// PingResult is the latest measurement of one probe target.
type PingResult struct {
	TaskID    int64   `json:"task_id"`        // 0 = built-in carrier probe
	Name      string  `json:"name"`           // "CT", "CU", "CM" or the task name
	LatencyMs float64 `json:"latency_ms"`     // -1 = lost
	Loss      float64 `json:"loss,omitempty"` // percent over the recent window (carrier probes)
	Mbps      float64 `json:"mbps,omitempty"` // download tasks: measured throughput
	At        int64   `json:"at,omitempty"`   // unix seconds of the sample
}

// Probe is the panel's monitoring configuration for a node.
type Probe struct {
	Enabled     bool       `json:"enabled"`
	BeatSeconds int        `json:"beat_seconds,omitempty"` // default 10
	CarrierPing bool       `json:"carrier_ping,omitempty"` // TCP-connect latency to the carrier probe points
	Carriers    []Carrier  `json:"carriers,omitempty"`     // empty = DefaultCarriers
	Tasks       []PingTask `json:"tasks,omitempty"`
}

// Komari makes the node report to a Komari monitoring server as a v2
// agent: it registers itself once through the auto-discovery key, then
// sends host metrics every few seconds and answers ping tasks.
type Komari struct {
	Enabled  bool   `json:"enabled"`
	Server   string `json:"server"`             // https://komari.example.com
	Key      string `json:"key,omitempty"`      // auto-discovery key (registration only)
	Name     string `json:"name,omitempty"`     // client name; "" = hostname
	Interval int    `json:"interval,omitempty"` // report seconds, default 3
}

// Carrier is one always-on TCP-connect latency target, named after the
// network it represents (CT/CU/CM by default).
type Carrier struct {
	Name string `json:"name" yaml:"name"`
	Addr string `json:"addr" yaml:"addr"` // host:port
}

// DefaultCarriers are the three Chinese carriers' probe points used by
// ServerStatus-style monitors; a refused connection still yields an RTT.
func DefaultCarriers() []Carrier {
	return []Carrier{{"CT", "ct.tz.cloudcpp.com:80"}, {"CU", "cu.tz.cloudcpp.com:80"}, {"CM", "cm.tz.cloudcpp.com:80"}}
}

// PingTask is a panel-defined latency check the node runs.
type PingTask struct {
	ID              int64  `json:"id" yaml:"id"`
	Name            string `json:"name" yaml:"name"`
	Type            string `json:"type" yaml:"type"`     // icmp | tcp | http | download
	Target          string `json:"target" yaml:"target"` // host, host:port or URL (download: a large file URL)
	IntervalSeconds int    `json:"interval_seconds,omitempty" yaml:"interval_seconds"`
	// SourceIP binds the probe to a local address (tcp, icmp): measure a
	// dedicated line from its own NIC instead of the default route.
	SourceIP string `json:"source_ip,omitempty" yaml:"source_ip"`
}

// Intervals are the panel-requested polling cadences.
type Intervals struct {
	Pull time.Duration `json:"pull,omitempty"`
	Push time.Duration `json:"push,omitempty"`
}
