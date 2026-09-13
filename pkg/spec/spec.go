// Package spec defines the core-agnostic model that every proxy core renders
// from and every panel driver maps into. Nothing in here may reference a
// specific core's configuration format.
package spec

import "time"

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
	SOCKS       Protocol = "socks"
	HTTP        Protocol = "http"
	Naive       Protocol = "naive"
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
	MieruTransport    string   `json:"mieru_transport,omitempty"`    // mieru: "TCP" or "UDP"
	TrafficPattern    string   `json:"traffic_pattern,omitempty"`    // mieru

	// Users restricts who may use this inbound. When ScopedUsers is false the
	// node-level user list applies; when true only Users are provisioned,
	// even if that is nobody.
	ScopedUsers bool   `json:"scoped_users,omitempty"`
	Users       []User `json:"users,omitempty"`
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
}

// Outbound is an extra egress the panel defines (e.g. relay to a landing node).
type Outbound struct {
	Tag      string         `json:"tag,omitempty"`
	Protocol string         `json:"protocol,omitempty"`
	Settings map[string]any `json:"settings,omitempty"`
	ProxyTag string         `json:"proxy_tag,omitempty"` // chain: dial through this outbound
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
}

// Node is the complete desired state for this server.
type Node struct {
	ID        string      `json:"id,omitempty"`
	Inbounds  []Inbound   `json:"inbounds,omitempty"`
	Outbounds []Outbound  `json:"outbounds,omitempty"`
	Routes    []RouteRule `json:"routes,omitempty"`
	Forwards  []Forward   `json:"forwards,omitempty"`
	ACME      *ACME       `json:"acme,omitempty"`
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
	Load1, Load5, Load15 float64      `json:"load1,omitempty"`
	NetUp                uint64       `json:"net_up,omitempty"`         // bytes/s averaged since the previous sample
	NetDown              uint64       `json:"net_down,omitempty"`       //
	NetTotalUp           uint64       `json:"net_total_up,omitempty"`   // interface counters since boot (all non-loopback)
	NetTotalDown         uint64       `json:"net_total_down,omitempty"` //
	TCP                  int          `json:"tcp,omitempty"`
	UDP                  int          `json:"udp,omitempty"`
	Processes            int          `json:"processes,omitempty"`
	Uptime               uint64       `json:"uptime,omitempty"` // seconds
	IPv4                 bool         `json:"ipv4,omitempty"`
	IPv6                 bool         `json:"ipv6,omitempty"`
	Info                 *HostInfo    `json:"info,omitempty"`  // static facts, sent with every beat (cheap)
	Pings                []PingResult `json:"pings,omitempty"` // carrier probes and panel-defined tasks
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
	At        int64   `json:"at,omitempty"`   // unix seconds of the sample
}

// Probe is the panel's monitoring configuration for a node.
type Probe struct {
	Enabled     bool       `json:"enabled"`
	BeatSeconds int        `json:"beat_seconds,omitempty"` // default 10
	CarrierPing bool       `json:"carrier_ping,omitempty"` // TCP-connect latency to CT/CU/CM probe points
	Tasks       []PingTask `json:"tasks,omitempty"`
}

// PingTask is a panel-defined latency check the node runs.
type PingTask struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	Type            string `json:"type"`   // icmp | tcp | http
	Target          string `json:"target"` // host, host:port or URL
	IntervalSeconds int    `json:"interval_seconds,omitempty"`
}

// Intervals are the panel-requested polling cadences.
type Intervals struct {
	Pull time.Duration `json:"pull,omitempty"`
	Push time.Duration `json:"push,omitempty"`
}
