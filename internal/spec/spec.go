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
	Mode       TLSMode
	ServerName string
	CertPath   string // TLSStandard only; resolved by the agent from local cert config
	KeyPath    string
	ALPN       []string
	Reality    *Reality // TLSReality only
}

// Reality holds REALITY server parameters.
type Reality struct {
	PrivateKey      string
	ShortIDs        []string
	HandshakeServer string
	HandshakePort   int
}

// Transport is the stream transport under VLESS/VMess/Trojan.
type Transport struct {
	Type        string // "tcp", "ws", "grpc", "httpupgrade", "http"
	Path        string
	Host        string
	ServiceName string
}

// Multiplex enables sing-mux style multiplexing on TCP-based protocols.
type Multiplex struct {
	Enabled bool
	Padding bool
	Brutal  *Brutal
}

// Brutal is TCP Brutal congestion control settings.
type Brutal struct {
	UpMbps   int
	DownMbps int
}

// Inbound is one listener. A node may run many, possibly on different cores.
type Inbound struct {
	Tag      string
	Protocol Protocol
	Listen   string // "" means dual-stack any
	Port     int
	Core     string // preferred core name; "" lets the registry choose

	TLS       *TLS
	Transport *Transport
	Multiplex *Multiplex

	// Protocol-specific fields. Unused ones stay zero.
	Flow              string   // vless
	Cipher            string   // shadowsocks
	ServerKey         string   // shadowsocks 2022 server PSK (base64)
	Obfs              string   // hysteria2 obfs type ("salamander") or ""
	ObfsPassword      string   // hysteria2
	UpMbps            int      // hysteria2
	DownMbps          int      // hysteria2
	CongestionControl string   // tuic
	PaddingScheme     []string // anytls
	MieruTransport    string   // mieru: "TCP" or "UDP"
	TrafficPattern    string   // mieru
}

// User is a subscriber allowed on every inbound of the node.
type User struct {
	ID             int64
	Name           string // stable identity used for stats; panels usually use the UUID
	UUID           string
	Password       string
	SpeedLimitMbps int // 0 = unlimited
	DeviceLimit    int // 0 = unlimited
}

// Outbound is an extra egress the panel defines (e.g. relay to a landing node).
type Outbound struct {
	Tag      string
	Protocol string
	Settings map[string]any
	ProxyTag string // chain: dial through this outbound
}

// RouteRule directs matched traffic to an action.
type RouteRule struct {
	Match  []string // e.g. "domain:example.com", "ip:1.1.1.1/32", "protocol:bittorrent"
	Action string   // "direct", "block", "outbound"
	Value  string   // outbound tag when Action == "outbound"
}

// Node is the complete desired state for this server.
type Node struct {
	ID        string
	Inbounds  []Inbound
	Outbounds []Outbound
	Routes    []RouteRule
}

// Traffic is a byte counter pair.
type Traffic struct {
	Up   int64
	Down int64
}

// UserTraffic is traffic attributed to one user since the last report.
type UserTraffic struct {
	UserID int64
	Up     int64
	Down   int64
}

// SystemStatus is a host resource snapshot.
type SystemStatus struct {
	CPUPercent float64
	MemTotal   uint64
	MemUsed    uint64
	SwapTotal  uint64
	SwapUsed   uint64
	DiskTotal  uint64
	DiskUsed   uint64
}

// Intervals are the panel-requested polling cadences.
type Intervals struct {
	Pull time.Duration
	Push time.Duration
}
