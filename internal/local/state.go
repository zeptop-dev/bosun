// Package local is bosun's standalone mode: inbounds, users and forwards
// live in a JSON state file on the node and the built-in web UI edits them.
// The same package implements panel.Driver over that file, so the agent does
// not care whether its desired state comes from Captain or from here.
//
// Modes: in "local" mode the file is authoritative. Adopting a Captain
// panel snapshots the local objects, switches the mode to "managed" and the
// agent restarts on the Captain driver; detaching restores the snapshot (or
// keeps the last managed state as the new local config).
package local

import (
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Mode is who owns the node's desired state.
type Mode string

const (
	ModeLocal   Mode = "local"
	ModeManaged Mode = "managed"
)

// State is the whole standalone configuration, persisted as one JSON file.
type State struct {
	Revision int64 `json:"revision"`

	Admin Admin `json:"admin"`
	Mode  Mode  `json:"mode"`
	// Managed is set while a panel owns the node.
	Managed *Managed `json:"managed,omitempty"`
	// Snapshot is the local config saved when a panel took over.
	Snapshot *Snapshot `json:"snapshot,omitempty"`

	Settings Settings `json:"settings"`

	Inbounds []Inbound      `json:"inbounds"`
	Users    []User         `json:"users"`
	Forwards []spec.Forward `json:"forwards"`

	// Ingresses are lines (IPLC) in front of the node; see Ingress.
	Ingresses []Ingress `json:"ingresses,omitempty"`
	// Outbounds/Routes/DefaultOutbound are the landing exits and rules,
	// the same objects Captain pushes in spec.Node.
	Outbounds       []spec.Outbound  `json:"outbounds,omitempty"`
	Routes          []spec.RouteRule `json:"routes,omitempty"`
	DefaultOutbound string           `json:"default_outbound,omitempty"`
	// Certificates are operator-supplied PEM pairs used ahead of ACME.
	Certificates []spec.Certificate `json:"certificates,omitempty"`
	// Probe is the standalone monitoring configuration.
	Probe ProbeSettings `json:"probe"`
	// Komari reports this node to a Komari server as an agent.
	Komari spec.Komari `json:"komari"`
}

// Ingress is a way into the node other than its public address: an IPLC
// or dedicated line with its own NIC address, the far-end address relays
// forward to, an optional provider-supplied public entry and a port range.
type Ingress struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	BindIP      string `json:"bind_ip"`      // local NIC address inbounds bind to ("" = all)
	LineIP      string `json:"line_ip"`      // far-end address a relay forwards to
	EntryHost   string `json:"entry_host"`   // provider's public entry clients dial ("" = none)
	EntryDomain string `json:"entry_domain"` // name for the public entry, advertised instead of the IP
	PortFrom    int    `json:"port_from"`    // usable port range (0 = any)
	PortTo      int    `json:"port_to"`
	PortOffset  int    `json:"port_offset"` // entry port = local port + offset
	// ReservedPorts are mapped ports the provider keeps (SSH); inbounds skip them.
	ReservedPorts []int `json:"reserved_ports,omitempty"`
}

// ClientHost is what share links advertise: the entry domain when set,
// else the provider's entry address.
func (g Ingress) ClientHost() string {
	if g.EntryDomain != "" {
		return g.EntryDomain
	}
	return g.EntryHost
}

// EntryPort maps a local inbound port to the port clients dial.
func (g Ingress) EntryPort(local int) int { return local + g.PortOffset }

// AllowsPort reports whether a local port fits the line's range and is not reserved.
func (g Ingress) AllowsPort(p int) bool {
	for _, r := range g.ReservedPorts {
		if r == p {
			return false
		}
	}
	return g.PortFrom == 0 || (p >= g.PortFrom && p <= g.PortTo)
}

// ProbePort is the far-end port the line RTT task uses when no inbound
// is on the line: a reserved (provider, e.g. SSH) port answers, else the
// range start, else 80.
func (g Ingress) ProbePort() int {
	if len(g.ReservedPorts) > 0 {
		return g.ReservedPorts[0]
	}
	if g.PortFrom > 0 {
		return g.PortFrom
	}
	return 80
}

// ProbeSettings is the standalone probe configuration (the UI edits it;
// config.yaml's probe section only applies to headless drivers).
type ProbeSettings struct {
	Enabled     bool            `json:"enabled"`
	CarrierPing bool            `json:"carrier_ping"`
	Carriers    []spec.Carrier  `json:"carriers"`
	Tasks       []spec.PingTask `json:"tasks"`
}

// Admin is the single local login.
type Admin struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

// Managed records the adopting panel.
type Managed struct {
	URL      string    `json:"url"`
	PairedAt time.Time `json:"paired_at"`
}

// Snapshot is the local objects before a takeover.
type Snapshot struct {
	TakenAt         time.Time          `json:"taken_at"`
	Inbounds        []Inbound          `json:"inbounds"`
	Users           []User             `json:"users"`
	Forwards        []spec.Forward     `json:"forwards"`
	Ingresses       []Ingress          `json:"ingresses,omitempty"`
	Outbounds       []spec.Outbound    `json:"outbounds,omitempty"`
	Routes          []spec.RouteRule   `json:"routes,omitempty"`
	DefaultOutbound string             `json:"default_outbound,omitempty"`
	Certificates    []spec.Certificate `json:"certificates,omitempty"`
	Probe           ProbeSettings      `json:"probe"`
}

// Settings are node-wide values the UI edits.
type Settings struct {
	// PublicHost is the address clients connect to; used in share links. When
	// empty the web UI falls back to the host it was reached on.
	PublicHost string `json:"public_host"`
	// NodeName prefixes share-link names.
	NodeName string `json:"node_name"`
	// ACMEEmail is the Let's Encrypt account contact for automatic certificates.
	ACMEEmail string `json:"acme_email"`
	// CloudflareToken enables DNS-01 challenges (wildcards, boxes without port 80).
	CloudflareToken string `json:"cloudflare_token"`
	// PanelDomain serves the web panel over HTTPS with an automatic
	// certificate for this name (takes effect after a restart).
	PanelDomain string `json:"panel_domain"`
	// PanelACME is the challenge for the panel certificate: "http" or "dns".
	PanelACME string `json:"panel_acme"`
}

// Inbound is a spec.Inbound plus local bookkeeping.
type Inbound struct {
	spec.Inbound
	Remark  string `json:"remark,omitempty"`
	Enabled bool   `json:"enabled"`
	// DisplayHost/DisplayPort override the address shown in share links, for
	// entrances that forward to this node (an IPLC provider's front door).
	DisplayHost string `json:"display_host,omitempty"`
	DisplayPort int    `json:"display_port,omitempty"`
	// IngressID picks a line ingress; "" = the node's direct entry.
	IngressID string `json:"ingress_id,omitempty"`
}

// User is a local subscriber with its own accounting.
type User struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	UUID     string `json:"uuid"`
	Password string `json:"password"`
	SubToken string `json:"sub_token"`
	Enabled  bool   `json:"enabled"`

	QuotaBytes int64      `json:"quota_bytes"` // 0 = unlimited
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	Up         int64      `json:"up"`
	Down       int64      `json:"down"`
	CreatedAt  time.Time  `json:"created_at"`
	// InboundTags restricts the user to these inbounds; empty = all.
	InboundTags []string `json:"inbound_tags,omitempty"`
}

// Usable reports whether the user should be provisioned right now.
func (u User) Usable(now time.Time) bool {
	if !u.Enabled {
		return false
	}
	if u.ExpiresAt != nil && now.After(*u.ExpiresAt) {
		return false
	}
	if u.QuotaBytes > 0 && u.Up+u.Down >= u.QuotaBytes {
		return false
	}
	return true
}

// Spec converts to the agent's user model. Name is the stats key.
func (u User) Spec() spec.User {
	pw := u.Password
	if pw == "" {
		pw = u.UUID
	}
	return spec.User{ID: u.ID, Name: u.UUID, UUID: u.UUID, Password: pw}
}
