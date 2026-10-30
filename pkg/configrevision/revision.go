// Package configrevision identifies declared proxy configuration structure.
// It deliberately excludes live authorization and credential material. It is
// neither a replacement for a complete state revision nor a replayable snapshot.
package configrevision

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Prefix versions the projection contract, including its normalization rules.
const Prefix = "cfg1-"

// ErrUnsupported means the declaration cannot be safely classified. Callers
// should retain ordinary state delivery and omit structural confirmation.
// No error includes user-supplied settings, tags or credential material.
var ErrUnsupported = errors.New("configuration structure cannot be classified")

// Digest hashes explicit allowlisted fields before any machine-specific
// certificate, WARP-account or private-access resolution. forwards is the
// authoritative forwarding list: the Captain driver replaces Node.Forwards
// with this list. A local caller can pass node.Forwards explicitly.
//
// A matching digest says nothing about current users, keys, certificates,
// service control, application success or connectivity. Delivery confirmation
// must additionally bind the complete state revision and process session.
func Digest(node spec.Node, forwards []spec.Forward) (string, error) {
	p, err := project(node, forwards)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("%w: projection encoding", ErrUnsupported)
	}
	sum := sha256.Sum256(b)
	return Prefix + hex.EncodeToString(sum[:]), nil
}

// These private DTOs intentionally contain no spec structs, opaque maps or
// json.RawMessage. Future spec fields do not silently enter the digest.
type projection struct {
	Schema                                     string
	Mode                                       string
	Inbounds                                   []inbound
	Outbounds                                  []outbound
	Routes                                     []route
	Forwards                                   []forward
	ReverseClients                             []reverseClient
	WireGuardLinks                             []wireGuardLink
	EgressUpstreams                            []egressUpstream
	DefaultOutbound                            string
	ConnLog, AllowPrivateDest, EgressByIngress bool
	PrivateDestAllow                           []string
	AuditRules                                 []auditRule
	DNS                                        []string
	Decoy                                      *decoy
}
type inbound struct {
	WireGuardSlot                                int
	PrivateAccess                                *privateAccess
	Reverse                                      *reverseInbound
	Tag, Protocol, Listen, Core                  string
	Port                                         int
	TLS                                          *tls
	Transport                                    transport
	Multiplex                                    *multiplex
	Flow, Cipher, Obfs                           string
	UpMbps, DownMbps                             int
	CongestionControl                            string
	PaddingScheme                                []string
	MieruTransport, TrafficPattern               string
	MieruMTU                                     int
	MieruMultiplexing, MieruHandshake            string
	WGAddress                                    string
	WGMTU, SnellVersion                          int
	SnellObfs, SnellObfsHost                     string
	ShadowTLS                                    *shadowTLS
	SnellMultiUser, NoSniff, AcceptProxyProtocol bool
	Fallbacks                                    []fallback
}
type tls struct {
	Mode       int
	ServerName string
	ALPN       []string
	Reality    *reality
	AutoCert   bool
	ACME       string
}
type reality struct {
	HandshakeServer string
	HandshakePort   int
	FallbackLimit   *fallbackLimit
}
type fallbackLimit struct {
	Off                                       bool
	AfterBytes, BytesPerSec, BurstBytesPerSec int64
}
type transport struct{ Type, Path, Host, ServiceName, Mode string }
type multiplex struct {
	Enabled, Padding bool
	Brutal           *brutal
}
type brutal struct{ UpMbps, DownMbps int }
type shadowTLS struct {
	Handshake  string
	StrictMode bool
}
type fallback struct {
	Name, ALPN, Path, Dest string
	Xver                   int
}
type privateAccess struct {
	AllowCoreOnly     bool
	Enforcement, Mode string
	Rules             []privateRule
}
type privateRule struct {
	CIDR, Protocol     string
	PortStart, PortEnd int
}
type reverseInbound struct {
	ID       string
	Receiver bool
}
type reverseClient struct {
	PrivateAccess *privateAccess
	ID, Host      string
	Port          int
	TLS           *tls
}
type wireGuardLink struct {
	Slot             int
	Exit             bool
	Endpoint         string
	ListenPort, MTU  int
	PrivateAccess    *privateAccess
	DomainPreference string
	AutoForwarding   bool
}
type egressUpstream struct {
	CIDR, Protocol string
	Port           int
}
type outbound struct {
	Tag, Protocol, ProxyTag string
	Remote                  *remote
	WARP                    *warp
	Balancer                *balancer
}
type remote struct {
	Host        string
	Port        int
	Insecure    bool
	Fingerprint string
	Settings    inbound
}
type warp struct {
	FromNode  bool
	Endpoint  string
	Addresses []string
}
type balancer struct {
	Members  []string
	Strategy string
}
type route struct {
	Match         []string
	Action, Value string
}
type auditRule struct {
	ID     int64
	Match  []string
	Action string
}
type forward struct {
	PathHealth                    *pathHealth `json:",omitempty"`
	Tag, Listen                   string
	Port                          int
	Protocol, Backend             string
	PreserveSource, ProxyProtocol bool
	Targets                       []forwardTarget
	Balance                       string
}
type pathHealth struct {
	RouteID                                                              int64
	ScopeID, Protocol, ServerName                                        string
	ALPN                                                                 []string
	AutoFailover                                                         bool
	IntervalSeconds, TimeoutSeconds, FailureThreshold, RecoveryThreshold int
	Candidates                                                           []pathHealthCandidate
}
type pathHealthCandidate struct{ ID, Target, Digest string }

func projectPathHealth(p *spec.PathHealth) *pathHealth {
	if p == nil {
		return nil
	}
	out := &pathHealth{RouteID: p.RouteID, ScopeID: p.ScopeID, Protocol: p.Protocol, ServerName: p.ServerName, ALPN: stringsCopy(p.ALPN), AutoFailover: p.AutoFailover, IntervalSeconds: p.IntervalSeconds, TimeoutSeconds: p.TimeoutSeconds, FailureThreshold: p.FailureThreshold, RecoveryThreshold: p.RecoveryThreshold}
	for _, c := range p.Candidates {
		out.Candidates = append(out.Candidates, pathHealthCandidate{ID: c.ID, Target: c.Target, Digest: c.Digest})
	}
	return out
}

type forwardTarget struct {
	Target string
	Weight int
}
type decoy struct {
	Domain                 string
	Port                   int
	Upstream, ACME         string
	AllowPrivate, Insecure bool
}

func project(n spec.Node, forwards []spec.Forward) (*projection, error) {
	for _, resolver := range n.DNS {
		if err := checkEndpointURL(resolver, true); err != nil {
			return nil, err
		}
	}
	if n.Decoy != nil {
		if err := checkEndpointURL(n.Decoy.Upstream, false); err != nil {
			return nil, err
		}
	}
	for _, raw := range n.Overrides {
		if strings.TrimSpace(string(raw)) == "" {
			continue
		}
		var empty map[string]json.RawMessage
		if json.Unmarshal(raw, &empty) != nil || len(empty) != 0 {
			return nil, fmt.Errorf("%w: native overrides", ErrUnsupported)
		}
	}
	p := &projection{Schema: Prefix, Mode: string(n.Mode.Effective()), DefaultOutbound: n.DefaultOutbound, ConnLog: n.ConnLog, AllowPrivateDest: n.AllowPrivateDest, EgressByIngress: n.EgressByIngress, PrivateDestAllow: stringsCopy(n.PrivateDestAllow), DNS: stringsCopy(n.DNS)}
	for _, v := range n.Inbounds {
		p.Inbounds = append(p.Inbounds, projectInbound(v))
	}
	for _, v := range n.Outbounds {
		if len(v.Settings) > 0 {
			return nil, fmt.Errorf("%w: native outbound settings", ErrUnsupported)
		}
		selectors := 0
		for _, present := range []bool{v.Remote != nil, v.WARP != nil, v.Balancer != nil} {
			if present {
				selectors++
			}
		}
		if selectors > 1 {
			return nil, fmt.Errorf("%w: ambiguous outbound selector", ErrUnsupported)
		}
		o := outbound{Tag: v.Tag, Protocol: v.Protocol, ProxyTag: v.ProxyTag}
		if r := v.Remote; r != nil {
			o.Remote = &remote{Host: r.Host, Port: r.Port, Insecure: r.Insecure, Fingerprint: r.Fingerprint, Settings: projectInbound(r.Settings)}
		}
		if w := v.WARP; w != nil {
			o.WARP = &warp{FromNode: w.FromNode, Endpoint: w.Endpoint, Addresses: stringsCopy(w.Addresses)}
		}
		if b := v.Balancer; b != nil {
			o.Balancer = &balancer{Members: stringsCopy(b.Members), Strategy: b.Strategy}
		}
		p.Outbounds = append(p.Outbounds, o)
	}
	for _, v := range n.Routes {
		p.Routes = append(p.Routes, route{stringsCopy(v.Match), v.Action, v.Value})
	}
	for _, v := range forwards {
		f := forward{PathHealth: projectPathHealth(v.PathHealth), Tag: v.Tag, Listen: v.Listen, Port: v.Port, Protocol: v.Protocol, Backend: v.Backend, PreserveSource: v.PreserveSource, ProxyProtocol: v.ProxyProtocol, Balance: v.BalanceMode()}
		if f.Backend == "" {
			f.Backend = "relay"
		}
		for _, h := range v.Hops() {
			f.Targets = append(f.Targets, forwardTarget{h.Target, h.Weight})
		}
		p.Forwards = append(p.Forwards, f)
	}
	for _, v := range n.ReverseClients {
		p.ReverseClients = append(p.ReverseClients, reverseClient{projectPrivate(v.PrivateAccess), v.ID, v.Host, v.Port, projectTLS(v.TLS)})
	}
	for _, v := range n.WireGuardLinks {
		p.WireGuardLinks = append(p.WireGuardLinks, wireGuardLink{v.Slot, v.Exit, v.Endpoint, v.ListenPort, v.MTU, projectPrivate(v.PrivateAccess), v.DomainPreference, v.AutoForwarding})
	}
	for _, v := range n.EgressUpstreams {
		p.EgressUpstreams = append(p.EgressUpstreams, egressUpstream{v.CIDR, v.Protocol, v.Port})
	}
	for _, v := range n.AuditRules {
		p.AuditRules = append(p.AuditRules, auditRule{v.ID, stringsCopy(v.Match), v.Action})
	}
	if d := n.Decoy; d != nil {
		p.Decoy = &decoy{d.Domain, d.Port, d.Upstream, d.ACME, d.AllowPrivate, d.Insecure}
	}
	// These are identity-keyed resources, not evaluation order. Ambiguous keys
	// retain input order; the digest does not validate otherwise-invalid specs.
	sortKeyed(p.Inbounds, func(v inbound) string { return v.Tag })
	sortKeyed(p.Outbounds, func(v outbound) string { return v.Tag })
	sortKeyed(p.Forwards, func(v forward) string { return v.Tag })
	sortKeyed(p.ReverseClients, func(v reverseClient) string { return v.ID })
	sortKeyed(p.WireGuardLinks, func(v wireGuardLink) string { return fmt.Sprint(v.Slot) })
	sort.Slice(p.EgressUpstreams, func(i, j int) bool {
		a, b := p.EgressUpstreams[i], p.EgressUpstreams[j]
		if a.CIDR != b.CIDR {
			return a.CIDR < b.CIDR
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.Port < b.Port
	})
	sort.Strings(p.PrivateDestAllow)
	return p, nil
}

// URL credentials and provider-specific token paths cannot be separated from
// their endpoint structure. Recognize only root upstreams and ordinary DoH;
// keep existing delivery available for other endpoints without a cfg1 claim.
func checkEndpointURL(raw string, dns bool) error {
	if !strings.Contains(raw, "://") {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return fmt.Errorf("%w: opaque endpoint URL", ErrUnsupported)
	}
	path := u.EscapedPath()
	if path != "" && path != "/" && !(dns && path == "/dns-query") {
		return fmt.Errorf("%w: opaque endpoint URL", ErrUnsupported)
	}
	return nil
}

func projectInbound(v spec.Inbound) inbound {
	i := inbound{WireGuardSlot: v.WireGuardSlot, PrivateAccess: projectPrivate(v.PrivateAccess), Tag: v.Tag, Protocol: string(v.Protocol), Listen: v.Listen, Core: v.Core, Port: v.Port, TLS: projectTLS(v.TLS), Flow: v.Flow, Cipher: v.Cipher, Obfs: v.Obfs, UpMbps: v.UpMbps, DownMbps: v.DownMbps, CongestionControl: v.CongestionControl, PaddingScheme: stringsCopy(v.PaddingScheme), MieruTransport: v.MieruTransport, TrafficPattern: v.TrafficPattern, MieruMTU: v.MieruMTU, MieruMultiplexing: v.MieruMultiplexing, MieruHandshake: v.MieruHandshake, WGAddress: v.WGAddress, WGMTU: v.WGMTU, SnellVersion: v.SnellVersion, SnellObfs: v.SnellObfs, SnellObfsHost: v.SnellObfsHost, SnellMultiUser: v.SnellMultiUser, NoSniff: v.NoSniff, AcceptProxyProtocol: v.AcceptProxyProtocol}
	i.Transport.Type = v.TransportType()
	if t := v.Transport; t != nil {
		i.Transport = transport{v.TransportType(), t.Path, t.Host, t.ServiceName, t.Mode}
	}
	if r := v.Reverse; r != nil {
		i.Reverse = &reverseInbound{r.ID, r.Receiver}
	}
	if m := v.Multiplex; m != nil {
		i.Multiplex = &multiplex{Enabled: m.Enabled, Padding: m.Padding}
		if b := m.Brutal; b != nil {
			i.Multiplex.Brutal = &brutal{b.UpMbps, b.DownMbps}
		}
	}
	if s := v.ShadowTLS; s != nil {
		i.ShadowTLS = &shadowTLS{s.Handshake, s.StrictMode}
	}
	for _, f := range v.Fallbacks {
		i.Fallbacks = append(i.Fallbacks, fallback{f.Name, f.ALPN, f.Path, f.Dest, f.Xver})
	}
	return i
}
func projectTLS(v *spec.TLS) *tls {
	if v == nil {
		return nil
	}
	t := &tls{Mode: int(v.Mode), ServerName: v.ServerName, ALPN: stringsCopy(v.ALPN), AutoCert: v.AutoCert, ACME: v.ACME}
	if r := v.Reality; r != nil {
		t.Reality = &reality{HandshakeServer: r.HandshakeServer, HandshakePort: r.HandshakePort}
		if f := r.FallbackLimit; f != nil {
			t.Reality.FallbackLimit = &fallbackLimit{f.Off, f.AfterBytes, f.BytesPerSec, f.BurstBytesPerSec}
		}
	}
	return t
}
func projectPrivate(v *spec.PrivateAccess) *privateAccess {
	if v == nil {
		return nil
	}
	p := &privateAccess{AllowCoreOnly: v.AllowCoreOnly, Enforcement: v.Enforcement, Mode: v.Mode}
	for _, r := range v.Rules {
		p.Rules = append(p.Rules, privateRule{r.CIDR, r.Protocol, r.PortStart, r.PortEnd})
	}
	return p
}
func stringsCopy(v []string) []string { return append([]string(nil), v...) }
func sortKeyed[T any](values []T, key func(T) string) {
	seen := map[string]bool{}
	for _, v := range values {
		k := key(v)
		if k == "" || seen[k] {
			return
		}
		seen[k] = true
	}
	sort.Slice(values, func(i, j int) bool { return key(values[i]) < key(values[j]) })
}
