package local

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/zeptop-dev/bosun/internal/authutil"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// ---- ingresses -------------------------------------------------------------

// ListIngresses returns a copy.
func (s *Store) ListIngresses() []Ingress {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Ingress{}, s.st.Ingresses...)
}

// ingressLocked finds one by id. Callers hold s.mu.
func (s *Store) ingressLocked(id string) (Ingress, bool) {
	for _, g := range s.st.Ingresses {
		if g.ID == id {
			return g, true
		}
	}
	return Ingress{}, false
}

// Ingress returns one by id.
func (s *Store) Ingress(id string) (Ingress, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ingressLocked(id)
}

func validateIngress(g *Ingress) error {
	g.Name = strings.TrimSpace(g.Name)
	if g.Name == "" {
		return errors.New("name is required")
	}
	g.BindIP = strings.TrimSpace(g.BindIP)
	if g.BindIP != "" && net.ParseIP(g.BindIP) == nil {
		return errors.New("bind address must be an IP on this node")
	}
	g.LineIP = strings.TrimSpace(g.LineIP)
	if g.LineIP != "" && net.ParseIP(g.LineIP) == nil {
		return errors.New("line address must be an IP")
	}
	g.EntryHost = strings.ToLower(strings.TrimSpace(g.EntryHost))
	if strings.ContainsAny(g.EntryHost, " /:") {
		return errors.New("entry host must be a host name or IP without a port")
	}
	g.EntryDomain = strings.ToLower(strings.TrimSpace(g.EntryDomain))
	if g.EntryDomain != "" && (strings.ContainsAny(g.EntryDomain, " /:") || net.ParseIP(g.EntryDomain) != nil || !strings.Contains(g.EntryDomain, ".")) {
		return errors.New("entry domain must be a host name")
	}
	if g.EntryDomain != "" && net.ParseIP(g.EntryHost) == nil {
		return errors.New("an entry domain needs the public entry to be an IP address to point at")
	}
	if g.LineIP == "" && g.EntryHost == "" {
		return errors.New("give the line's far-end address, its public entry, or both")
	}
	if (g.PortFrom == 0) != (g.PortTo == 0) || g.PortFrom < 0 || g.PortTo > 65535 || g.PortFrom > g.PortTo {
		return errors.New("port range must be from-to within 1-65535, or empty")
	}
	return nil
}

// PutIngress creates (prevID "") or replaces a line ingress. The id is
// generated on create and kept on update.
func (s *Store) PutIngress(g Ingress, prevID string) (Ingress, error) {
	if err := validateIngress(&g); err != nil {
		return Ingress{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if prevID == "" {
		g.ID = authutil.Hex(4)
		s.st.Ingresses = append(s.st.Ingresses, g)
		return g, s.commit()
	}
	for i, cur := range s.st.Ingresses {
		if cur.ID == prevID {
			g.ID = prevID
			s.st.Ingresses[i] = g
			return g, s.commit()
		}
	}
	return Ingress{}, ErrNotFound
}

// DeleteIngress removes a line; inbounds using it fall back to direct.
func (s *Store) DeleteIngress(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, cur := range s.st.Ingresses {
		if cur.ID == id {
			idx = i
		}
	}
	if idx < 0 {
		return ErrNotFound
	}
	s.st.Ingresses = append(s.st.Ingresses[:idx], s.st.Ingresses[idx+1:]...)
	for i := range s.st.Inbounds {
		if s.st.Inbounds[i].IngressID == id {
			s.st.Inbounds[i].IngressID = ""
		}
	}
	return s.commit()
}

// ---- routing ---------------------------------------------------------------

// Routing is the node's landing outbounds and rules.
type Routing struct {
	Outbounds       []spec.Outbound  `json:"outbounds"`
	Routes          []spec.RouteRule `json:"routes"`
	DefaultOutbound string           `json:"default_outbound"`
	DNS             []string         `json:"dns"`
	// Traffic is lifetime bytes per outbound tag (read-only).
	Traffic map[string]spec.Traffic `json:"traffic,omitempty"`
}

// Routing returns a copy with non-nil slices.
func (s *Store) Routing() Routing {
	s.mu.Lock()
	defer s.mu.Unlock()
	tr := map[string]spec.Traffic{}
	for k, v := range s.st.OutboundTraffic {
		tr[k] = v
	}
	return Routing{Outbounds: append([]spec.Outbound{}, s.st.Outbounds...), Routes: append([]spec.RouteRule{}, s.st.Routes...), DefaultOutbound: s.st.DefaultOutbound, DNS: append([]string{}, s.st.DNS...), Traffic: tr}
}

// ValidateRouting checks tags: every rule and the default must point at a
// defined outbound, chains must not loop.
func ValidateRouting(nr *Routing) error {
	tags := map[string]bool{"direct": true, "block": true}
	for i := range nr.Outbounds {
		o := &nr.Outbounds[i]
		o.Tag = strings.TrimSpace(o.Tag)
		if o.Tag == "" || tags[o.Tag] {
			return errors.New("every outbound needs a unique tag (not direct/block)")
		}
		if o.Remote == nil && o.Protocol == "" && o.WARP == nil && o.Balancer == nil {
			return errors.New("outbound " + o.Tag + ": a share link or a protocol with settings is required")
		}
		if o.Balancer != nil && len(o.Balancer.Members) == 0 {
			return errors.New("balancer " + o.Tag + " needs at least one member")
		}
		if o.Remote != nil && (o.Remote.Host == "" || o.Remote.Port <= 0 || o.Remote.Settings.Protocol == "") {
			return errors.New("outbound " + o.Tag + ": host, port and protocol are required")
		}
		if o.ProxyTag == o.Tag {
			return errors.New("outbound " + o.Tag + " cannot chain through itself")
		}
		tags[o.Tag] = true
	}
	for _, o := range nr.Outbounds {
		if o.ProxyTag != "" && !tags[o.ProxyTag] {
			return errors.New("outbound " + o.Tag + " chains through unknown " + o.ProxyTag)
		}
		if o.Balancer != nil {
			for _, mbr := range o.Balancer.Members {
				if !tags[mbr] || mbr == o.Tag {
					return errors.New("balancer " + o.Tag + " has unknown member " + mbr)
				}
			}
		}
	}
	// A chain must end somewhere: walk proxy_tag links and refuse cycles.
	via := map[string]string{}
	for _, o := range nr.Outbounds {
		via[o.Tag] = o.ProxyTag
	}
	for _, o := range nr.Outbounds {
		seen := map[string]bool{}
		for cur := o.Tag; cur != ""; cur = via[cur] {
			if seen[cur] {
				return errors.New("outbound " + o.Tag + " is part of a chain loop")
			}
			seen[cur] = true
		}
	}
	for i := range nr.Routes {
		rule := &nr.Routes[i]
		switch rule.Action {
		case "outbound":
			if !tags[rule.Value] || rule.Value == "direct" || rule.Value == "block" {
				return errors.New("rule points at unknown outbound " + rule.Value)
			}
		case "direct", "block":
			rule.Value = ""
		default:
			return errors.New("rule action must be outbound, direct or block")
		}
		if len(rule.Match) == 0 {
			return errors.New("a rule needs at least one match (inbound:tag, domain:, ip:, protocol:, port:)")
		}
	}
	if nr.DefaultOutbound != "" && (!tags[nr.DefaultOutbound] || nr.DefaultOutbound == "direct" || nr.DefaultOutbound == "block") {
		return errors.New("default outbound must be one of the defined outbounds")
	}
	return nil
}

// SetRouting validates and stores the exits and rules.
func (s *Store) SetRouting(nr Routing) error {
	if err := ValidateRouting(&nr); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Outbounds, s.st.Routes, s.st.DefaultOutbound, s.st.DNS = nr.Outbounds, nr.Routes, nr.DefaultOutbound, nr.DNS
	return s.commit()
}

// ---- certificates ----------------------------------------------------------

// CertificateView is what the UI sees: never the PEM or the key.
type CertificateView struct {
	Domain   string    `json:"domain"`
	Names    []string  `json:"names"`
	NotAfter time.Time `json:"not_after"`
	Issuer   string    `json:"issuer"`
}

// ParseCertificate validates a PEM pair and reads its names and expiry.
// domain may be blank: the leaf's first DNS name is used.
func ParseCertificate(domain, certPEM, keyPEM string) (spec.Certificate, CertificateView, error) {
	certPEM, keyPEM = strings.TrimSpace(certPEM)+"\n", strings.TrimSpace(keyPEM)+"\n"
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return spec.Certificate{}, CertificateView{}, errors.New("certificate and key do not parse as a pair: " + err.Error())
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return spec.Certificate{}, CertificateView{}, err
	}
	names := append([]string{}, leaf.DNSNames...)
	if len(names) == 0 && leaf.Subject.CommonName != "" {
		names = []string{leaf.Subject.CommonName}
	}
	for i := range names {
		names[i] = strings.ToLower(names[i])
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		if len(names) == 0 {
			return spec.Certificate{}, CertificateView{}, errors.New("certificate has no DNS names; give a domain")
		}
		domain = names[0]
	}
	has := false
	for _, n := range names {
		if n == domain {
			has = true
		}
	}
	if !has {
		names = append([]string{domain}, names...)
	}
	return spec.Certificate{Domain: domain, CertPEM: certPEM, KeyPEM: keyPEM}, CertificateView{Domain: domain, Names: names, NotAfter: leaf.NotAfter, Issuer: leaf.Issuer.CommonName}, nil
}

// ListCertificates returns the stored pairs as views.
func (s *Store) ListCertificates() []CertificateView {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []CertificateView{}
	for _, c := range s.st.Certificates {
		_, v, err := ParseCertificate(c.Domain, c.CertPEM, c.KeyPEM)
		if err != nil {
			v = CertificateView{Domain: c.Domain, Names: []string{c.Domain}}
		}
		out = append(out, v)
	}
	return out
}

// PutCertificate stores or replaces the pair for its domain.
func (s *Store) PutCertificate(domain, certPEM, keyPEM string) (CertificateView, error) {
	c, v, err := ParseCertificate(domain, certPEM, keyPEM)
	if err != nil {
		return CertificateView{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	replaced := false
	for i := range s.st.Certificates {
		if s.st.Certificates[i].Domain == c.Domain {
			s.st.Certificates[i] = c
			replaced = true
		}
	}
	if !replaced {
		s.st.Certificates = append(s.st.Certificates, c)
	}
	return v, s.commit()
}

// DeleteCertificate removes the pair for a domain.
func (s *Store) DeleteCertificate(domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.st.Certificates {
		if c.Domain == strings.ToLower(strings.TrimSpace(domain)) {
			s.st.Certificates = append(s.st.Certificates[:i], s.st.Certificates[i+1:]...)
			return s.commit()
		}
	}
	return ErrNotFound
}

// ---- probe -----------------------------------------------------------------

// ProbeSettings returns a copy with non-nil slices.
func (s *Store) ProbeSettings() ProbeSettings {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.st.Probe
	p.Carriers = append([]spec.Carrier{}, p.Carriers...)
	p.Tasks = append([]spec.PingTask{}, p.Tasks...)
	return p
}

// ValidateProbe checks carriers and tasks and numbers the tasks.
func ValidateProbe(p *ProbeSettings) error {
	seen := map[string]bool{}
	carriers := []spec.Carrier{}
	for i, c := range p.Carriers {
		c.Name, c.Addr = strings.TrimSpace(c.Name), strings.TrimSpace(c.Addr)
		if c.Name == "" && c.Addr == "" {
			continue
		}
		if host, port, err := net.SplitHostPort(c.Addr); err != nil || host == "" || port == "" {
			return fmt.Errorf("carrier %d: address must be host:port", i+1)
		}
		if c.Name == "" || seen[c.Name] {
			return fmt.Errorf("carrier %d: a unique name is required", i+1)
		}
		seen[c.Name] = true
		carriers = append(carriers, c)
	}
	p.Carriers = carriers
	tasks := []spec.PingTask{}
	for i, t := range p.Tasks {
		t.Name, t.Target, t.SourceIP = strings.TrimSpace(t.Name), strings.TrimSpace(t.Target), strings.TrimSpace(t.SourceIP)
		t.Type = strings.ToLower(strings.TrimSpace(t.Type))
		switch t.Type {
		case "icmp", "tcp", "http", "download":
		default:
			return fmt.Errorf("task %d: type must be icmp, tcp, http or download", i+1)
		}
		if t.Target == "" {
			return fmt.Errorf("task %d: target is required", i+1)
		}
		if t.SourceIP != "" && net.ParseIP(t.SourceIP) == nil {
			return fmt.Errorf("task %d: source must be an IP", i+1)
		}
		if t.Name == "" {
			t.Name = t.Target
		}
		t.ID = int64(i + 1)
		tasks = append(tasks, t)
	}
	p.Tasks = tasks
	return nil
}

// SetProbe validates and stores the probe configuration.
func (s *Store) SetProbe(p ProbeSettings) error {
	if err := ValidateProbe(&p); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Probe = p
	return s.commit()
}

// Probe implements panel.ProbeSource: the UI's settings plus one RTT task
// per line ingress, measured from the line NIC to its far end (a refused
// port still yields the line's round trip).
func (s *Store) Probe() *spec.Probe {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.st.Probe.Enabled {
		return nil
	}
	p := &spec.Probe{Enabled: true, CarrierPing: s.st.Probe.CarrierPing, Carriers: append([]spec.Carrier(nil), s.st.Probe.Carriers...), Tasks: append([]spec.PingTask(nil), s.st.Probe.Tasks...)}
	for i, g := range s.st.Ingresses {
		if g.BindIP == "" || g.LineIP == "" {
			continue
		}
		port := 0
		for _, ib := range s.st.Inbounds {
			if ib.IngressID == g.ID {
				port = ib.Port
				break
			}
		}
		if port == 0 {
			port = g.ProbePort()
		}
		p.Tasks = append(p.Tasks, spec.PingTask{ID: -int64(i + 1), Name: g.Name, Type: "tcp", Target: net.JoinHostPort(g.LineIP, strconv.Itoa(port)), IntervalSeconds: 30, SourceIP: g.BindIP})
	}
	return p
}

// ---- komari ----------------------------------------------------------------

// KomariSettings returns the exporter configuration.
func (s *Store) KomariSettings() spec.Komari {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Komari
}

// SetKomari validates and stores it; a blank key keeps the stored one.
func (s *Store) SetKomari(k spec.Komari) error {
	k.Server = strings.TrimRight(strings.TrimSpace(k.Server), "/")
	k.Name = strings.TrimSpace(k.Name)
	if k.Enabled && !strings.HasPrefix(k.Server, "http://") && !strings.HasPrefix(k.Server, "https://") {
		return errors.New("komari: server must start with http:// or https://")
	}
	if k.Interval < 0 || k.Interval > 300 {
		return errors.New("komari: interval must be 0-300 seconds")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(k.Key) == "" {
		k.Key = s.st.Komari.Key
	}
	s.st.Komari = k
	return s.commit()
}

// Komari implements panel.KomariSource.
func (s *Store) Komari() *spec.Komari {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.st.Komari.Enabled {
		return nil
	}
	k := s.st.Komari
	return &k
}

// DStatus implements panel.DStatusSource.
func (s *Store) DStatus() *spec.DStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.st.DStatus.Enabled {
		return nil
	}
	d := s.st.DStatus
	return &d
}
