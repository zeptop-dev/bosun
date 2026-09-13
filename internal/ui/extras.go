package ui

import (
	"errors"
	"net/http"
	"strings"

	"github.com/zeptop-dev/bosun/internal/local"
	"github.com/zeptop-dev/bosun/pkg/sharelink"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Standalone parity with Captain's node page: line ingresses, landing
// outbounds and routes, operator certificates and the probe.

func (s *Server) extraRoutes() {
	m := s.mux
	auth := s.requireAuth
	m.HandleFunc("GET /api/ingresses", auth(s.listIngresses))
	m.HandleFunc("POST /api/ingresses", auth(s.local(s.createIngress)))
	m.HandleFunc("PUT /api/ingresses/{id}", auth(s.local(s.updateIngress)))
	m.HandleFunc("DELETE /api/ingresses/{id}", auth(s.local(s.deleteIngress)))

	m.HandleFunc("GET /api/routing", auth(s.getRouting))
	m.HandleFunc("PUT /api/routing", auth(s.local(s.putRouting)))
	m.HandleFunc("POST /api/routing/parse", auth(s.parseLinks))

	m.HandleFunc("GET /api/certificates", auth(s.listCertificates))
	m.HandleFunc("POST /api/certificates", auth(s.local(s.putCertificate)))
	m.HandleFunc("DELETE /api/certificates/{domain}", auth(s.local(s.deleteCertificate)))

	m.HandleFunc("GET /api/probe", auth(s.getProbe))
	m.HandleFunc("PUT /api/probe", auth(s.local(s.putProbe)))
}

// ---- ingresses -------------------------------------------------------------

// ingressInput accepts the PascalCase keys the forms send and the
// snake_case keys of the stored object.
type ingressInput struct {
	Name        string `json:"Name"`
	BindIP      string `json:"BindIP"`
	LineIP      string `json:"LineIP"`
	EntryHost   string `json:"EntryHost"`
	EntryDomain string `json:"EntryDomain"`
	PortFrom    int    `json:"PortFrom"`
	PortTo      int    `json:"PortTo"`
	PortOffset  int    `json:"PortOffset"`

	SName        string `json:"name"`
	SBindIP      string `json:"bind_ip"`
	SLineIP      string `json:"line_ip"`
	SEntryHost   string `json:"entry_host"`
	SEntryDomain string `json:"entry_domain"`
	SPortFrom    int    `json:"port_from"`
	SPortTo      int    `json:"port_to"`
	SPortOffset  int    `json:"port_offset"`
}

func (in ingressInput) ingress() local.Ingress {
	pick := func(a, b string) string {
		if a != "" {
			return a
		}
		return b
	}
	pickInt := func(a, b int) int {
		if a != 0 {
			return a
		}
		return b
	}
	return local.Ingress{
		Name: pick(in.Name, in.SName), BindIP: pick(in.BindIP, in.SBindIP), LineIP: pick(in.LineIP, in.SLineIP),
		EntryHost: pick(in.EntryHost, in.SEntryHost), EntryDomain: pick(in.EntryDomain, in.SEntryDomain),
		PortFrom: pickInt(in.PortFrom, in.SPortFrom), PortTo: pickInt(in.PortTo, in.SPortTo), PortOffset: pickInt(in.PortOffset, in.SPortOffset),
	}
}

func (s *Server) listIngresses(w http.ResponseWriter, r *http.Request) {
	ok(w, s.d.Store.ListIngresses())
}

func (s *Server) createIngress(w http.ResponseWriter, r *http.Request) {
	var in ingressInput
	if err := decode(r, &in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	g, err := s.d.Store.PutIngress(in.ingress(), "")
	if err != nil {
		storeErr(w, err)
		return
	}
	ok(w, g)
}

func (s *Server) updateIngress(w http.ResponseWriter, r *http.Request) {
	var in ingressInput
	if err := decode(r, &in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	g, err := s.d.Store.PutIngress(in.ingress(), r.PathValue("id"))
	if err != nil {
		storeErr(w, err)
		return
	}
	ok(w, g)
}

func (s *Server) deleteIngress(w http.ResponseWriter, r *http.Request) {
	storeErr(w, s.d.Store.DeleteIngress(r.PathValue("id")))
}

// ---- routing ---------------------------------------------------------------

func (s *Server) getRouting(w http.ResponseWriter, r *http.Request) {
	ok(w, s.d.Store.Routing())
}

func (s *Server) putRouting(w http.ResponseWriter, r *http.Request) {
	var nr local.Routing
	if err := decode(r, &nr); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	storeErr(w, s.d.Store.SetRouting(nr))
}

// parseLinks turns pasted share links into landing outbound remotes.
func (s *Server) parseLinks(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Text string `json:"text"`
		Alt  string `json:"Text"`
	}
	if err := decode(r, &in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	text := in.Text
	if text == "" {
		text = in.Alt
	}
	if strings.TrimSpace(text) == "" {
		fail(w, http.StatusBadRequest, errors.New("paste one or more share links"))
		return
	}
	lines, skipped := sharelink.ParseList(text)
	type node struct {
		Name     string       `json:"name"`
		Protocol string       `json:"protocol"`
		Remote   *spec.Remote `json:"remote"`
	}
	out := []node{}
	for _, l := range lines {
		out = append(out, node{Name: l.Name, Protocol: string(l.Inbound.Protocol), Remote: l.Remote()})
	}
	ok(w, map[string]any{"nodes": out, "skipped": skipped})
}

// ---- certificates ----------------------------------------------------------

func (s *Server) listCertificates(w http.ResponseWriter, r *http.Request) {
	ok(w, s.d.Store.ListCertificates())
}

func (s *Server) putCertificate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domain  string `json:"domain"`
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := decode(r, &in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if in.CertPEM == "" || in.KeyPEM == "" {
		fail(w, http.StatusBadRequest, errors.New("cert_pem and key_pem are required"))
		return
	}
	v, err := s.d.Store.PutCertificate(in.Domain, in.CertPEM, in.KeyPEM)
	if err != nil {
		storeErr(w, err)
		return
	}
	ok(w, v)
}

func (s *Server) deleteCertificate(w http.ResponseWriter, r *http.Request) {
	storeErr(w, s.d.Store.DeleteCertificate(r.PathValue("domain")))
}

// ---- probe -----------------------------------------------------------------

func (s *Server) probeResults() []spec.PingResult {
	out := []spec.PingResult{}
	if a := s.currentAgent(); a != nil {
		out = append(out, a.ProbeResults()...)
	}
	return out
}

func (s *Server) getProbe(w http.ResponseWriter, r *http.Request) {
	ok(w, map[string]any{"settings": s.d.Store.ProbeSettings(), "results": s.probeResults(), "defaults": spec.DefaultCarriers()})
}

func (s *Server) putProbe(w http.ResponseWriter, r *http.Request) {
	var p local.ProbeSettings
	if err := decode(r, &p); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	storeErr(w, s.d.Store.SetProbe(p))
}
