package ui

import (
	"errors"
	"net/http"

	"github.com/zeptop-dev/bosun/pkg/subdesign"
	"github.com/zeptop-dev/bosun/pkg/subscription"
)

// Subscription templates and the visual designer, the same editors
// Captain has, for the standalone panel.

func (s *Server) subTemplateRoutes() {
	m := s.mux
	auth := s.requireAuth
	m.HandleFunc("GET /api/sub-templates", auth(s.getSubTemplates))
	m.HandleFunc("PUT /api/sub-templates", auth(s.local(s.putSubTemplates)))
	m.HandleFunc("GET /api/sub-design", auth(s.getSubDesign))
	m.HandleFunc("PUT /api/sub-design", auth(s.local(s.putSubDesign)))
	m.HandleFunc("POST /api/sub-design/preview", auth(s.previewSubDesign))
	m.HandleFunc("POST /api/sub-design/apply", auth(s.local(s.applySubDesign)))
	m.HandleFunc("GET /api/sub-design/presets/{key}", auth(s.subDesignPreset))
}

func (s *Server) writeSubTemplates(w http.ResponseWriter) {
	templates := s.d.Store.SubTemplates()
	defaults := map[string]string{}
	for _, name := range subscription.TemplateNames() {
		defaults[name] = subscription.DefaultTemplate(name)
	}
	ok(w, map[string]any{"templates": templates, "defaults": defaults})
}

func (s *Server) getSubTemplates(w http.ResponseWriter, _ *http.Request) { s.writeSubTemplates(w) }

func (s *Server) putSubTemplates(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Templates map[string]string `json:"templates"`
	}
	if err := decode(r, &in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if err := s.d.Store.SetSubTemplates(in.Templates); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	s.writeSubTemplates(w)
}

func (s *Server) getSubDesign(w http.ResponseWriter, _ *http.Request) {
	ok(w, map[string]any{"design": s.d.Store.SubDesign(), "catalogue": subdesign.Catalogue, "presets": subdesign.Presets, "regions": subdesign.Regions, "tags": []string{}, "formats": subdesign.Formats})
}

func (s *Server) subDesignPreset(w http.ResponseWriter, r *http.Request) {
	d, found := subdesign.Preset(r.PathValue("key"))
	if !found {
		fail(w, http.StatusNotFound, errors.New("unknown preset"))
		return
	}
	ok(w, d)
}

func (s *Server) decodeDesign(w http.ResponseWriter, r *http.Request) (*subdesign.Design, string, bool) {
	var in struct {
		Design subdesign.Design `json:"design"`
		Format string           `json:"format"`
	}
	if err := decode(r, &in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return nil, "", false
	}
	if err := in.Design.Validate(); err != nil {
		fail(w, http.StatusBadRequest, err)
		return nil, "", false
	}
	return &in.Design, in.Format, true
}

func (s *Server) putSubDesign(w http.ResponseWriter, r *http.Request) {
	d, _, good := s.decodeDesign(w, r)
	if !good {
		return
	}
	if err := s.d.Store.SetSubDesign(*d); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	ok(w, d)
}

func (s *Server) previewSubDesign(w http.ResponseWriter, r *http.Request) {
	d, format, good := s.decodeDesign(w, r)
	if !good {
		return
	}
	text, err := d.Render(format)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	ok(w, map[string]string{"format": format, "text": text})
}

func (s *Server) applySubDesign(w http.ResponseWriter, r *http.Request) {
	d, _, good := s.decodeDesign(w, r)
	if !good {
		return
	}
	all, err := d.RenderAll()
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if err := s.d.Store.SetSubDesign(*d); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	cur := s.d.Store.SubTemplates()
	for format, text := range all {
		cur[format] = text
	}
	if err := s.d.Store.SetSubTemplates(cur); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	s.writeSubTemplates(w)
}
