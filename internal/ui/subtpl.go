package ui

import (
	"errors"
	"fmt"
	"net/http"
	"slices"

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
	m.HandleFunc("POST /api/sub-design/inspect", auth(s.inspectSubDesign))
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

type subDesignRequest struct {
	Design  subdesign.Design `json:"design"`
	Format  string           `json:"format"`
	Formats []string         `json:"formats"`
}

func (s *Server) decodeDesign(w http.ResponseWriter, r *http.Request) (*subDesignRequest, bool) {
	var in subDesignRequest
	if err := decode(r, &in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return nil, false
	}
	if err := in.Design.Validate(); err != nil {
		fail(w, http.StatusBadRequest, err)
		return nil, false
	}
	return &in, true
}

func (s *Server) inspectSubDesign(w http.ResponseWriter, r *http.Request) {
	in, good := s.decodeDesign(w, r)
	if !good {
		return
	}
	ok(w, map[string]any{"formats": in.Design.Support()})
}

func (s *Server) putSubDesign(w http.ResponseWriter, r *http.Request) {
	in, good := s.decodeDesign(w, r)
	if !good {
		return
	}
	if err := s.d.Store.SetSubDesign(in.Design); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	ok(w, in.Design)
}

func (s *Server) previewSubDesign(w http.ResponseWriter, r *http.Request) {
	in, good := s.decodeDesign(w, r)
	if !good {
		return
	}
	text, err := in.Design.Render(in.Format)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	ok(w, map[string]string{"format": in.Format, "text": text})
}

func (s *Server) applySubDesign(w http.ResponseWriter, r *http.Request) {
	in, good := s.decodeDesign(w, r)
	if !good {
		return
	}
	formats := in.Formats
	// Omitted/null retains the old all-or-nothing API contract. Only an
	// explicit selection may leave other client templates unchanged.
	if formats == nil {
		formats = subdesign.Formats
	}
	if len(formats) == 0 || len(formats) > len(subdesign.Formats) {
		fail(w, http.StatusBadRequest, errors.New("select at least one supported client format"))
		return
	}
	generated := make(map[string]string, len(formats))
	for _, format := range formats {
		if !slices.Contains(subdesign.Formats, format) {
			fail(w, http.StatusBadRequest, fmt.Errorf("unknown designer format %q", format))
			return
		}
		if _, duplicate := generated[format]; duplicate {
			fail(w, http.StatusBadRequest, fmt.Errorf("duplicate designer format %q", format))
			return
		}
		text, err := in.Design.Render(format)
		if err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		generated[format] = text
	}
	// Render every requested format before saving anything. The draft and
	// selected templates are persisted together, under the store lock.
	if err := s.d.Store.ApplySubDesign(in.Design, generated); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	s.writeSubTemplates(w)
}
