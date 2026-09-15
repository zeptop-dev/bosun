package local

import (
	"strings"

	"github.com/zeptop-dev/bosun/pkg/subdesign"
	"github.com/zeptop-dev/bosun/pkg/subscription"
)

// SubTemplates returns the operator's subscription templates by format
// ("" = the built-in default).
func (s *Store) SubTemplates() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for _, name := range subscription.TemplateNames() {
		out[name] = s.st.SubTemplates[name]
	}
	return out
}

// SetSubTemplates stores the templates; unknown formats are dropped and an
// empty body means the default.
func (s *Store) SetSubTemplates(in map[string]string) error {
	clean := map[string]string{}
	for _, name := range subscription.TemplateNames() {
		if body := in[name]; strings.TrimSpace(body) != "" {
			clean[name] = body
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.SubTemplates = clean
	return s.saveLocked()
}

// SubTemplate is one format's template ("" = default).
func (s *Store) SubTemplate(format string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.SubTemplates[format]
}

// SubDesign returns the visual designer's state (empty when unused).
func (s *Store) SubDesign() subdesign.Design {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.SubDesign == nil {
		return subdesign.Design{Groups: []subdesign.Group{}, Rules: []subdesign.Rule{}}
	}
	return *s.st.SubDesign
}

// SetSubDesign stores the designer's state.
func (s *Store) SetSubDesign(d subdesign.Design) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := d
	s.st.SubDesign = &cp
	return s.saveLocked()
}
