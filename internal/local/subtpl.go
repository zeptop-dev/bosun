package local

import (
	"fmt"
	"maps"
	"slices"
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
	previous := s.st.SubDesign
	s.st.SubDesign = &cp
	if err := s.saveLocked(); err != nil {
		s.st.SubDesign = previous
		return err
	}
	return nil
}

// ApplySubDesign persists the draft and explicitly selected generated templates
// in one state-file replacement. Unselected templates retain their current value.
func (s *Store) ApplySubDesign(d subdesign.Design, generated map[string]string) error {
	for format, body := range generated {
		if !slices.Contains(subdesign.Formats, format) || strings.TrimSpace(body) == "" {
			return fmt.Errorf("invalid generated template for %q", format)
		}
	}
	if len(generated) == 0 {
		return fmt.Errorf("no generated templates selected")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previousDesign, previousTemplates := s.st.SubDesign, s.st.SubTemplates
	templates := maps.Clone(previousTemplates)
	if templates == nil {
		templates = make(map[string]string, len(generated))
	}
	maps.Copy(templates, generated)
	cp := d
	s.st.SubDesign, s.st.SubTemplates = &cp, templates
	if err := s.saveLocked(); err != nil {
		s.st.SubDesign, s.st.SubTemplates = previousDesign, previousTemplates
		return err
	}
	return nil
}
