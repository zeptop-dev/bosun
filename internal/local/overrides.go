package local

import (
	"encoding/json"
	"errors"
	"github.com/zeptop-dev/bosun/internal/core"
	"strings"
)

// OverrideCores are the cores whose config accepts an override object.
var OverrideCores = []string{"xray", "singbox", "hysteria", "mita"}

// Overrides returns the raw per-core override JSON (always non-nil).
func (s *Store) Overrides() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for _, c := range OverrideCores {
		out[c] = s.st.Overrides[c]
	}
	return out
}

// SetOverrides validates each entry as a JSON object (blank clears) and
// re-renders.
func (s *Store) SetOverrides(in map[string]string) error {
	clean := map[string]string{}
	for _, c := range OverrideCores {
		raw := strings.TrimSpace(in[c])
		if raw == "" {
			continue
		}
		if err := core.CheckOverride(c, json.RawMessage(raw)); err != nil {
			return errors.New(c + ": " + err.Error())
		}
		clean[c] = raw
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Overrides = clean
	return s.commit()
}
