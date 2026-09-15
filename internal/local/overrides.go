package local

import (
	"encoding/json"
	"errors"
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
		var obj map[string]any
		if err := json.Unmarshal([]byte(raw), &obj); err != nil {
			return errors.New(c + ": override must be a JSON object: " + err.Error())
		}
		clean[c] = raw
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Overrides = clean
	return s.commit()
}
