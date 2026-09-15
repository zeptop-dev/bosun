package local

import "github.com/zeptop-dev/bosun/pkg/spec"

// WARP returns the registered account (with secrets) or nil.
func (s *Store) WARP() *spec.WARPAccount {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.WARP == nil {
		return nil
	}
	cp := *s.st.WARP
	return &cp
}

// SetWARP stores or clears the account and re-renders (outbounds may
// depend on it).
func (s *Store) SetWARP(a *spec.WARPAccount) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.WARP = a
	return s.commit()
}
