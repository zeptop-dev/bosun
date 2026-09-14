package ui

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// sessionStore keeps panel logins across restarts: tokens are hashed and
// written next to the state file, so an upgrade or restart from the web
// panel does not sign the operator out. Nothing but hashes and expiries
// is stored; losing the file only forces a new login.
type sessionStore struct {
	mu   sync.Mutex
	path string
	ttl  time.Duration
	byID map[string]time.Time
}

func newSessionStore(statePath string, ttl time.Duration) *sessionStore {
	s := &sessionStore{ttl: ttl, byID: map[string]time.Time{}}
	if statePath != "" {
		s.path = strings.TrimSuffix(statePath, ".json") + ".sessions.json"
		if raw, err := os.ReadFile(s.path); err == nil {
			_ = json.Unmarshal(raw, &s.byID)
		}
	}
	s.mu.Lock()
	s.pruneLocked()
	s.mu.Unlock()
	return s
}

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// Add registers a fresh token.
func (s *sessionStore) Add(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	s.byID[hashToken(tok)] = time.Now().Add(s.ttl)
	s.saveLocked()
}

// Valid reports whether the token is known and unexpired.
func (s *sessionStore) Valid(tok string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, found := s.byID[hashToken(tok)]
	if found && time.Now().After(exp) {
		delete(s.byID, hashToken(tok))
		s.saveLocked()
		return false
	}
	return found
}

// Remove forgets one token (logout).
func (s *sessionStore) Remove(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, hashToken(tok))
	s.saveLocked()
}

// Clear drops every session (password change).
func (s *sessionStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID = map[string]time.Time{}
	s.saveLocked()
}

func (s *sessionStore) pruneLocked() {
	now := time.Now()
	for k, exp := range s.byID {
		if now.After(exp) {
			delete(s.byID, k)
		}
	}
}

func (s *sessionStore) saveLocked() {
	if s.path == "" {
		return
	}
	raw, err := json.Marshal(s.byID)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(s.path), 0o750)
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, s.path)
}
