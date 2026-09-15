package local

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/zeptop-dev/bosun/internal/authutil"
)

// Second factor and API tokens for the standalone panel.

// TOTP returns the admin's secret and whether it is enforced.
func (s *Store) TOTP() (secret string, enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Admin.TOTPSecret, s.st.Admin.TOTPEnabled
}

// SetTOTP stores a secret (enabled=false keeps it pending until the first
// code confirms the authenticator) or clears it.
func (s *Store) SetTOTP(secret string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Admin.TOTPSecret, s.st.Admin.TOTPEnabled = secret, enabled
	return s.saveLocked()
}

const apiTokenPrefix = "bsn_"

func hashAPIToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// CreateAPIToken mints a token and returns its plaintext once.
func (s *Store) CreateAPIToken(name string) (APIToken, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return APIToken{}, "", errors.New("name is required")
	}
	plain := apiTokenPrefix + authutil.Token(32)
	s.mu.Lock()
	defer s.mu.Unlock()
	var maxID int64
	for _, t := range s.st.APITokens {
		if t.ID > maxID {
			maxID = t.ID
		}
	}
	tok := APIToken{ID: maxID + 1, Name: name, Hash: hashAPIToken(plain), CreatedAt: time.Now()}
	s.st.APITokens = append(s.st.APITokens, tok)
	return tok, plain, s.saveLocked()
}

// ListAPITokens returns the tokens without their hashes.
func (s *Store) ListAPITokens() []APIToken {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]APIToken, 0, len(s.st.APITokens))
	for _, t := range s.st.APITokens {
		t.Hash = ""
		out = append(out, t)
	}
	return out
}

// DeleteAPIToken revokes one token.
func (s *Store) DeleteAPIToken(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, t := range s.st.APITokens {
		if t.ID == id {
			s.st.APITokens = append(s.st.APITokens[:i], s.st.APITokens[i+1:]...)
			return s.saveLocked()
		}
	}
	return ErrNotFound
}

// CheckAPIToken reports whether a bearer token is valid and records its use.
func (s *Store) CheckAPIToken(plain string) bool {
	if !strings.HasPrefix(plain, apiTokenPrefix) {
		return false
	}
	h := hashAPIToken(plain)
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.st.APITokens {
		if s.st.APITokens[i].Hash == h {
			now := time.Now()
			if last := s.st.APITokens[i].LastUsedAt; last == nil || now.Sub(*last) > time.Minute {
				s.st.APITokens[i].LastUsedAt = &now
				_ = s.saveLocked()
			}
			return true
		}
	}
	return false
}
