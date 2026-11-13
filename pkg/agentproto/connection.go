package agentproto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
)

const ConnectionVersion = "2"
const ConnectionVersionHeader = "X-Bosun-Connection-Version"
const ConnectionURLHeader = "X-Bosun-Connection-URL"
const ConnectionCursorHeader = "X-Bosun-Connection-Cursor"

// ConnectionMigration is temporary control metadata, not proxy configuration.
// ProofKey is an attempt-specific key, never the node token.
type ConnectionMigration struct {
	ID        string `json:"id"`
	SourceURL string `json:"source_url"`
	TargetURL string `json:"target_url"`
	ProofKey  string `json:"proof_key"`
	ExpiresAt int64  `json:"expires_at"`
}
type ConnectionProof struct {
	ID        string `json:"id"`
	Challenge string `json:"challenge"`
	Signature string `json:"signature"`
}
type ConnectionResult struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

func ConnectionSignature(key, id, target, challenge string, binding ...string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte("bosun-connection-v1\x00" + id + "\x00" + target + "\x00" + challenge))
	if len(binding) > 0 {
		h.Write([]byte("\x00" + binding[0]))
	}
	return hex.EncodeToString(h.Sum(nil))
}
func VerifyConnectionProof(key, id, target, challenge, signature string, binding ...string) bool {
	got, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	want, _ := hex.DecodeString(ConnectionSignature(key, id, target, challenge, binding...))
	return hmac.Equal(got, want)
}
func ConnectionOrigin(raw string) (string, bool) {
	if strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\r\n\t") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", false
	}
	return "https://" + strings.ToLower(u.Host), true
}

// The proof is bound to this TLS session; a hostile endpoint cannot relay the
// anonymous challenge to another Captain connection and then receive a token.
func ConnectionBinding(state *tls.ConnectionState, challenge string) (string, error) {
	if state == nil {
		return "", errors.New("direct TLS is required for automatic migration")
	}
	b, err := state.ExportKeyingMaterial("EXPORTER-bosun-connection-v1", []byte(challenge), 32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
