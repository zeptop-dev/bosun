package captain

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

func (c *Client) endpoint() string {
	if u, ok := c.connectionURL.Load().(string); ok && u != "" {
		return u
	}
	return c.cfg.URL
}
func (c *Client) ActiveURL() string { return c.endpoint() }
func (c *Client) migrationResult(ctx context.Context, origin, id, status string, pinned ...http.RoundTripper) error {
	b, _ := json.Marshal(agentproto.ConnectionResult{ID: id, Status: status})
	req, err := http.NewRequestWithContext(ctx, "POST", origin+"/api/agent/connection-result", strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	c.mu.Lock()
	token := c.token
	revoked := c.revoked
	c.mu.Unlock()
	if revoked {
		return errors.New("node authorization revoked")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(agentproto.ConnectionURLHeader, origin)
	transport := c.http.Transport
	if len(pinned) > 0 {
		transport = pinned[0]
	}
	hc := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("migration redirects forbidden") }}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		c.revokeLease()
	}
	if resp.StatusCode != 200 {
		return errors.New("migration confirmation rejected")
	}
	return nil
}
func (c *Client) migrateConnection(m agentproto.ConnectionMigration) {
	if !c.migrationMu.TryLock() {
		return
	}
	defer c.migrationMu.Unlock()
	c.connectionCursor.Store(m.ID)
	c.mu.Lock()
	if c.connectionAttempts == nil {
		c.connectionAttempts = map[string]int64{}
	}
	for id, expires := range c.connectionAttempts {
		if expires < time.Now().Unix() {
			delete(c.connectionAttempts, id)
		}
	}
	_, seen := c.connectionAttempts[m.ID]
	if seen || len(c.connectionAttempts) >= 128 {
		c.mu.Unlock()
		return
	}
	c.connectionAttempts[m.ID] = m.ExpiresAt
	c.mu.Unlock()
	source := c.endpoint()
	if _, ok := agentproto.ConnectionOrigin(m.TargetURL); !ok || len(m.ID) < 20 || len(m.ProofKey) < 32 || m.ExpiresAt <= time.Now().Unix() || m.ExpiresAt > time.Now().Add(6*time.Minute).Unix() {
		return
	}
	normalizedSource, sourceOK := agentproto.ConnectionOrigin(source)
	normalizedExpected, expectedOK := agentproto.ConnectionOrigin(m.SourceURL)
	if source != m.SourceURL && source != m.TargetURL && !(sourceOK && expectedOK && normalizedSource == normalizedExpected) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	go func() {
		select {
		case <-c.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	c.mu.Lock()
	token := c.token
	generation := c.authGeneration
	revoked := c.revoked
	c.mu.Unlock()
	if token == "" || revoked {
		return
	}
	fail := func() { _ = c.migrationResult(ctx, source, m.ID, "failed") }
	if source == m.TargetURL {
		_ = c.migrationResult(ctx, source, m.ID, "completed")
		return
	}
	challengeBytes := make([]byte, 32)
	if _, err := rand.Read(challengeBytes); err != nil {
		fail()
		return
	}
	challenge := hex.EncodeToString(challengeBytes)
	// The first target request is strictly anonymous and cannot follow a redirect.
	req, err := http.NewRequestWithContext(ctx, "GET", m.TargetURL+"/api/agent/connection-proof?id="+url.QueryEscape(m.ID)+"&challenge="+challenge, nil)
	if err != nil {
		fail()
		return
	}
	hc := &http.Client{Transport: c.http.Transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("proof redirects forbidden") }}
	resp, err := hc.Do(req)
	if err != nil {
		fail()
		return
	}
	var proof agentproto.ConnectionProof
	binding, bindingErr := agentproto.ConnectionBinding(resp.TLS, challenge)
	err = json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&proof)
	resp.Body.Close()
	if bindingErr != nil || err != nil || resp.StatusCode != 200 || proof.ID != m.ID || proof.Challenge != challenge || !agentproto.VerifyConnectionProof(m.ProofKey, m.ID, m.TargetURL, challenge, proof.Signature, binding) {
		fail()
		return
	}
	pinned, err := pinConnectionTransport(c.http.Transport, resp.TLS)
	if err != nil {
		fail()
		return
	}
	defer pinned.CloseIdleConnections()
	if err = c.migrationResult(ctx, m.TargetURL, m.ID, "verified", pinned); err != nil {
		fail()
		return
	}
	c.mu.Lock()
	valid := !c.revoked && c.authGeneration == generation && c.endpoint() == source
	c.mu.Unlock()
	if !valid {
		return
	}
	if err = config.SaveConnection(c.cfg.DataDir, c.cfg.OriginalURL, source, m.TargetURL, m.ID, token); err != nil {
		selected, readErr := config.ReadConnection(c.cfg.DataDir, c.cfg.OriginalURL, token)
		if readErr == nil && selected.URL == m.TargetURL {
			if rollbackErr := config.SaveConnection(c.cfg.DataDir, c.cfg.OriginalURL, m.TargetURL, source, m.ID, token); rollbackErr != nil {
				c.connectionURL.Store(m.TargetURL)
				c.connectionGeneration.Add(1)
				return
			}
		}
		fail()
		return
	}
	c.mu.Lock()
	if c.revoked || c.authGeneration != generation {
		c.mu.Unlock()
		_ = config.SaveConnection(c.cfg.DataDir, c.cfg.OriginalURL, m.TargetURL, source, m.ID, token)
		return
	}
	c.connectionURL.Store(m.TargetURL)
	c.connectionGeneration.Add(1)
	c.etag = ""
	c.addresses = nil
	c.addressesURL = ""
	c.mu.Unlock()
	if err = c.migrationResult(ctx, m.TargetURL, m.ID, "completed", pinned); err != nil {
		// Restore durable selection before rolling back the running connection.
		if e := config.SaveConnection(c.cfg.DataDir, c.cfg.OriginalURL, m.TargetURL, source, m.ID, token); e == nil {
			c.connectionURL.Store(source)
			c.connectionGeneration.Add(1)
			fail()
		}
		return
	}
	c.saveSnapshot()
	c.log.Info("Captain connection migrated", "migration", m.ID)
	select {
	case c.changed <- struct{}{}:
	default:
	}
}

func pinConnectionTransport(base http.RoundTripper, proof *tls.ConnectionState) (*http.Transport, error) {
	if proof == nil || len(proof.PeerCertificates) == 0 {
		return nil, errors.New("missing proof certificate")
	}
	if base == nil {
		base = http.DefaultTransport
	}
	transport, ok := base.(*http.Transport)
	if !ok {
		return nil, errors.New("migration requires a pinnable TLS transport")
	}
	out := transport.Clone()
	if out.TLSClientConfig == nil {
		out.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		out.TLSClientConfig = out.TLSClientConfig.Clone()
	}
	pin := sha256.Sum256(proof.PeerCertificates[0].RawSubjectPublicKeyInfo)
	previous := out.TLSClientConfig.VerifyConnection
	out.TLSClientConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if previous != nil {
			if err := previous(state); err != nil {
				return err
			}
		}
		if len(state.PeerCertificates) == 0 || sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo) != pin {
			return errors.New("migration target certificate changed")
		}
		return nil
	}
	return out, nil
}
