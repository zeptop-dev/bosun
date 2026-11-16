package captain

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"io"
	"net/http"
	"net/url"
	"time"
)

func (c *Client) probeConnection(p agentproto.ConnectionProbe) {
	c.connectionProbeCursor.Store(p.ID)
	c.connectionProbeNext.Store(&p)
	c.processProbe()
}
func (c *Client) processProbe() {
	if !c.connectionProbeMu.TryLock() {
		return
	}
	defer func() {
		c.connectionProbeMu.Unlock()
		if c.connectionProbeNext.Load() != nil {
			go c.processProbe()
		}
	}()
	next := c.connectionProbeNext.Swap(nil)
	if next == nil {
		return
	}
	p := *next
	if c.connectionProbeHandled == p.ID {
		return
	}
	c.connectionProbeHandled = p.ID
	if _, ok := agentproto.ConnectionOrigin(p.TargetURL); !ok || len(p.ID) < 20 || len(p.ProofKey) < 32 || p.ExpiresAt <= time.Now().Unix() || p.ExpiresAt > time.Now().Add(6*time.Minute).Unix() {
		return
	}
	origin := c.endpoint()
	generation := c.connectionGeneration.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go func() {
		select {
		case <-c.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	result := agentproto.ConnectionProbeResult{ID: p.ID, Status: "failed", Error: "proof_request"}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err == nil {
		challenge := hex.EncodeToString(b)
		req, _ := http.NewRequestWithContext(ctx, "GET", p.TargetURL+"/api/agent/connection-proof?id="+url.QueryEscape(p.ID)+"&challenge="+challenge, nil)
		transport, err := verifiedProxyTransport(c.http.Transport)
		if err == nil {
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("probe redirects forbidden") }}
			resp, err := client.Do(req)
			if err == nil {
				var proof agentproto.ConnectionProof
				decode := json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&proof)
				resp.Body.Close()
				result.Error = "proof_verification"
				if resp.StatusCode == 200 && decode == nil && proof.ID == p.ID && proof.Challenge == challenge {
					binding, e := agentproto.ConnectionBinding(resp.TLS, challenge)
					if e == nil && agentproto.VerifyConnectionProof(p.ProofKey, p.ID, p.TargetURL, challenge, proof.Signature, binding) {
						result.Status = "direct"
						result.Error = ""
					} else if agentproto.VerifyConnectionProof(p.ProofKey, p.ID, p.TargetURL, challenge, proof.ProxySignature, agentproto.ProbeConnectionBinding(p.ExpiresAt)) {
						result.Status = "trusted-proxy"
						result.Error = ""
					}
				}
			}
		}
	}
	// Never send node credentials to the inspected target or after a source move.
	if origin != c.endpoint() || generation != c.connectionGeneration.Load() {
		return
	}
	c.connectionProbePending = &result
	c.connectionProbeOrigin = origin
	c.connectionProbeGeneration = generation
	c.sendProbeReceipt(ctx)
}

func (c *Client) finishProbeReceipt() {
	select {
	case <-c.stop:
		return
	default:
	}
	if !c.connectionProbeMu.TryLock() {
		return
	}
	defer func() {
		c.connectionProbeMu.Unlock()
		if c.connectionProbeNext.Load() != nil {
			go c.processProbe()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	go func() {
		select {
		case <-c.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	c.sendProbeReceipt(ctx)
}
func (c *Client) sendProbeReceipt(ctx context.Context) {
	if c.connectionProbePending == nil {
		return
	}
	if c.connectionProbeOrigin != c.endpoint() || c.connectionProbeGeneration != c.connectionGeneration.Load() {
		c.connectionProbePending = nil
		return
	}
	status, _, _, err := c.doClient(ctx, c.http, "POST", "/api/agent/connection-probe-result", *c.connectionProbePending, nil)
	if err == nil && (status == 200 || status == 400 || status == 401 || status == 403 || status == 404 || status == 409) {
		c.connectionProbePending = nil
	}
}
