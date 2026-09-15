// Package warp registers a Cloudflare WARP account the way wgcf does and
// hands back WireGuard credentials for an outbound: traffic sent through it
// leaves from Cloudflare's address space, which is the usual fix when a
// VPS's own IP is refused by a site. No system interface is touched; the
// tunnel lives inside xray or sing-box.
package warp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

const (
	apiBase       = "https://api.cloudflareclient.com/v0a2158"
	clientVersion = "a-6.30-3596"
	userAgent     = "okhttp/3.12.1"
	// DefaultEndpoint is Cloudflare's WARP relay.
	DefaultEndpoint = "engage.cloudflareclient.com:2408"
)

// Client talks to the registration API; BaseURL and HTTP are overridable
// for tests.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func (c *Client) base() string {
	if c.BaseURL != "" {
		return strings.TrimSuffix(c.BaseURL, "/")
	}
	return apiBase
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// Keypair returns a fresh Curve25519 pair, base64 like wg(8).
func Keypair() (priv, pub string, err error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", "", err
	}
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	p, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k[:]), base64.StdEncoding.EncodeToString(p), nil
}

type regResponse struct {
	ID      string `json:"id"`
	Token   string `json:"token"`
	Account struct {
		License string `json:"license"`
	} `json:"account"`
	Config struct {
		ClientID string `json:"client_id"`
		Peers    []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				Host string `json:"host"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

// Register creates a WARP account for a new key pair. A WARP+ license, if
// given, is attached in a second call (a free account is still returned
// when that fails, with the error reported).
func (c *Client) Register(ctx context.Context, license string) (*spec.WARPAccount, error) {
	priv, pub, err := Keypair()
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"key": pub, "install_id": "", "fcm_token": "", "tos": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"model": "PC", "serial_number": "", "locale": "en_US",
	}
	var rr regResponse
	if err := c.call(ctx, http.MethodPost, "/reg", "", body, &rr); err != nil {
		return nil, fmt.Errorf("warp: register: %w", err)
	}
	acct := accountFrom(rr, priv)
	if license = strings.TrimSpace(license); license != "" {
		if err := c.applyLicense(ctx, acct, license); err != nil {
			return acct, fmt.Errorf("warp: registered, but the license was not accepted: %w", err)
		}
	}
	return acct, nil
}

// SetLicense attaches a WARP+ license to an existing account and refreshes
// the credentials (Cloudflare re-issues the config with the new plan).
func (c *Client) SetLicense(ctx context.Context, acct *spec.WARPAccount, license string) error {
	if acct == nil || acct.ID == "" {
		return errors.New("warp: not registered")
	}
	return c.applyLicense(ctx, acct, strings.TrimSpace(license))
}

func (c *Client) applyLicense(ctx context.Context, acct *spec.WARPAccount, license string) error {
	var out struct {
		License string `json:"license"`
	}
	if err := c.call(ctx, http.MethodPut, "/reg/"+acct.ID+"/account", acct.Token, map[string]string{"license": license}, &out); err != nil {
		return err
	}
	acct.License = license
	var rr regResponse
	if err := c.call(ctx, http.MethodGet, "/reg/"+acct.ID, acct.Token, nil, &rr); err == nil && len(rr.Config.Peers) > 0 {
		fresh := accountFrom(rr, acct.PrivateKey)
		acct.PeerPublicKey, acct.Endpoint, acct.Addresses, acct.Reserved = fresh.PeerPublicKey, fresh.Endpoint, fresh.Addresses, fresh.Reserved
	}
	return nil
}

func accountFrom(rr regResponse, priv string) *spec.WARPAccount {
	acct := &spec.WARPAccount{ID: rr.ID, Token: rr.Token, License: rr.Account.License, PrivateKey: priv, Endpoint: DefaultEndpoint, RegisteredAt: time.Now()}
	if len(rr.Config.Peers) > 0 {
		acct.PeerPublicKey = rr.Config.Peers[0].PublicKey
		if h := rr.Config.Peers[0].Endpoint.Host; h != "" {
			acct.Endpoint = h
		}
	}
	if v4 := rr.Config.Interface.Addresses.V4; v4 != "" {
		acct.Addresses = append(acct.Addresses, withPrefix(v4, "/32"))
	}
	if v6 := rr.Config.Interface.Addresses.V6; v6 != "" {
		acct.Addresses = append(acct.Addresses, withPrefix(v6, "/128"))
	}
	if b, err := base64.StdEncoding.DecodeString(rr.Config.ClientID); err == nil && len(b) == 3 {
		acct.Reserved = []int{int(b[0]), int(b[1]), int(b[2])}
	}
	return acct
}

func withPrefix(ip, p string) string {
	if strings.Contains(ip, "/") {
		return ip
	}
	return ip + p
}

func (c *Client) call(ctx context.Context, method, path, token string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base()+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("CF-Client-Version", clientVersion)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		msg := strings.TrimSpace(string(data))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, msg)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// Resolve fills a from_node WARP outbound with the account's credentials.
func Resolve(o spec.Outbound, acct *spec.WARPAccount) (spec.Outbound, error) {
	if o.WARP == nil || !o.WARP.FromNode {
		return o, nil
	}
	if acct == nil || acct.PrivateKey == "" {
		return o, fmt.Errorf("outbound %q: WARP is not registered on this node", o.Tag)
	}
	w := *o.WARP
	w.PrivateKey, w.PeerPublicKey, w.Endpoint, w.Addresses, w.Reserved, w.License = acct.PrivateKey, acct.PeerPublicKey, acct.Endpoint, acct.Addresses, acct.Reserved, acct.License
	o.WARP = &w
	return o, nil
}

// Public strips secrets for reports and the UI.
func Public(acct *spec.WARPAccount) *spec.WARPAccount {
	if acct == nil {
		return nil
	}
	cp := *acct
	cp.PrivateKey, cp.Token = "", ""
	return &cp
}
