// Package agentdownload restricts authenticated artifact requests to one
// Captain endpoint. No node credential can follow an upstream redirect.
package agentdownload

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

// MinVersion is the first bosun release that understands Captain delivery.
const MinVersion = "v0.89.0"
const Prefix = "/api/agent/downloads/"

// Client is an authenticated, same-origin download channel. TokenFile is read
// per request so successful pairing immediately replaces the bootstrap code.
type Client struct {
	BaseURL   string
	TokenFile string
	PairCode  string
	HTTP      *http.Client
	root      *url.URL
	prefix    string
}

func New(base, tokenFile, pairCode string, allowHTTP bool) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Scheme != "https" && !(allowHTTP && u.Scheme == "http")) {
		return nil, errors.New("Captain download endpoint must be an HTTPS URL without credentials, query or fragment")
	}
	if u.Path != "" || u.RawPath != "" {
		return nil, errors.New("Captain download endpoint must be an origin without a path prefix")
	}

	c := &Client{BaseURL: strings.TrimRight(base, "/"), TokenFile: tokenFile, PairCode: pairCode, root: u, prefix: strings.TrimRight(u.Path, "/") + Prefix}
	c.HTTP = &http.Client{Timeout: 10 * time.Minute, Transport: transport{owner: c, next: http.DefaultTransport}, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return errors.New("Captain artifact redirects are not allowed")
	}}
	return c, nil
}

func (c *Client) APIBase() string { return c.BaseURL + strings.TrimSuffix(Prefix, "/") }

// URL resolves a relative manifest URL and rejects another origin, sibling
// endpoint, query credentials, encoded path separator or traversal.
func (c *Client) URL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("invalid Captain artifact URL")
	}
	if !u.IsAbs() {
		u = c.root.ResolveReference(u)
	}
	if u.Scheme != c.root.Scheme || u.Host != c.root.Host || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" || !strings.HasPrefix(u.Path, c.prefix) || path.Clean(u.Path) != u.Path {
		return "", errors.New("artifact URL is outside the Captain download endpoint")
	}
	return u.String(), nil
}

type transport struct {
	owner *Client
	next  http.RoundTripper
}

func (t transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if _, err := t.owner.URL(req.URL.String()); err != nil {
		return nil, err
	}
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return nil, errors.New("Captain downloads require GET or HEAD")
	}
	r := req.Clone(req.Context())
	r.Header = req.Header.Clone()
	r.Header.Del("Authorization")
	r.Header.Del("X-Bosun-Pair-Code")
	token, err := os.ReadFile(t.owner.TokenFile)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read Captain download token: %w", err)
	}
	if tok := strings.TrimSpace(string(token)); tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	} else if t.owner.PairCode != "" {
		r.Header.Set("X-Bosun-Pair-Code", t.owner.PairCode)
	} else {
		return nil, errors.New("Captain download authentication is unavailable")
	}
	return t.next.RoundTrip(r)
}

type contextKey struct{}

func WithClient(ctx context.Context, c *Client) context.Context {
	return context.WithValue(ctx, contextKey{}, c)
}
func FromContext(ctx context.Context) *Client { c, _ := ctx.Value(contextKey{}).(*Client); return c }
