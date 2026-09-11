// Package captain implements the panel.Driver for Captain using
// bosun/pkg/agentproto: one-time pairing, ETag-cached desired state, and a
// single combined report.
package captain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"gitlab.com/boyang-hu/bosun/pkg/agentproto"
	"gitlab.com/boyang-hu/bosun/pkg/spec"
)

// Config is the connection setup.
type Config struct {
	URL       string        // panel base URL
	PairCode  string        // one-time pairing code; used only when no token is stored
	TokenFile string        // where the node token is persisted
	Version   string        // bosun version reported to the panel
	Timeout   time.Duration // HTTP timeout
}

// Client is a Captain driver.
type Client struct {
	cfg  Config
	http *http.Client
	log  *slog.Logger

	mu        sync.Mutex
	token     string
	etag      string
	state     *agentproto.State
	nodeSeen  string // revision last returned by Node()
	usersSeen string // revision last returned by Users()
	fwdSeen   string // revision last returned by Forwards()
}

// New returns a driver. It loads a stored token if present; pairing happens
// on the first state fetch when only a pairing code is configured.
func New(cfg Config, log *slog.Logger) (*Client, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("captain: url is required")
	}
	if cfg.TokenFile == "" {
		return nil, fmt.Errorf("captain: token_file is required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	c := &Client{cfg: cfg, http: &http.Client{Timeout: cfg.Timeout}, log: log.With("panel", "captain")}
	if b, err := os.ReadFile(cfg.TokenFile); err == nil {
		c.token = strings.TrimSpace(string(b))
	} else if cfg.PairCode == "" {
		return nil, fmt.Errorf("captain: no token at %s and no pair_code configured", cfg.TokenFile)
	}
	return c, nil
}

func (c *Client) Name() string { return "captain" }

// Intervals returns the cadences the panel asked for.
func (c *Client) Intervals() spec.Intervals {
	c.mu.Lock()
	defer c.mu.Unlock()
	iv := spec.Intervals{Pull: 60 * time.Second, Push: 60 * time.Second}
	if c.state != nil {
		if c.state.PullSeconds > 0 {
			iv.Pull = time.Duration(c.state.PullSeconds) * time.Second
		}
		if c.state.PushSeconds > 0 {
			iv.Push = time.Duration(c.state.PushSeconds) * time.Second
		}
	}
	return iv
}

func (c *Client) do(ctx context.Context, method, path string, body any, headers map[string]string) (int, []byte, http.Header, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.URL+path, rd)
	if err != nil {
		return 0, nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.mu.Lock()
	tok := c.token
	c.mu.Unlock()
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return resp.StatusCode, out, resp.Header, err
}

// pair redeems the pairing code and persists the token.
func (c *Client) pair(ctx context.Context) error {
	host, _ := os.Hostname()
	code, body, _, err := c.do(ctx, http.MethodPost, "/api/agent/pair", agentproto.PairRequest{
		Code: c.cfg.PairCode, Hostname: host, Version: c.cfg.Version, Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}, nil)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("captain: pairing failed: %s: %s", http.StatusText(code), truncate(body))
	}
	var resp agentproto.PairResponse
	if err := json.Unmarshal(body, &resp); err != nil || resp.Token == "" {
		return fmt.Errorf("captain: bad pair response: %s", truncate(body))
	}
	if err := os.MkdirAll(filepath.Dir(c.cfg.TokenFile), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(c.cfg.TokenFile, []byte(resp.Token+"\n"), 0o600); err != nil {
		return err
	}
	c.mu.Lock()
	c.token = resp.Token
	c.mu.Unlock()
	c.log.Info("paired with captain", "node_id", resp.NodeID, "token_file", c.cfg.TokenFile)
	return nil
}

// fetch refreshes the cached state. It returns whether the revision moved.
func (c *Client) fetch(ctx context.Context) (bool, error) {
	c.mu.Lock()
	tok, etag := c.token, c.etag
	c.mu.Unlock()
	if tok == "" {
		if err := c.pair(ctx); err != nil {
			return false, err
		}
	}
	headers := map[string]string{}
	if etag != "" {
		headers["If-None-Match"] = etag
	}
	code, body, h, err := c.do(ctx, http.MethodGet, "/api/agent/state", nil, headers)
	if err != nil {
		return false, err
	}
	switch code {
	case http.StatusNotModified:
		return false, nil
	case http.StatusOK:
	case http.StatusUnauthorized:
		return false, fmt.Errorf("captain: token rejected; remove %s and pair again", c.cfg.TokenFile)
	default:
		return false, fmt.Errorf("captain: GET state: %s: %s", http.StatusText(code), truncate(body))
	}
	var st agentproto.State
	if err := json.Unmarshal(body, &st); err != nil {
		return false, fmt.Errorf("captain: decode state: %w", err)
	}
	c.mu.Lock()
	c.state, c.etag = &st, h.Get("ETag")
	c.mu.Unlock()
	return true, nil
}

// Node fetches state and returns the node when its revision changed.
func (c *Client) Node(ctx context.Context) (*spec.Node, bool, error) {
	if _, err := c.fetch(ctx); err != nil {
		return nil, false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == nil || c.state.Revision == c.nodeSeen {
		return nil, false, nil
	}
	c.nodeSeen = c.state.Revision
	n := c.state.Node
	n.Forwards = c.state.Forwards
	return &n, true, nil
}

// Users returns the node-level user list when the revision changed. It
// relies on the fetch done by Node in the same pull cycle.
func (c *Client) Users(ctx context.Context) ([]spec.User, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == nil || c.state.Revision == c.usersSeen {
		return nil, false, nil
	}
	c.usersSeen = c.state.Revision
	users := c.state.Users
	if users == nil {
		users = []spec.User{}
	}
	return users, true, nil
}

// Forwards implements panel.ForwardSource.
func (c *Client) Forwards(ctx context.Context) ([]spec.Forward, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == nil || c.state.Revision == c.fwdSeen {
		return nil, false, nil
	}
	c.fwdSeen = c.state.Revision
	fw := c.state.Forwards
	if fw == nil {
		fw = []spec.Forward{}
	}
	return fw, true, nil
}

// Report implements panel.Reporter: one combined POST per push interval.
func (c *Client) Report(ctx context.Context, rep agentproto.Report) (bool, error) {
	c.mu.Lock()
	if c.state != nil {
		rep.Revision = c.state.Revision
	}
	c.mu.Unlock()
	rep.Version = c.cfg.Version
	code, body, _, err := c.do(ctx, http.MethodPost, "/api/agent/report", rep, nil)
	if err != nil {
		return false, err
	}
	if code != http.StatusOK {
		return false, fmt.Errorf("captain: POST report: %s: %s", http.StatusText(code), truncate(body))
	}
	var resp agentproto.ReportResponse
	_ = json.Unmarshal(body, &resp)
	return resp.StateChanged, nil
}

// PushTraffic and PushStatus exist to satisfy panel.Driver; the agent uses
// Report when a driver provides it, so these only run as fallbacks.
func (c *Client) PushTraffic(ctx context.Context, traffic []spec.UserTraffic) error {
	_, err := c.Report(ctx, agentproto.Report{Traffic: traffic})
	return err
}

func (c *Client) PushStatus(ctx context.Context, s spec.SystemStatus) error {
	_, err := c.Report(ctx, agentproto.Report{Host: s})
	return err
}

func truncate(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "..."
	}
	return string(b)
}

var _ = errors.New
