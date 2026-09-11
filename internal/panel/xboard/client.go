// Package xboard implements the panel.Driver for Xboard's UniProxy v1 API
// (also spoken by V2board and its forks).
package xboard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"gitlab.com/zeptop-group/bosun/internal/spec"
)

// Config is the connection setup for one node.
type Config struct {
	URL      string // panel base URL, e.g. https://panel.example.com
	Token    string // admin setting "server_token"
	NodeID   int
	NodeType string // optional; the panel resolves by ID alone if empty
	Timeout  time.Duration
}

// Client is an Xboard UniProxy driver.
type Client struct {
	cfg  Config
	http *http.Client
	log  *slog.Logger

	mu         sync.Mutex
	configETag string
	userETag   string
	intervals  spec.Intervals
}

const (
	pathConfig = "/api/v1/server/UniProxy/config"
	pathUser   = "/api/v1/server/UniProxy/user"
	pathPush   = "/api/v1/server/UniProxy/push"
	pathStatus = "/api/v1/server/UniProxy/status"
)

// New returns a driver. It performs no network I/O.
func New(cfg Config, log *slog.Logger) (*Client, error) {
	if cfg.URL == "" || cfg.Token == "" || cfg.NodeID == 0 {
		return nil, fmt.Errorf("xboard: url, token and node_id are required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &Client{
		cfg:       cfg,
		http:      &http.Client{Timeout: cfg.Timeout},
		log:       log.With("panel", "xboard"),
		intervals: spec.Intervals{Pull: 60 * time.Second, Push: 60 * time.Second},
	}, nil
}

func (c *Client) Name() string { return "xboard" }

// Intervals returns the cadences last advertised by the panel.
func (c *Client) Intervals() spec.Intervals {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.intervals
}

func (c *Client) endpoint(path string) string {
	q := url.Values{}
	q.Set("token", c.cfg.Token)
	q.Set("node_id", strconv.Itoa(c.cfg.NodeID))
	if c.cfg.NodeType != "" {
		q.Set("node_type", c.cfg.NodeType)
	}
	return c.cfg.URL + path + "?" + q.Encode()
}

// get performs a conditional GET. notModified is true on HTTP 304.
func (c *Client) get(ctx context.Context, path, etag string) (body []byte, newETag string, notModified bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint(path), nil)
	if err != nil {
		return nil, "", false, err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, etag, true, nil
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, "", false, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", false, fmt.Errorf("xboard: GET %s: %s: %s", path, resp.Status, truncate(body))
	}
	return body, resp.Header.Get("ETag"), false, nil
}

func (c *Client) post(ctx context.Context, path string, payload any) error {
	buf, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(path), bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("xboard: POST %s: %s: %s", path, resp.Status, truncate(body))
	}
	return nil
}

// Node fetches the node configuration and maps it to a spec.Node.
func (c *Client) Node(ctx context.Context) (*spec.Node, bool, error) {
	c.mu.Lock()
	etag := c.configETag
	c.mu.Unlock()

	body, newETag, notModified, err := c.get(ctx, pathConfig, etag)
	if err != nil {
		return nil, false, err
	}
	if notModified {
		return nil, false, nil
	}
	var raw nodeConfig
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, false, fmt.Errorf("xboard: decode config: %w", err)
	}
	node, err := mapNode(c.cfg.NodeID, &raw)
	if err != nil {
		return nil, false, err
	}
	c.mu.Lock()
	c.configETag = newETag
	if raw.BaseConfig.PullInterval > 0 {
		c.intervals.Pull = time.Duration(raw.BaseConfig.PullInterval) * time.Second
	}
	if raw.BaseConfig.PushInterval > 0 {
		c.intervals.Push = time.Duration(raw.BaseConfig.PushInterval) * time.Second
	}
	c.mu.Unlock()
	return node, true, nil
}

// Users fetches the list of users allowed on this node.
func (c *Client) Users(ctx context.Context) ([]spec.User, bool, error) {
	c.mu.Lock()
	etag := c.userETag
	c.mu.Unlock()

	body, newETag, notModified, err := c.get(ctx, pathUser, etag)
	if err != nil {
		return nil, false, err
	}
	if notModified {
		return nil, false, nil
	}
	var raw userList
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, false, fmt.Errorf("xboard: decode users: %w", err)
	}
	users := make([]spec.User, 0, len(raw.Users))
	for _, u := range raw.Users {
		users = append(users, spec.User{
			ID:             u.ID,
			Name:           u.UUID,
			UUID:           u.UUID,
			Password:       u.UUID,
			SpeedLimitMbps: u.SpeedLimit,
			DeviceLimit:    u.DeviceLimit,
		})
	}
	c.mu.Lock()
	c.userETag = newETag
	c.mu.Unlock()
	return users, true, nil
}

// PushTraffic reports per-user byte deltas. Xboard expects {"<uid>": [up, down]}.
func (c *Client) PushTraffic(ctx context.Context, traffic []spec.UserTraffic) error {
	if len(traffic) == 0 {
		return nil
	}
	payload := make(map[string][2]int64, len(traffic))
	for _, t := range traffic {
		payload[strconv.FormatInt(t.UserID, 10)] = [2]int64{t.Up, t.Down}
	}
	return c.post(ctx, pathPush, payload)
}

// PushStatus reports host resource usage.
func (c *Client) PushStatus(ctx context.Context, s spec.SystemStatus) error {
	payload := map[string]any{
		"cpu":  s.CPUPercent,
		"mem":  map[string]uint64{"total": s.MemTotal, "used": s.MemUsed},
		"swap": map[string]uint64{"total": s.SwapTotal, "used": s.SwapUsed},
		"disk": map[string]uint64{"total": s.DiskTotal, "used": s.DiskUsed},
	}
	return c.post(ctx, pathStatus, payload)
}

func truncate(b []byte) string {
	const n = 200
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}
