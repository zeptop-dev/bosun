// Package captain implements the panel.Driver for Captain using
// bosun/pkg/agentproto: one-time pairing, ETag-cached desired state, and a
// single combined report.
package captain

import (
	"bytes"
	"context"
	"crypto/sha256"
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

	"github.com/zeptop-dev/bosun/internal/dns"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Config is the connection setup.
type Config struct {
	URL           string        // panel base URL
	PairCode      string        // one-time pairing code; used only when no token is stored
	TokenFile     string        // where the node token is persisted
	Version       string        // bosun version reported to the panel
	Timeout       time.Duration // HTTP timeout
	OfflineMaxAge time.Duration // opt-in bounded recovery lease; zero disables
}

// Client is a Captain driver.
type Client struct {
	cfg  Config
	http *http.Client
	log  *slog.Logger

	snapshotMu     sync.Mutex
	verifiedAt     time.Time
	offline        bool
	revoked        bool
	authGeneration uint64
	mu             sync.Mutex
	token          string
	etag           string
	state          *agentproto.State
	nodeSeen       string // revision last returned by Node()
	usersSeen      string // revision last returned by Users()
	fwdSeen        string // revision last returned by Forwards()
	upgradeTo      string // from the last report response
	addresses      *agentproto.PublicAddresses

	// Long-poll watcher: keeps a GET /state?wait= request open so a change
	// on the panel reaches the agent within a second or two.
	changed   chan struct{}
	watchOnce sync.Once
	stop      chan struct{}
}

// Changed implements panel.Notifier; the first call starts the watcher.
func (c *Client) Changed() <-chan struct{} {
	c.watchOnce.Do(func() { go c.watch(); go c.watchAddresses() })
	return c.changed
}

// Close stops the watcher (the agent calls it when it shuts down).
func (c *Client) Close() error {
	c.watchOnce.Do(func() {}) // never start after Close
	select {
	case <-c.stop:
	default:
		close(c.stop)
	}
	return nil
}

// watch long-polls the panel and signals the agent on a new revision. The
// panel answers 304 when nothing changed within the wait window.
func (c *Client) watch() {
	for {
		select {
		case <-c.stop:
			return
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		moved, err := c.fetchWait(ctx, "30s")
		cancel()
		if err != nil {
			c.log.Debug("state watch", "err", err)
			select {
			case <-c.stop:
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		if moved {
			select {
			case c.changed <- struct{}{}:
			default:
			}
		}
	}
}

// UpgradeRequested implements panel.UpgradeRequester.
func (c *Client) UpgradeRequested() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.upgradeTo
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
	if cfg.OfflineMaxAge < 0 || cfg.OfflineMaxAge > 24*time.Hour {
		return nil, fmt.Errorf("captain: offline_max_age must be between 0 and 24h")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	c := &Client{cfg: cfg, http: &http.Client{Timeout: cfg.Timeout}, log: log.With("panel", "captain"), changed: make(chan struct{}, 1), stop: make(chan struct{})}
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
	return c.doClient(ctx, c.http, method, path, body, headers)
}

// waitClient returns an HTTP client whose timeout covers a long-poll.
func (c *Client) waitClient(wait string) *http.Client {
	if wait == "" {
		return c.http
	}
	return &http.Client{Timeout: 60 * time.Second, Transport: c.http.Transport}
}

func (c *Client) doClient(ctx context.Context, hc *http.Client, method, path string, body any, headers map[string]string) (int, []byte, http.Header, error) {
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
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return resp.StatusCode, out, resp.Header, err
}

// Pair redeems the pairing code and persists the token. The agent calls it
// lazily on the first fetch; the local UI calls it up front so a bad code is
// reported before the node switches modes.
func (c *Client) Pair(ctx context.Context) error {
	host, _ := os.Hostname()
	code, body, _, err := c.do(ctx, http.MethodPost, "/api/agent/pair", agentproto.PairRequest{NodeModes: true,
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
func (c *Client) fetch(ctx context.Context) (bool, error) { return c.fetchWait(ctx, "") }

// fetchWait is fetch with an optional long-poll window; the server holds
// the request until the revision changes or the window ends.
func (c *Client) fetchWait(ctx context.Context, wait string) (bool, error) {
	c.mu.Lock()
	tok, etag, generation := c.token, c.etag, c.authGeneration
	c.mu.Unlock()
	if tok == "" {
		if err := c.Pair(ctx); err != nil {
			return false, err
		}
	}
	headers := map[string]string{}
	path := "/api/agent/state"
	if etag != "" {
		headers["If-None-Match"] = etag
		if wait != "" {
			path += "?wait=" + wait
		}
	}
	code, body, h, err := c.doClient(ctx, c.waitClient(wait), http.MethodGet, path, nil, headers)
	if err != nil {
		return false, err
	}
	switch code {
	case http.StatusNotModified:
		if etag == "" {
			return false, fmt.Errorf("captain: unsolicited state 304")
		}
		return false, c.validateLease(generation)
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		c.revokeLease()
		return false, fmt.Errorf("captain: token rejected; remove %s and pair again", c.cfg.TokenFile)
	default:
		return false, &stateFetchError{status: code}
	}
	var st agentproto.State
	if err := json.Unmarshal(body, &st); err != nil {
		return false, fmt.Errorf("captain: decode state: %w", err)
	}
	c.mu.Lock()
	if c.authGeneration != generation {
		c.mu.Unlock()
		return false, errors.New("captain: state response predates authorization rejection")
	}
	if c.state != nil && st.Node.ModeRevision < c.state.Node.ModeRevision {
		c.mu.Unlock()
		return false, nil
	}
	c.state, c.etag = &st, h.Get("ETag")
	c.verifiedAt, c.offline, c.revoked = time.Now(), false, false
	c.mu.Unlock()
	c.saveSnapshot()
	return true, nil
}

// State returns the last state fetched from the panel, or nil.
func (c *Client) State() *agentproto.State {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == nil {
		return nil
	}
	return cloneState(c.state)
}

// Node fetches state and returns the node when its revision changed.
func (c *Client) Node(ctx context.Context) (*spec.Node, bool, error) {
	if _, err := c.fetch(ctx); err != nil {
		if recoveryErr := c.recoverSnapshot(err); recoveryErr != nil {
			return nil, false, recoveryErr
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == nil || c.state.Revision == c.nodeSeen {
		return nil, false, nil
	}
	c.nodeSeen = c.state.Revision
	st := cloneState(c.state)
	n := st.Node
	n.Forwards = st.Forwards
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
	users := cloneState(c.state).Users
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
	fw := cloneState(c.state).Forwards
	if fw == nil {
		fw = []spec.Forward{}
	}
	return fw, true, nil
}

// ConsumedRevisions deliberately uses accessor cursors, not c.state: watch()
// may receive a newer revision while the agent is applying the previous one.
func (c *Client) ConsumedRevisions() (nodeUsers, forwards string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nodeSeen == c.usersSeen {
		nodeUsers = c.nodeSeen
	}
	return nodeUsers, c.fwdSeen
}

// Report implements panel.Reporter: one combined POST per push interval.
func (c *Client) Report(ctx context.Context, rep agentproto.Report) (bool, error) {
	c.mu.Lock()
	rep.PublicAddresses = c.addresses
	if c.state != nil {
		rep.Revision = c.state.Revision
	}
	c.mu.Unlock()
	rep.Version = c.cfg.Version
	rep.Hostname, _ = os.Hostname()
	code, body, _, err := c.do(ctx, http.MethodPost, "/api/agent/report", rep, nil)
	if err != nil {
		return false, err
	}
	if code == http.StatusUnauthorized || code == http.StatusForbidden {
		c.revokeLease()
	}
	if code != http.StatusOK {
		return false, fmt.Errorf("captain: POST report: %s: %s", http.StatusText(code), truncate(body))
	}
	var resp agentproto.ReportResponse
	_ = json.Unmarshal(body, &resp)
	c.mu.Lock()
	c.upgradeTo = resp.UpgradeTo
	c.mu.Unlock()
	return resp.StateChanged, nil
}

// Probe returns the panel's monitoring configuration (nil when off).
// Jobs implements panel.JobSource from the last pulled state.
func (c *Client) Jobs() []agentproto.Job {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == nil || c.offline || c.revoked || (c.cfg.OfflineMaxAge > 0 && !time.Now().Before(c.verifiedAt.Add(c.cfg.OfflineMaxAge))) {
		return nil
	}
	return append([]agentproto.Job(nil), c.state.Jobs...)
}

func (c *Client) Probe() *spec.Probe {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == nil || c.state.Probe == nil {
		return nil
	}
	p := *c.state.Probe
	p.CarrierProbe = p.CarrierProbe.Clone()
	p.Carriers = append([]spec.Carrier(nil), p.Carriers...)
	p.Tasks = append([]spec.PingTask(nil), p.Tasks...)
	return &p
}

// Beat posts one host sample to the probe endpoint.
func (c *Client) Beat(ctx context.Context, b agentproto.Beat) error {
	b.Version = c.cfg.Version
	code, body, _, err := c.do(ctx, http.MethodPost, "/api/agent/beat", b, nil)
	if err != nil {
		return err
	}
	if code == http.StatusUnauthorized || code == http.StatusForbidden {
		c.revokeLease()
	}
	if code != http.StatusOK && code != http.StatusNoContent {
		return fmt.Errorf("captain: POST beat: %s: %s", http.StatusText(code), truncate(body))
	}
	return nil
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

// RemovalConnection is copied only into a root-only local worker plan. It
// must never be logged or returned by the local UI.
func (c *Client) RemovalConnection() (string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg.URL, c.token
}

// TrafficIdentity binds the local journal to the authenticated panel/node.
// Re-pairing starts another journal; old unacknowledged data is not sent to a
// different account space, and no credentials are persisted in the journal.
func (c *Client) TrafficIdentity() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == "" {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(c.cfg.URL+"\x00"+c.token)))
}

// One serial sampler per driver, including monitor-only nodes. Network I/O is
// independent of reports and config pulls, and is cancelled on driver shutdown.
func (c *Client) watchAddresses() {
	c.watchAddressSamples(dns.ObservePublicAddresses)
}

func (c *Client) watchAddressSamples(observe func(context.Context) agentproto.PublicAddresses) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-c.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	started := time.Now()
	timer := time.NewTimer(addressProbeInterval(0))
	defer timer.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		sampleCtx, done := context.WithTimeout(ctx, 12*time.Second)
		sample := observe(sampleCtx)
		done()
		if ctx.Err() != nil {
			return
		}
		c.mu.Lock()
		c.addresses = &sample
		c.mu.Unlock()
		timer.Reset(addressProbeInterval(time.Since(started)))
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}

// Keep several independent startup samples: reports may be a minute apart,
// so a single fast retry could be overwritten before Captain ever sees it.
func addressProbeInterval(elapsed time.Duration) time.Duration {
	if elapsed < 3*time.Minute {
		return 30 * time.Second
	}
	return 5 * time.Minute
}
