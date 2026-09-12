// Package selfupdate lets a bosun or Captain binary check GitHub Releases
// for a newer version, replace itself atomically and restart under systemd.
// Both projects publish "<binary>-<os>-<arch>" assets plus a SHA256SUMS file
// on every tag, so one implementation serves both.
//
// Inside a container the binary lives in the image: replacing it would be
// undone by the next `docker compose up`, so Apply refuses there and the UI
// tells the operator to pull the new image instead.
package selfupdate

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrInContainer is returned by Apply when the process runs inside Docker.
var ErrInContainer = errors.New("running in a container: pull the new image instead")

// ErrUpToDate is returned by Apply when there is nothing newer.
var ErrUpToDate = errors.New("already on the latest version")

const (
	cacheTTL    = 20 * time.Minute
	maxAsset    = 200 << 20
	apiTimeout  = 30 * time.Second
	downloadTTL = 10 * time.Minute
)

// Client checks and applies updates for one binary.
type Client struct {
	// Repo is "owner/name" on GitHub.
	Repo string
	// Binary is the asset prefix, e.g. "bosun" -> bosun-linux-amd64.
	Binary string
	// Version is the running version as embedded at build time ("v0.5.0";
	// "dev" or anything not starting with v disables updates).
	Version string
	// APIBase overrides https://api.github.com (tests).
	APIBase string
	// Exe overrides the path to replace (tests); default os.Executable().
	Exe string
	// HTTP is the client for API calls and downloads.
	HTTP *http.Client
	// Token is an optional GitHub token (rate limits on busy hosts).
	Token string

	mu      sync.Mutex
	cached  *Info
	fetched time.Time
	busy    bool
}

// Info is the result of a check.
type Info struct {
	Current       string    `json:"current"`
	Latest        string    `json:"latest"`
	HasUpdate     bool      `json:"has_update"`
	ReleaseBuild  bool      `json:"release_build"` // false for "dev" builds: no updates offered
	InContainer   bool      `json:"in_container"`
	Notes         string    `json:"notes,omitempty"`
	PublishedAt   time.Time `json:"published_at,omitempty"`
	URL           string    `json:"url,omitempty"`
	CheckedAt     time.Time `json:"checked_at"`
	Cached        bool      `json:"cached"`
	Warning       string    `json:"warning,omitempty"`
	HasBackup     bool      `json:"has_backup"`
	BackupVersion string    `json:"backup_version,omitempty"`
}

type release struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	HTMLURL     string    `json:"html_url"`
	PublishedAt time.Time `json:"published_at"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	Assets      []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

func (c *Client) api() string {
	if c.APIBase != "" {
		return strings.TrimRight(c.APIBase, "/")
	}
	return "https://api.github.com"
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: downloadTTL}
}

// ReleaseBuild reports whether the running binary has a release version.
func (c *Client) ReleaseBuild() bool {
	_, ok := parseVersion(c.Version)
	return ok
}

// InContainer reports whether the process runs inside Docker or similar.
func InContainer() bool {
	if os.Getenv("IN_CONTAINER") != "" {
		return true
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil && (strings.Contains(string(b), "docker") || strings.Contains(string(b), "containerd")) {
		return true
	}
	return false
}

func (c *Client) exePath() (string, error) {
	if c.Exe != "" {
		return c.Exe, nil
	}
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(p)
}

// Check returns the latest release relative to the running version. Results
// are cached for 20 minutes unless force is set; on network failure the
// cached result is returned with a warning.
func (c *Client) Check(ctx context.Context, force bool) Info {
	c.mu.Lock()
	if !force && c.cached != nil && time.Since(c.fetched) < cacheTTL {
		info := *c.cached
		info.Cached = true
		c.mu.Unlock()
		return c.decorate(info)
	}
	c.mu.Unlock()

	info := Info{Current: c.Version, Latest: c.Version, ReleaseBuild: c.ReleaseBuild(), CheckedAt: time.Now()}
	rel, err := c.latest(ctx)
	if err != nil {
		c.mu.Lock()
		cached := c.cached
		c.mu.Unlock()
		if cached != nil {
			out := *cached
			out.Cached = true
			out.Warning = "using cached result: " + err.Error()
			return c.decorate(out)
		}
		info.Warning = err.Error()
		return c.decorate(info)
	}
	info.Latest = rel.TagName
	info.Notes, info.URL, info.PublishedAt = rel.Body, rel.HTMLURL, rel.PublishedAt
	if cur, ok := parseVersion(c.Version); ok {
		if lat, ok := parseVersion(rel.TagName); ok {
			info.HasUpdate = compare(lat, cur) > 0
		}
	}
	c.mu.Lock()
	c.cached, c.fetched = &info, time.Now()
	c.mu.Unlock()
	return c.decorate(info)
}

// decorate adds the runtime facts that are not worth caching.
func (c *Client) decorate(info Info) Info {
	info.InContainer = InContainer()
	if exe, err := c.exePath(); err == nil {
		if st, err := os.Stat(exe + ".backup"); err == nil && st.Mode().IsRegular() {
			info.HasBackup = true
			if b, err := os.ReadFile(exe + ".backup.version"); err == nil {
				info.BackupVersion = strings.TrimSpace(string(b))
			}
		}
	}
	return info
}

func (c *Client) latest(ctx context.Context) (*release, error) {
	ctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.api()+"/repos/"+c.Repo+"/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", c.Binary+"-selfupdate/"+c.Version)
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: %s", resp.Status)
	}
	var rel release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return nil, err
	}
	if rel.Draft || rel.Prerelease {
		return nil, errors.New("latest release is a draft or pre-release")
	}
	return &rel, nil
}

// Apply downloads the given release (or the latest when version is empty),
// verifies it against SHA256SUMS and swaps the running binary. The caller
// restarts the process afterwards. The previous binary is kept next to the
// new one as <exe>.backup for Rollback.
func (c *Client) Apply(ctx context.Context, version string) (applied string, err error) {
	if InContainer() {
		return "", ErrInContainer
	}
	if !c.ReleaseBuild() {
		return "", errors.New("this is a development build; install a release to use self-update")
	}
	c.mu.Lock()
	if c.busy {
		c.mu.Unlock()
		return "", errors.New("an update is already in progress")
	}
	c.busy = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.busy = false
		c.mu.Unlock()
	}()

	var rel *release
	if version == "" {
		rel, err = c.latest(ctx)
	} else {
		rel, err = c.byTag(ctx, version)
	}
	if err != nil {
		return "", err
	}
	if rel.TagName == c.Version {
		return "", ErrUpToDate
	}
	assetName := fmt.Sprintf("%s-%s-%s", c.Binary, runtime.GOOS, runtime.GOARCH)
	var assetURL, sumsURL string
	for _, a := range rel.Assets {
		switch a.Name {
		case assetName:
			assetURL = a.URL
		case "SHA256SUMS":
			sumsURL = a.URL
		}
	}
	if assetURL == "" {
		return "", fmt.Errorf("release %s has no asset %s", rel.TagName, assetName)
	}
	if sumsURL == "" {
		return "", fmt.Errorf("release %s has no SHA256SUMS", rel.TagName)
	}
	if c.APIBase == "" && !strings.HasPrefix(assetURL, "https://") {
		return "", fmt.Errorf("refusing non-https download %q", assetURL)
	}

	exe, err := c.exePath()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(exe)
	tmp, err := os.MkdirTemp(dir, "."+c.Binary+"-update-*")
	if err != nil {
		return "", fmt.Errorf("binary directory %s is not writable by this user: %w", dir, err)
	}
	defer os.RemoveAll(tmp)

	newBin := filepath.Join(tmp, c.Binary)
	sum, err := c.download(ctx, assetURL, newBin)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	want, err := c.expectedSum(ctx, sumsURL, assetName)
	if err != nil {
		return "", err
	}
	if sum != want {
		return "", fmt.Errorf("checksum mismatch for %s: got %s want %s", assetName, sum, want)
	}
	if err := os.Chmod(newBin, 0o755); err != nil {
		return "", err
	}

	backup := exe + ".backup"
	_ = os.Remove(backup)
	if err := os.Rename(exe, backup); err != nil {
		return "", fmt.Errorf("move current binary aside: %w", err)
	}
	if err := os.Rename(newBin, exe); err != nil {
		if rerr := os.Rename(backup, exe); rerr != nil {
			return "", fmt.Errorf("install failed (%v) and restoring the old binary failed too (%v)", err, rerr)
		}
		return "", fmt.Errorf("install failed, old binary restored: %w", err)
	}
	_ = os.WriteFile(exe+".backup.version", []byte(c.Version+"\n"), 0o644)
	c.mu.Lock()
	c.cached = nil
	c.mu.Unlock()
	return rel.TagName, nil
}

// Rollback puts the previous binary back. The caller restarts afterwards.
func (c *Client) Rollback() (string, error) {
	if InContainer() {
		return "", ErrInContainer
	}
	exe, err := c.exePath()
	if err != nil {
		return "", err
	}
	backup := exe + ".backup"
	if _, err := os.Stat(backup); err != nil {
		return "", errors.New("no previous version to roll back to")
	}
	ver := "previous"
	if b, err := os.ReadFile(exe + ".backup.version"); err == nil {
		ver = strings.TrimSpace(string(b))
	}
	// Keep the current one as the new backup so rollback is reversible.
	if err := os.Rename(exe, exe+".rollback-tmp"); err != nil {
		return "", err
	}
	if err := os.Rename(backup, exe); err != nil {
		_ = os.Rename(exe+".rollback-tmp", exe)
		return "", err
	}
	_ = os.Rename(exe+".rollback-tmp", backup)
	_ = os.WriteFile(exe+".backup.version", []byte(c.Version+"\n"), 0o644)
	return ver, nil
}

// Restart exits the process after delay so a supervisor (systemd
// Restart=always, Docker restart policy) starts the new binary. The caller
// should have flushed its HTTP response first.
func Restart(delay time.Duration) {
	go func() {
		time.Sleep(delay)
		os.Exit(0)
	}()
}

func (c *Client) byTag(ctx context.Context, tag string) (*release, error) {
	ctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.api()+"/repos/"+c.Repo+"/releases/tags/"+tag, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: release %s: %s", tag, resp.Status)
	}
	var rel release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

func (c *Client) download(ctx context.Context, url, dest string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", url, resp.Status)
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxAsset+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if n > maxAsset {
		return "", errors.New("asset larger than the allowed maximum")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (c *Client) expectedSum(ctx context.Context, url, name string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("SHA256SUMS: %s", resp.Status)
	}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 64<<10))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("SHA256SUMS has no entry for %s", name)
}

// Watch re-checks every interval and calls onUpdate when a newer release
// appears (once per version). It returns when ctx ends.
func (c *Client) Watch(ctx context.Context, interval time.Duration, onUpdate func(Info)) {
	seen := ""
	for {
		info := c.Check(ctx, false)
		if info.HasUpdate && info.Latest != seen {
			seen = info.Latest
			onUpdate(info)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// ---- versions ------------------------------------------------------------

// parseVersion reads "v1.2.3" (optionally with a "-pre" suffix, which sorts
// before the release) into comparable parts.
func parseVersion(s string) ([4]int, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "v") {
		return [4]int{}, false
	}
	s = s[1:]
	pre := 0
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		if s[i] == '-' {
			pre = -1
		}
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return [4]int{}, false
	}
	var out [4]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [4]int{}, false
		}
		out[i] = n
	}
	out[3] = pre
	return out, true
}

func compare(a, b [4]int) int {
	for i := 0; i < 4; i++ {
		if a[i] != b[i] {
			if a[i] > b[i] {
				return 1
			}
			return -1
		}
	}
	return 0
}

// Newer reports whether tag a is a newer release than tag b.
func Newer(a, b string) bool {
	va, ok1 := parseVersion(a)
	vb, ok2 := parseVersion(b)
	return ok1 && ok2 && compare(va, vb) > 0
}
