// Package hostupdate implements an optional, host-owned Docker updater. The
// application receives a narrow Unix socket, never the Docker daemon socket.
package hostupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var tagRE = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func validProduct(p string) bool { return p == "captain" || p == "bosun" }

func newer(a, b string) bool {
	x, y := tagRE.FindStringSubmatch(a), tagRE.FindStringSubmatch(b)
	if x == nil || y == nil {
		return false
	}
	for i := 1; i < 4; i++ {
		n, e1 := strconv.ParseUint(x[i], 10, 32)
		m, e2 := strconv.ParseUint(y[i], 10, 32)
		if e1 != nil || e2 != nil {
			return false
		}
		if n != m {
			return n > m
		}
	}
	return false
}

// Job is persisted by the host so replacing the application does not lose its
// outcome. Error contains a fixed stage description, never Docker stderr/env.
type Job struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	Previous  string    `json:"previous,omitempty"`
	Phase     string    `json:"phase"`
	Error     string    `json:"error,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (j Job) Active() bool { return j.ID != "" && j.Phase != "complete" && j.Phase != "failed" }

type Status struct {
	Available bool `json:"available"`
	Job       *Job `json:"job,omitempty"`
}

func socket(product string) string { return "/run/" + product + "-updater/control.sock" }

func unixClient(path string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func exchange(ctx context.Context, path, method, endpoint string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, method, "http://localhost"+endpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}
	c := unixClient(path)
	defer c.CloseIdleConnections()
	res, err := c.Do(r)
	if err != nil {
		return errors.New("host updater unavailable; enable it on the host")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 && res.StatusCode != 202 {
		return fmt.Errorf("host updater rejected the request (HTTP %d); check updater status on the host", res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 16384)).Decode(out)
}

func Check(ctx context.Context, product string) Status {
	var s Status
	if validProduct(product) {
		_ = exchange(ctx, socket(product), "GET", "/status", nil, &s)
	}
	return s
}

func Request(ctx context.Context, product, target string) (Job, error) {
	var j Job
	if !validProduct(product) || !tagRE.MatchString(target) {
		return j, errors.New("invalid update target")
	}
	err := exchange(ctx, socket(product), "POST", "/upgrade", struct {
		Version string `json:"version"`
	}{target}, &j)
	return j, err
}

// Readiness lives in the running application process. A second invocation of
// `version` alone cannot prove the actual application started successfully.
// Use the application's writable data directory: systemd ProtectSystem=strict
// makes /tmp read-only, and PrivateTmp would hide a temporary socket from CLI.
func Readiness(ctx context.Context, product, version, dataDir string, check func() error) error {
	path := filepath.Join(dataDir, "."+product+"-ready.sock")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0600); err != nil {
		ln.Close()
		return err
	}
	srv := &http.Server{ReadHeaderTimeout: 2 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/ready" {
			http.NotFound(w, r)
			return
		}
		if check != nil && check() != nil {
			http.Error(w, "not ready", 503)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"version": version})
	})}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	go func() { _ = srv.Serve(ln) }()
	return nil
}

func Healthcheck(product, expected, dataDir string) error {
	var out struct {
		Version string `json:"version"`
	}
	err := exchange(context.Background(), filepath.Join(dataDir, "."+product+"-ready.sock"), "GET", "/ready", nil, &out)
	if err != nil {
		return errors.New("application is not ready")
	}
	if expected != "" && out.Version != expected {
		return errors.New("running application version does not match target")
	}
	fmt.Println(product, out.Version)
	return nil
}

// Listening checks the application's own listener without contacting external
// DNS, proxies or ACME. This deliberately does not validate public TLS/DNS.
func Listening(addr string) error {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if h == "" || h == "0.0.0.0" {
		h = "127.0.0.1"
	}
	if h == "::" {
		h = "::1"
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(strings.Trim(h, "[]"), p), time.Second)
	if err == nil {
		c.Close()
	}
	return err
}

// NewerRelease compares strict stable release tags for host installation.
func NewerRelease(target, current string) bool { return newer(target, current) }
