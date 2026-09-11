package hysteria

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"gitlab.com/zeptop-group/bosun/internal/spec"
)

// statsClient talks to hysteria's trafficStats HTTP API.
type statsClient struct {
	base   string
	secret string
	http   *http.Client
}

func (s *statsClient) do(ctx context.Context, method, path string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, s.base+path, body)
	if err != nil {
		return nil, err
	}
	if s.secret != "" {
		req.Header.Set("Authorization", s.secret)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hysteria: %s %s: %s", method, path, resp.Status)
	}
	return b, nil
}

// traffic returns per-user counters. Hysteria's tx is bytes sent by the
// client (user upload) and rx bytes received by the client (user download).
// With clear the server zeroes its counters after reporting.
func (s *statsClient) traffic(ctx context.Context, clear bool) (map[string]spec.Traffic, error) {
	path := "/traffic"
	if clear {
		path += "?clear=1"
	}
	b, err := s.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var raw map[string]struct {
		Tx uint64 `json:"tx"`
		Rx uint64 `json:"rx"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("hysteria: decode traffic: %w", err)
	}
	out := make(map[string]spec.Traffic, len(raw))
	for id, t := range raw {
		out[id] = spec.Traffic{Up: int64(t.Tx), Down: int64(t.Rx)}
	}
	return out, nil
}

// kick disconnects the given user ids.
func (s *statsClient) kick(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	body, _ := json.Marshal(ids)
	_, err := s.do(ctx, http.MethodPost, "/kick", bytesReader(body))
	return err
}

// online returns the number of connections per user id; used as a readiness probe.
func (s *statsClient) online(ctx context.Context) (map[string]int, error) {
	b, err := s.do(ctx, http.MethodGet, "/online", nil)
	if err != nil {
		return nil, err
	}
	var out map[string]int
	return out, json.Unmarshal(b, &out)
}
