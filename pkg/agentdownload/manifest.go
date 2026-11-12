package agentdownload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Manifest describes the exact cached artifact; SourceVerified distinguishes
// an independent upstream digest from a digest computed only by Captain.
type Manifest struct {
	SHA256         string `json:"sha256"`
	URL            string `json:"url"`
	SourceVerified bool   `json:"source_verified"`
}

func (c *Client) CoreManifest(ctx context.Context, core, version, platform string) (Manifest, error) {
	var m Manifest
	endpoint := c.APIBase() + "/cores/" + url.PathEscape(core) + "/" + url.PathEscape(version) + "/" + platform + "/manifest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return m, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return m, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case 404:
			return m, fmt.Errorf("Captain does not support core %s %s (%s); update Captain first (HTTP 404)", core, version, platform)
		case 401, 403:
			return m, fmt.Errorf("Captain core download authentication rejected (HTTP %d)", resp.StatusCode)
		default:
			return m, fmt.Errorf("Captain artifact manifest: HTTP %d", resp.StatusCode)
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (16<<10)+1))
	if err != nil {
		return m, err
	}
	if len(body) > 16<<10 {
		return m, errors.New("Captain artifact manifest too large")
	}
	if err = json.Unmarshal(body, &m); err != nil {
		return m, errors.New("invalid Captain artifact manifest")
	}
	sum, err := hex.DecodeString(m.SHA256)
	if err != nil || len(sum) != sha256.Size {
		return m, errors.New("invalid Captain artifact digest")
	}
	m.URL, err = c.URL(m.URL)
	if err != nil {
		return m, err
	}
	expected := c.APIBase() + "/cores/" + url.PathEscape(core) + "/" + url.PathEscape(version) + "/" + platform + "/asset"
	if m.URL != expected {
		return m, errors.New("Captain manifest refers to a different artifact")
	}
	return m, nil
}
