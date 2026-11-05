package dns

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

const traceBodyLimit = 8192

// traceOrigin removes every non-origin component. Userinfo is rejected rather
// than forwarded, even though the panel's own URL validation should reject it.
func traceOrigin(value string) *url.URL {
	if len(value) > 2048 {
		return nil
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.Hostname() == "" || u.User != nil || strings.HasSuffix(u.Host, ":") {
		return nil
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil
		}
	}
	return &url.URL{Scheme: "https", Host: u.Host}
}

func observeTrace(ctx context.Context, client *http.Client, captainURL string, v6 bool) *agentproto.PublicAddressFallback {
	origin := traceOrigin(captainURL)
	if origin == nil {
		return nil
	}
	out := &agentproto.PublicAddressFallback{Source: agentproto.PublicAddressFallbackSource, Origin: origin.String()}
	defer func() { out.SampledAt = time.Now().Unix() }()
	endpoint := *origin
	endpoint.Path = "/cdn-cgi/trace"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		out.Error = "invalid_origin"
		return out
	}
	req.Header.Set("Accept", "text/plain")
	resp, err := client.Do(req)
	if err != nil {
		out.Error = traceRequestError(err)
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		out.Error = "http_status"
		return out
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "text/plain" {
		out.Error = "invalid_response"
		return out
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, traceBodyLimit+1))
	if err != nil {
		out.Error = traceRequestError(err)
		return out
	}
	if len(raw) > traceBodyLimit {
		out.Error = "invalid_response"
		return out
	}
	out.Address = parseTrace(raw, origin, v6)
	if out.Address == "" {
		out.Error = "invalid_response"
	}
	return out
}

// Schema checks prevent a generic HTML/JSON/error response or an isolated ip=
// line from becoming an observation. This is still a single-source report;
// neither the schema nor a Cloudflare header proves independent consensus.
func parseTrace(raw []byte, origin *url.URL, v6 bool) string {
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		key, value, ok := strings.Cut(strings.TrimSuffix(line, "\r"), "=")
		_, duplicate := fields[key]
		if !ok || key == "" || duplicate {
			return ""
		}
		fields[key] = value
	}
	if !strings.EqualFold(fields["h"], origin.Host) && !strings.EqualFold(fields["h"], origin.Hostname()) {
		return ""
	}
	ts, err := strconv.ParseFloat(fields["ts"], 64)
	if err != nil || ts <= 0 || math.IsNaN(ts) || math.IsInf(ts, 0) {
		return ""
	}
	colo := fields["colo"]
	if len(colo) != 3 || strings.IndexFunc(colo, func(r rune) bool { return r < 'A' || r > 'Z' }) >= 0 || !strings.HasPrefix(fields["tls"], "TLSv") {
		return ""
	}
	value := fields["ip"]
	if !agentproto.ValidPublicAddress(value, v6) {
		return ""
	}
	return net.ParseIP(value).String()
}

func traceRequestError(err error) string {
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return "tls"
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "network"
}
