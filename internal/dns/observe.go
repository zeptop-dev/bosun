package dns

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

// ObservePublicAddresses requires agreement from independent HTTPS responders.
// Force each address family and bypass environment proxies: a configured HTTP
// proxy is not this machine's public egress. Failed probes never erase an IP.
func ObservePublicAddresses(ctx context.Context) agentproto.PublicAddresses {
	return ObservePublicAddressesWithFallback(ctx, "")
}

// ObservePublicAddressesWithFallback keeps consensus and advisory observations
// separate. The only fallback is the configured Captain HTTPS origin's trace
// endpoint; it never uses the authenticated panel client or changes its URL.
func ObservePublicAddressesWithFallback(ctx context.Context, captainURL string) agentproto.PublicAddresses {
	out := agentproto.PublicAddresses{}
	var wg sync.WaitGroup
	for _, v6 := range []bool{false, true} {
		wg.Add(1)
		go func(v6 bool) {
			defer wg.Done()
			urls := []string{"https://api.ipify.org", "https://ipv4.icanhazip.com", ipipSource, mainlandTextSource}
			if v6 {
				urls = []string{"https://api6.ipify.org", "https://ipv6.icanhazip.com"}
			}
			client := publicAddressClient(v6)
			defer client.CloseIdleConnections()
			value, fallback := observeFamilyWithFallback(ctx, client, urls, captainURL, v6)
			if v6 {
				out.IPv6, out.FallbackIPv6 = value, fallback
			} else {
				out.IPv4, out.FallbackIPv4 = value, fallback
			}
		}(v6)
	}
	wg.Wait()
	out.SampledAt = time.Now().Unix()
	return out
}

// Deliberately do not clone DefaultTransport: it may have ProxyFromEnvironment
// or caller-installed credentials. TLS uses system roots and normal hostname
// verification. A family is mandatory even when DNS returns both address types.
func publicAddressClient(v6 bool) *http.Client {
	network := "tcp4"
	if v6 {
		network = "tcp6"
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, network, addr)
	}}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func observeFamilyWithFallback(ctx context.Context, client *http.Client, urls []string, origin string, v6 bool) (string, *agentproto.PublicAddressFallback) {
	values := observeFamilySources(ctx, client, urls, v6)
	value := addressConsensus(values)
	if value != "" || ctx.Err() != nil {
		return value, nil
	}
	fallback := observeTrace(ctx, client, origin, v6)
	if fallback == nil || fallback.Address == "" || fallback.Error != "" || ctx.Err() != nil || len(values) < 2 {
		return "", fallback
	}
	// Failed responders are unavailable evidence, not agreement. Keep every
	// successful response so one failed source cannot conceal a disagreement
	// between another source and the fallback, or between the regular sources.
	fallback.CheckStatus = agentproto.PublicAddressFallbackCheckNoConflict
	for _, observed := range values {
		if observed != "" && observed != fallback.Address {
			fallback.CheckStatus = agentproto.PublicAddressFallbackCheckConflict
			break
		}
	}
	return "", fallback
}

func observeFamily(ctx context.Context, client *http.Client, urls []string, v6 bool) string {
	return addressConsensus(observeFamilySources(ctx, client, urls, v6))
}

func observeFamilySources(ctx context.Context, client *http.Client, urls []string, v6 bool) []string {
	// Parallel requests preserve two-source agreement while reserving time for
	// the bounded fallback inside the driver's 12-second sampling deadline.
	values := make([]string, len(urls))
	var wg sync.WaitGroup
	seen := map[string]bool{}
	for i, url := range urls {
		if seen[url] {
			continue
		}
		seen[url] = true
		if url == mainlandTextSource && !mainlandProbeGate.allow(time.Now()) {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			limit := 128
			if url == ipipSource {
				limit = 512
			}
			raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit+1)))
			if err != nil || len(raw) > limit || resp.StatusCode != http.StatusOK {
				return
			}
			values[i] = parseAddressResponse(url, raw, v6)
		}()
	}
	wg.Wait()
	return values
}

// At least two successful independent sources must agree. Missing responses
// do not veto agreement, but a single conflicting valid response always does.
func addressConsensus(values []string) string {
	candidate, count := "", 0
	for _, value := range values {
		if value == "" {
			continue
		}
		if candidate != "" && candidate != value {
			return ""
		}
		candidate = value
		count++
	}
	if count < 2 {
		return ""
	}
	return candidate
}

const ipipSource = "https://myip.ipip.net"
const mainlandTextSource = "https://ip.3322.net"

// Be conservative with the free mainland endpoint during the startup burst.
// Skipped probes contribute no vote; never reuse a cached success as fresh.
var mainlandProbeGate sourceGate

type sourceGate struct {
	mu   sync.Mutex
	last time.Time
}

func (g *sourceGate) allow(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.last.IsZero() && now.Sub(g.last) < 65*time.Second {
		return false
	}
	g.last = now
	return true
}

func parseAddressResponse(source string, raw []byte, v6 bool) string {
	candidate := strings.TrimSpace(string(raw))
	if source == ipipSource {
		if v6 || len(raw) > 512 || strings.ContainsAny(candidate, "\r\n") {
			return ""
		}
		// Parse only this endpoint's explicit IP field, never arbitrary IP-like
		// substrings from HTML, error messages or the location description.
		rest, ok := strings.CutPrefix(candidate, "当前 IP：")
		if !ok {
			return ""
		}
		address, location, ok := strings.Cut(rest, "  来自于：")
		if !ok || strings.TrimSpace(location) == "" {
			return ""
		}
		candidate = strings.TrimSpace(address)
	} else if len(raw) > 128 {
		return ""
	}
	if !agentproto.ValidPublicAddress(candidate, v6) {
		return ""
	}
	return net.ParseIP(candidate).String()
}
