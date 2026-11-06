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
			urls := []string{"https://api.ipify.org", "https://ipv4.icanhazip.com"}
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
	for i, url := range urls {
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
			raw, err := io.ReadAll(io.LimitReader(resp.Body, 129))
			candidate := strings.TrimSpace(string(raw))
			if err != nil || len(raw) > 128 || resp.StatusCode != http.StatusOK || !agentproto.ValidPublicAddress(candidate, v6) {
				return
			}
			values[i] = net.ParseIP(candidate).String()
		}()
	}
	wg.Wait()
	return values
}

func addressConsensus(values []string) string {
	if len(values) < 2 {
		return ""
	}
	for _, value := range values {
		if value == "" || value != values[0] {
			return ""
		}
	}
	return values[0]
}
