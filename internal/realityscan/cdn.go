package realityscan

import (
	"crypto/x509"
	"net"
	"net/http"
	"strings"
)

// cloudflareRanges is the published list (https://www.cloudflare.com/ips),
// snapshot 2026-09-14. An IP inside it means the target is a Cloudflare edge.
var cloudflareRanges = mustCIDRs(
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
)

func mustCIDRs(list ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(list))
	for _, s := range list {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}

// CDNByIP reports the CDN owning ip ("cloudflare") or "".
func CDNByIP(ip net.IP) string {
	for _, n := range cloudflareRanges {
		if n.Contains(ip) {
			return "cloudflare"
		}
	}
	return ""
}

// cdnByIssuer recognises certificates a CDN issues for its customers.
func cdnByIssuer(leaf *x509.Certificate) string {
	iss := strings.ToLower(strings.Join(append(leaf.Issuer.Organization, leaf.Issuer.CommonName), " "))
	switch {
	case strings.Contains(iss, "cloudflare"):
		return "cloudflare"
	case strings.Contains(iss, "fastly"):
		return "fastly"
	case strings.Contains(iss, "akamai"):
		return "akamai"
	}
	return ""
}

// cdnByHeaders reads the response headers a CDN edge stamps on every reply.
func cdnByHeaders(h http.Header) string {
	server := strings.ToLower(h.Get("Server"))
	switch {
	case h.Get("CF-Ray") != "" || server == "cloudflare":
		return "cloudflare"
	case h.Get("X-Amz-Cf-Id") != "" || strings.Contains(server, "cloudfront"):
		return "cloudfront"
	case strings.Contains(strings.ToLower(h.Get("Via")), "varnish") && strings.HasPrefix(strings.ToLower(h.Get("X-Served-By")), "cache-"):
		return "fastly"
	case strings.Contains(server, "akamai"):
		return "akamai"
	}
	return ""
}
