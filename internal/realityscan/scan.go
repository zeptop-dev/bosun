// Package realityscan probes candidate REALITY targets the way xray-core's
// RealiTLScanner and 3x-ui do: a real TLS handshake from this node, checking
// what REALITY needs (TLS 1.3, h2, X25519, a trusted certificate) and what
// operators must avoid (a site on a public CDN, whose traffic gets relayed
// through the node by "preferred IP" scanners once the fallback is found).
package realityscan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultCandidates are big self-hosted sites that passed every check
// (TLS 1.3, h2, X25519, trusted chain, no CDN, no cross-host redirect)
// when probed on 2026-09-14, spread over the US, Japan and Europe so a
// node anywhere finds a nearby one. Deliberately absent: anything Google
// (a node that answers as Google draws attention), Microsoft (its REALITY
// gate fails on current xray, and it is overused), the community classic
// www.lovelive-anime.jp (now on CloudFront, and fingerprinted by overuse),
// and every site fronted by Cloudflare / Akamai / Fastly / CloudFront
// (nvidia, amd, intel, ibm, amazon, aws, tesla, mozilla, python.org ...).
var DefaultCandidates = []string{
	// Apple runs its own edge.
	"www.apple.com",
	"www.icloud.com",
	"gateway.icloud.com",
	"swdist.apple.com",
	// Other large self-hosted companies.
	"www.samsung.com",
	"www.sony.com",
	"www.yahoo.com",
	"www.adobe.com",
	"www.salesforce.com",
	"www.oracle.com",
	"www.westerndigital.com",
	"www.crucial.com",
	"www.msi.com",
	"www.shell.com",
	"www.unilever.com",
	// Japan.
	"www.yahoo.co.jp",
	"www.softbank.jp",
	"www.rakuten.co.jp",
	"www.muji.com",
	"www.kyocera.co.jp",
	// Europe.
	"www.bmw.com",
	"www.mercedes-benz.com",
	"www.debian.org",
	"www.opensuse.org",
	"www.libreoffice.org",
	"www.videolan.org",
	// Universities and foundations with their own hosting.
	"www.wikipedia.org",
	"www.harvard.edu",
	"www.stanford.edu",
}

// Result is one probed target.
type Result struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	IP        string `json:"ip,omitempty"`
	Feasible  bool   `json:"feasible"`
	Reason    string `json:"reason,omitempty"`
	TLS13     bool   `json:"tls13"`
	H2        bool   `json:"h2"`
	X25519    bool   `json:"x25519"`
	CertValid bool   `json:"cert_valid"`
	// CDN names the content network the target sits behind ("cloudflare",
	// "fastly", "akamai", "cloudfront"); empty means none detected.
	CDN         string    `json:"cdn,omitempty"`
	CertSubject string    `json:"cert_subject,omitempty"`
	CertIssuer  string    `json:"cert_issuer,omitempty"`
	NotAfter    time.Time `json:"not_after,omitempty"`
	// ServerNames are the certificate's DNS names: what the inbound may
	// advertise as SNI besides the host itself.
	ServerNames []string `json:"server_names,omitempty"`
	LatencyMs   int      `json:"latency_ms"`
	// HTTPStatus is the answer to HEAD / (0 = not checked); Redirect is
	// its Location when it redirects. A target that bounces to another
	// host makes a poor dest: probes that follow the redirect end up on
	// a different SNI than the inbound advertises.
	HTTPStatus int    `json:"http_status,omitempty"`
	Redirect   string `json:"redirect,omitempty"`
}

// Options tune a scan.
type Options struct {
	Port        int           // default 443
	Timeout     time.Duration // per target, default 6s
	Concurrency int           // default 12
	// Dial overrides the TCP dial (tests, line-bound sources).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// SkipHTTP disables the HTTP header check used for CDN detection.
	SkipHTTP bool
}

// Scan probes every host and returns the results best-first: feasible
// targets by latency, then the rest.
func Scan(ctx context.Context, hosts []string, o Options) []Result {
	if len(hosts) == 0 {
		hosts = DefaultCandidates
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 12
	}
	out := make([]Result, len(hosts))
	sem := make(chan struct{}, o.Concurrency)
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = Probe(ctx, h, o)
		}(i, strings.TrimSpace(h))
	}
	wg.Wait()
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Feasible != out[b].Feasible {
			return out[a].Feasible
		}
		if out[a].LatencyMs != out[b].LatencyMs {
			la, lb := out[a].LatencyMs, out[b].LatencyMs
			if la < 0 {
				return false
			}
			if lb < 0 {
				return true
			}
			return la < lb
		}
		return out[a].Host < out[b].Host
	})
	return out
}

// Probe checks one target. host may carry its own port ("example.com:8443").
func Probe(ctx context.Context, host string, o Options) Result {
	port := o.Port
	if port <= 0 {
		port = 443
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		if n, err := strconv.Atoi(p); err == nil {
			host, port = h, n
		}
	}
	res := Result{Host: host, Port: port, LatencyMs: -1}
	if host == "" {
		res.Reason = "empty host"
		return res
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 6 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dial := o.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()
	raw, err := dial(ctx, "tcp", addr)
	if err != nil {
		res.Reason = "connect failed: " + err.Error()
		return res
	}
	defer raw.Close()
	res.LatencyMs = int(time.Since(start).Milliseconds())
	if ta, ok := raw.RemoteAddr().(*net.TCPAddr); ok {
		res.IP = ta.IP.String()
		if cdn := CDNByIP(ta.IP); cdn != "" {
			res.CDN = cdn
		}
	}

	// Verify the chain ourselves so an untrusted certificate still yields
	// the rest of the picture instead of aborting the handshake.
	var chainErr error
	cfg := &tls.Config{
		ServerName:         host,
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				chainErr = errors.New("no certificate presented")
				return nil
			}
			opts := x509.VerifyOptions{DNSName: host, Intermediates: x509.NewCertPool()}
			for _, c := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(c)
			}
			_, chainErr = cs.PeerCertificates[0].Verify(opts)
			return nil
		},
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		res.Reason = "TLS handshake failed: " + err.Error()
		return res
	}
	cs := conn.ConnectionState()
	res.TLS13 = cs.Version == tls.VersionTLS13
	res.H2 = cs.NegotiatedProtocol == "h2"
	res.X25519 = cs.CurveID == tls.X25519 || cs.CurveID == tls.X25519MLKEM768
	res.CertValid = chainErr == nil && len(cs.PeerCertificates) > 0
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		res.CertSubject = leaf.Subject.CommonName
		res.CertIssuer = leaf.Issuer.CommonName
		if len(leaf.Issuer.Organization) > 0 {
			res.CertIssuer = leaf.Issuer.Organization[0]
		}
		res.NotAfter = leaf.NotAfter
		res.ServerNames = serverNames(leaf, host)
		if res.CDN == "" {
			res.CDN = cdnByIssuer(leaf)
		}
	}
	if !o.SkipHTTP {
		cdn, status, loc := headRequest(ctx, host, addr, dial)
		if res.CDN == "" {
			res.CDN = cdn
		}
		res.HTTPStatus = status
		if status >= 300 && status < 400 && loc != "" && !sameHost(loc, host) {
			res.Redirect = loc
		}
	}

	switch {
	case !res.TLS13:
		res.Reason = "server does not negotiate TLS 1.3"
	case !res.H2:
		res.Reason = "server does not negotiate HTTP/2"
	case !res.X25519:
		res.Reason = "server did not use X25519 key exchange"
	case !res.CertValid:
		res.Reason = "certificate not trusted"
		if chainErr != nil {
			res.Reason += ": " + chainErr.Error()
		}
	case res.CDN != "":
		res.Reason = "hosted on " + res.CDN + " CDN: scanners would relay traffic through this node"
	case res.Redirect != "":
		res.Reason = "redirects to " + res.Redirect + ": use the final host instead"
	default:
		res.Feasible = true
	}
	return res
}

func serverNames(leaf *x509.Certificate, host string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	if hostMatches(leaf, host) {
		add(host)
	}
	for _, n := range leaf.DNSNames {
		if !strings.HasPrefix(n, "*.") {
			add(n)
		}
	}
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

func hostMatches(leaf *x509.Certificate, host string) bool {
	return leaf.VerifyHostname(host) == nil
}

// sameHost reports whether a redirect Location stays on host (scheme or
// path changes only).
func sameHost(loc, host string) bool {
	u, err := url.Parse(loc)
	if err != nil || u.Host == "" {
		return true // relative redirect
	}
	return strings.EqualFold(u.Hostname(), host)
}

// headRequest asks the site for its headers over a fresh HTTP/1.1
// connection: CDN fingerprints, status and redirect target.
func headRequest(ctx context.Context, host, addr string, dial func(context.Context, string, string) (net.Conn, error)) (cdn string, status int, location string) {
	tr := &http.Transport{
		DialContext:       func(ctx context.Context, network, _ string) (net.Conn, error) { return dial(ctx, network, addr) },
		TLSClientConfig:   &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
		TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{}, // force HTTP/1.1
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+host+"/", nil)
	if err != nil {
		return "", 0, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, ""
	}
	resp.Body.Close()
	return cdnByHeaders(resp.Header), resp.StatusCode, resp.Header.Get("Location")
}
