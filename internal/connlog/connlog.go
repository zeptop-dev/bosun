// Package connlog collects, when the panel asks for it (Node.ConnLog),
// one record per connection a core accepted: which user, from which
// client address, to which destination. The cores write these facts to
// their logs (sing-box and xray at info, hysteria at debug); the drivers
// parse the lines and hand events here, and the agent ships them with
// the next report. A bounded ring keeps memory flat when the panel is
// slow: the oldest events are dropped and the drop count is reported.
package connlog

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Collector buffers events between reports.
type Collector struct {
	// Cap is the ring size (0 = 5000).
	Cap int

	enabled atomic.Bool
	mu      sync.Mutex
	buf     []agentproto.ConnEvent
	dropped int
}

// SetEnabled turns collection on or off (events arriving while off are
// discarded without cost).
func (c *Collector) SetEnabled(on bool) { c.enabled.Store(on) }

// Enabled reports the current switch.
func (c *Collector) Enabled() bool { return c.enabled.Load() }

// Add records one event. user is the core's user name ("name|tag" for
// per-inbound accounting), which is split here.
func (c *Collector) Add(user, clientIP, host string, port int, network string) {
	if c == nil || !c.enabled.Load() || host == "" {
		return
	}
	name, tag := spec.SplitInboundUser(user)
	ev := agentproto.ConnEvent{At: time.Now().Unix(), User: name, Inbound: tag, ClientIP: clientIP, Host: host, Port: port, Network: network}
	limit := c.Cap
	if limit <= 0 {
		limit = 5000
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.buf) >= limit {
		c.buf = c.buf[1:]
		c.dropped++
	}
	c.buf = append(c.buf, ev)
}

// Drain returns and clears the buffered events and the drop count.
func (c *Collector) Drain() ([]agentproto.ConnEvent, int) {
	if c == nil {
		return nil, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out, n := c.buf, c.dropped
	c.buf, c.dropped = nil, 0
	return out, n
}

var (
	// xray access log: from 203.0.113.9:51234 accepted tcp:example.com:443 [in -> direct] email: alice|in
	xrayRe = regexp.MustCompile(`from (\S+) accepted (tcp|udp):(.+):(\d+) (?:\[[^\]]*\] )?(?:\S+ )?email: (\S+)`)
	// hysteria (debug): TCP request {"addr": "203.0.113.9:51234", "id": "alice|hy", "reqAddr": "example.com:443"}
	hyRe = regexp.MustCompile(`(TCP|UDP) request\s+\{.*"addr": "([^"]+)".*"id": "([^"]*)".*"reqAddr": "([^"]+)"`)
)

// ParseXray extracts an accepted connection from an xray access line.
func ParseXray(line string) (user, clientIP, host string, port int, network string, ok bool) {
	m := xrayRe.FindStringSubmatch(line)
	if m == nil {
		return
	}
	port, _ = strconv.Atoi(m[4])
	return m[5], HostOnly(m[1]), strings.Trim(m[3], "[]"), port, m[2], true
}

// ParseHysteria extracts a request from a hysteria debug line.
func ParseHysteria(line string) (user, clientIP, host string, port int, network string, ok bool) {
	m := hyRe.FindStringSubmatch(line)
	if m == nil {
		return
	}
	host, port = SplitHostPort(m[4])
	if host == "" {
		return
	}
	return m[3], HostOnly(m[2]), host, port, strings.ToLower(m[1]), true
}

// HostOnly drops the port and brackets from an address.
func HostOnly(addr string) string {
	h, _ := SplitHostPort(addr)
	return h
}

// SplitHostPort splits "host:port" (IPv6 in brackets) into host and port;
// a bare host returns port 0.
func SplitHostPort(addr string) (string, int) {
	addr = strings.TrimSpace(addr)
	i := strings.LastIndex(addr, ":")
	if i < 0 || strings.HasSuffix(addr, "]") {
		return strings.Trim(addr, "[]"), 0
	}
	p, err := strconv.Atoi(addr[i+1:])
	if err != nil {
		return strings.Trim(addr, "[]"), 0
	}
	return strings.Trim(addr[:i], "[]"), p
}
