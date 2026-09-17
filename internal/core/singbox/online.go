package singbox

import (
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/zeptop-dev/bosun/internal/connlog"
)

// sing-box has no API that lists the client addresses behind a user, but at
// log level info it writes two lines per connection that share a context id:
//
//	INFO [1745031466 0ms] inbound/vless[in]: inbound connection from 203.0.113.9:51234
//	INFO [1745031466 0ms] inbound/vless[in]: [alice] inbound connection to example.com:443
//
// (UDP inbounds put both on one line: "[alice] inbound packet connection
// from 203.0.113.9:51234".) onlineTracker joins them and remembers which
// IPs each user was seen from recently, which is what the panel's device
// limit needs.
// hostRe is what a destination may look like: a domain or an IP literal.
// sing-box writes the client's requested destination into the log without
// escaping it, so anything else is a forgery attempt (see README).
var hostRe = regexp.MustCompile(`^[A-Za-z0-9._:\[\]-]{1,253}$`)

type onlineTracker struct {
	mu   sync.Mutex
	src  map[string]srcSeen              // context id -> source address
	seen map[string]map[string]time.Time // user -> ip -> last seen
	now  func() time.Time
	// sink receives (user, client ip, destination) per accepted
	// connection for the connection log; nil = off.
	sink func(user, clientIP, host string, port int, network string)
	// users are the names this node serves ("name|tag" and the bare
	// name); nil accepts every name (tests).
	users map[string]bool
}

// setUsers records who this node serves, so a forged log line naming
// somebody else is ignored.
func (t *onlineTracker) setUsers(names map[string]bool) {
	t.mu.Lock()
	t.users = names
	t.mu.Unlock()
}

type srcSeen struct {
	ip string
	at time.Time
}

const (
	onlineWindow = 3 * time.Minute  // an IP counts as online this long after its last connection
	srcTTL       = 30 * time.Second // how long an unmatched "connection from" line is kept
)

var (
	lineRe = regexp.MustCompile(`\[(\d+) [^\]]*\] (?:inbound/[^:]*): (.*)$`)
	fromRe = regexp.MustCompile(`^(?:\[([^\]]+)\] )?inbound (?:packet )?connection from (\S+)$`)
	userRe = regexp.MustCompile(`^\[([^\]]+)\] inbound (packet )?connection to (\S+)$`)
)

func newOnlineTracker(sink func(user, clientIP, host string, port int, network string)) *onlineTracker {
	return &onlineTracker{src: map[string]srcSeen{}, seen: map[string]map[string]time.Time{}, now: time.Now, sink: sink}
}

// feed consumes one log line.
func (t *onlineTracker) feed(line string) {
	m := lineRe.FindStringSubmatch(line)
	if m == nil {
		return
	}
	id, msg := m[1], m[2]
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if f := fromRe.FindStringSubmatch(msg); f != nil {
		ip := hostOnly(f[2])
		if ip == "" {
			return
		}
		if f[1] != "" { // packet line carries the user already
			if !t.believable(f[1], "") {
				return
			}
			t.mark(f[1], ip, now)
		}
		t.src[id] = srcSeen{ip: ip, at: now}
		if len(t.src) > 4096 {
			t.pruneSrc(now)
		}
		return
	}
	if u := userRe.FindStringSubmatch(msg); u != nil {
		host, _ := connlog.SplitHostPort(u[3])
		if !t.believable(u[1], host) {
			delete(t.src, id)
			return
		}
		if s, ok := t.src[id]; ok {
			t.mark(u[1], s.ip, now)
			delete(t.src, id)
			if t.sink != nil {
				_, port := connlog.SplitHostPort(u[3])
				network := "tcp"
				if u[2] != "" {
					network = "udp"
				}
				t.sink(u[1], s.ip, host, port, network)
			}
		}
	}
}

// believable filters what the log claims: the user must be one this node
// serves and the host must look like a host. Callers hold t.mu.
func (t *onlineTracker) believable(user, host string) bool {
	if t.users != nil && !t.users[user] {
		return false
	}
	return host == "" || hostRe.MatchString(host)
}

func (t *onlineTracker) mark(user, ip string, now time.Time) {
	ips := t.seen[user]
	if ips == nil {
		ips = map[string]time.Time{}
		t.seen[user] = ips
	}
	ips[ip] = now
}

func (t *onlineTracker) pruneSrc(now time.Time) {
	for id, s := range t.src {
		if now.Sub(s.at) > srcTTL {
			delete(t.src, id)
		}
	}
}

// online returns user -> IPs seen within onlineWindow and forgets older ones.
func (t *onlineTracker) online() map[string][]string {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneSrc(now)
	out := map[string][]string{}
	for user, ips := range t.seen {
		for ip, at := range ips {
			if now.Sub(at) > onlineWindow {
				delete(ips, ip)
				continue
			}
			out[user] = append(out[user], ip)
		}
		if len(ips) == 0 {
			delete(t.seen, user)
		}
	}
	return out
}

func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(addr, "[]")
}
