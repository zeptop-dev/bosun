// Package audit matches accepted connections against the panel's audit
// rules and records the hits for the next report. Blocking itself is the
// cores' job (the agent turns "block" rules into route rules); this
// package only answers "who tried to reach what": the same log feed that
// serves the connection log (sing-box and xray at info, hysteria at debug)
// is checked here whether or not the connection log is switched on.
package audit

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// rule is one compiled audit rule. A rule holds when every kind of match
// it names is satisfied by at least one entry of that kind (the same
// semantics as the cores' route rules).
type rule struct {
	id     int64
	name   string
	action string
	suffix []string
	full   []string
	kw     []string
	re     []*regexp.Regexp
	nets   []*net.IPNet
	ports  map[int]bool
	inb    map[string]bool
	// unmatchable: names a kind this matcher cannot evaluate (geosite,
	// geoip, protocol); the core may still block, but nothing is logged.
	unmatchable bool
}

// Collector holds the compiled rules and the buffered hits.
type Collector struct {
	// Cap is the ring size (0 = 2000).
	Cap int

	mu      sync.Mutex
	rules   []rule
	buf     []agentproto.AuditHit
	dropped int
	recent  map[string]time.Time // "user/rule" -> last hit, for the 60 s dedupe
	now     func() time.Time
}

// SetRules replaces the rule set (called on every apply).
func (c *Collector) SetRules(rules []spec.AuditRule) {
	compiled := make([]rule, 0, len(rules))
	for _, r := range rules {
		cr := rule{id: r.ID, name: r.Name, action: r.Action, ports: map[int]bool{}, inb: map[string]bool{}}
		for _, mt := range r.Match {
			key, val, ok := strings.Cut(strings.TrimSpace(mt), ":")
			if !ok {
				key, val = "domain", key
			}
			val = strings.TrimSpace(val)
			switch key {
			case "domain":
				cr.suffix = append(cr.suffix, strings.ToLower(val))
			case "full":
				cr.full = append(cr.full, strings.ToLower(val))
			case "keyword":
				cr.kw = append(cr.kw, strings.ToLower(val))
			case "regexp":
				if re, err := regexp.Compile(val); err == nil {
					cr.re = append(cr.re, re)
				}
			case "ip", "ip_cidr":
				if _, n, err := net.ParseCIDR(val); err == nil {
					cr.nets = append(cr.nets, n)
				} else if ip := net.ParseIP(val); ip != nil {
					bits := 32
					if ip.To4() == nil {
						bits = 128
					}
					cr.nets = append(cr.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
				}
			case "port":
				for _, p := range strings.Split(val, ",") {
					if lo, hi, ok := strings.Cut(p, "-"); ok {
						a, _ := strconv.Atoi(strings.TrimSpace(lo))
						b, _ := strconv.Atoi(strings.TrimSpace(hi))
						for i := a; i <= b && i-a < 65536; i++ {
							cr.ports[i] = true
						}
					} else if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
						cr.ports[n] = true
					}
				}
			case "inbound":
				cr.inb[val] = true
			default:
				cr.unmatchable = true
			}
		}
		compiled = append(compiled, cr)
	}
	c.mu.Lock()
	c.rules = compiled
	c.mu.Unlock()
}

// Check evaluates one accepted connection (user is the core's "name|tag"
// name) and records the first matching rule.
func (c *Collector) Check(user, clientIP, host string, port int, network string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	rules := c.rules
	c.mu.Unlock()
	if len(rules) == 0 || host == "" {
		return
	}
	name, tag := spec.SplitInboundUser(user)
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	ip := net.ParseIP(strings.Trim(host, "[]"))
	for i := range rules {
		if rules[i].matches(h, ip, port, tag) {
			c.record(rules[i], name, tag, clientIP, host, port)
			return
		}
	}
}

func (r *rule) matches(host string, ip net.IP, port int, inbound string) bool {
	if r.unmatchable {
		return false
	}
	any := false
	if len(r.suffix)+len(r.full)+len(r.kw)+len(r.re) > 0 {
		any = true
		if ip != nil || !domainMatch(r, host) {
			return false
		}
	}
	if len(r.nets) > 0 {
		any = true
		if ip == nil {
			return false
		}
		hit := false
		for _, n := range r.nets {
			if n.Contains(ip) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if len(r.ports) > 0 {
		any = true
		if !r.ports[port] {
			return false
		}
	}
	if len(r.inb) > 0 {
		any = true
		if !r.inb[inbound] {
			return false
		}
	}
	return any
}

func domainMatch(r *rule, host string) bool {
	for _, s := range r.suffix {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	for _, f := range r.full {
		if host == f {
			return true
		}
	}
	for _, k := range r.kw {
		if strings.Contains(host, k) {
			return true
		}
	}
	for _, re := range r.re {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

func (c *Collector) record(r rule, user, inbound, clientIP, host string, port int) {
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	t := now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.recent == nil {
		c.recent = map[string]time.Time{}
	}
	key := user + "/" + strconv.FormatInt(r.id, 10)
	if last, ok := c.recent[key]; ok && t.Sub(last) < time.Minute {
		return // one hit per user and rule per minute is plenty
	}
	c.recent[key] = t
	if len(c.recent) > 4096 {
		for k, v := range c.recent {
			if t.Sub(v) >= time.Minute {
				delete(c.recent, k)
			}
		}
	}
	limit := c.Cap
	if limit <= 0 {
		limit = 2000
	}
	if len(c.buf) >= limit {
		c.buf = c.buf[1:]
		c.dropped++
	}
	c.buf = append(c.buf, agentproto.AuditHit{At: t.Unix(), User: user, Inbound: inbound, ClientIP: clientIP, Host: host, Port: port, RuleID: r.id, RuleName: r.name, Action: r.action})
}

// Drain returns and clears the buffered hits and the drop count.
func (c *Collector) Drain() ([]agentproto.AuditHit, int) {
	if c == nil {
		return nil, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out, n := c.buf, c.dropped
	c.buf, c.dropped = nil, 0
	return out, n
}

// BlockRules turns the "block" audit rules into route rules for the cores.
func BlockRules(rules []spec.AuditRule) []spec.RouteRule {
	var out []spec.RouteRule
	for _, r := range rules {
		if r.Action == "block" && len(r.Match) > 0 {
			out = append(out, spec.RouteRule{Match: r.Match, Action: "block"})
		}
	}
	return out
}
