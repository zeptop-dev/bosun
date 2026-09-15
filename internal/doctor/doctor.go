// Package doctor runs read-only health checks on a node: listeners,
// bindings, forwards, certificates, port clashes, firewall, disk, memory,
// panel contact, clock sync. Every check is independent, bounded and never
// panics; the result is a flat list the UI, the CLI and the panel display.
package doctor

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zeptop-dev/bosun/internal/shaper"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Check statuses.
const (
	OK   = "ok"
	Warn = "warn"
	Fail = "fail"
	Skip = "skip"
)

// The wire types live in agentproto so the panel can decode them; these
// aliases keep the package readable.
type (
	Check   = agentproto.DoctorCheck
	Summary = agentproto.DoctorSummary
	Report  = agentproto.DoctorReport
)

// CoreState is what the registry knows about one core.
type CoreState struct {
	Name     string
	Running  bool
	Inbounds int // inbounds assigned to it; 0 = should not be running
}

// ForwardState is one relay rule's live status.
type ForwardState struct {
	Tag      string
	Protocol string
	Listen   string
	Port     int
	Target   string
	Up       bool
	Error    string
}

// CertState is one certificate the node knows.
type CertState struct {
	Domain   string
	NotAfter time.Time
	Error    string
}

// Deps is everything Run looks at. Zero fields make the related check a
// skip, so an agent-less CLI run can still use the package.
type Deps struct {
	Node  *spec.Node
	Users []spec.User
	Cores []CoreState
	// CoresKnown false = this process does not run the cores (CLI): skip.
	CoresKnown bool
	Forwards   []ForwardState
	Certs      []CertState
	Host       spec.SystemStatus
	// Managed mode: LastReport is when the panel last accepted a report,
	// PushInterval the report cadence; Managed false = standalone (skip).
	Managed      bool
	LastReport   time.Time
	LastError    string
	PushInterval time.Duration
	// Komari exporter state.
	KomariEnabled bool
	KomariError   string
	// Assign maps inbound tag to the core serving it (for core-specific advice).
	Assign map[string]string
	// Shaper is the speed-limit state (nil = no limits configured).
	Shaper *shaper.Status
	// Dial overrides TCP connects (tests).
	Dial func(ctx context.Context, addr string) error
	// Lookup overrides DNS resolution (tests).
	Lookup func(ctx context.Context, host string) ([]net.IP, error)
	// Exec overrides command execution (tests); nil uses exec.Command.
	Exec func(ctx context.Context, name string, args ...string) ([]byte, error)
	// Interfaces overrides local address discovery (tests).
	Interfaces func() []net.IP
	Now        func() time.Time
}

const perCheck = 5 * time.Second

// Run executes every check and returns the report.
func Run(ctx context.Context, d Deps) Report {
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	rep := Report{At: now(), Checks: []Check{}}
	checks := []func(context.Context, *Deps) []Check{
		checkCores, checkInbounds, checkBind, checkForwards, checkCerts, checkPorts,
		checkFirewall, checkDisk, checkMemory, checkPanel, checkPublic, checkKomari, checkTime, checkReality, checkShaper,
	}
	for _, fn := range checks {
		cctx, cancel := context.WithTimeout(ctx, perCheck)
		out := safeRun(cctx, &d, fn)
		cancel()
		rep.Checks = append(rep.Checks, out...)
	}
	for _, c := range rep.Checks {
		switch c.Status {
		case OK:
			rep.Summary.OK++
		case Warn:
			rep.Summary.Warn++
		case Fail:
			rep.Summary.Fail++
		default:
			rep.Summary.Skip++
		}
	}
	return rep
}

func safeRun(ctx context.Context, d *Deps, fn func(context.Context, *Deps) []Check) (out []Check) {
	defer func() {
		if r := recover(); r != nil {
			out = []Check{{ID: "internal", Name: "check crashed", Status: Warn, Detail: fmt.Sprint(r)}}
		}
	}()
	return fn(ctx, d)
}

func (d *Deps) dial(ctx context.Context, addr string) error {
	if d.Dial != nil {
		return d.Dial(ctx, addr)
	}
	dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(dctx, "tcp", addr)
	if err == nil {
		c.Close()
	}
	return err
}

func (d *Deps) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if d.Exec != nil {
		return d.Exec(ctx, name, args...)
	}
	if _, err := exec.LookPath(name); err != nil {
		return nil, err
	}
	return exec.CommandContext(ctx, name, args...).Output()
}

func (d *Deps) localIPs() []net.IP {
	if d.Interfaces != nil {
		return d.Interfaces()
	}
	var out []net.IP
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			out = append(out, ipn.IP)
		}
	}
	return out
}

func inbounds(d *Deps) []spec.Inbound {
	if d.Node == nil {
		return nil
	}
	return d.Node.Inbounds
}

// udpOnly protocols never answer a TCP connect.
func udpOnly(ib spec.Inbound) bool {
	switch ib.Protocol {
	case spec.Hysteria2, spec.TUIC:
		return true
	case spec.Mieru:
		return strings.EqualFold(ib.MieruTransport, "UDP")
	}
	return false
}

func listenAddr(ib spec.Inbound) string {
	host := ib.Listen
	if host == "" || host == "::" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(ib.Port))
}

func checkCores(_ context.Context, d *Deps) []Check {
	if !d.CoresKnown {
		return []Check{{ID: "cores", Name: "Cores running", Status: Skip, Detail: "not the running service"}}
	}
	var down []string
	for _, c := range d.Cores {
		if c.Inbounds > 0 && !c.Running {
			down = append(down, c.Name)
		}
	}
	if len(down) > 0 {
		return []Check{{ID: "cores", Name: "Cores running", Status: Fail, Detail: "not running: " + strings.Join(down, ", ")}}
	}
	return []Check{{ID: "cores", Name: "Cores running", Status: OK}}
}

func checkInbounds(ctx context.Context, d *Deps) []Check {
	ibs := inbounds(d)
	if len(ibs) == 0 {
		return []Check{{ID: "inbounds", Name: "Inbounds listening", Status: Skip, Detail: "no inbounds"}}
	}
	var out []Check
	for _, ib := range ibs {
		c := Check{ID: "inbound:" + ib.Tag, Name: "Inbound " + ib.Tag + " listening"}
		if udpOnly(ib) {
			c.Status, c.Detail = Skip, "udp"
		} else if err := d.dial(ctx, listenAddr(ib)); err != nil {
			c.Status, c.Detail = Fail, listenAddr(ib)+": "+err.Error()
		} else {
			c.Status, c.Detail = OK, listenAddr(ib)
		}
		out = append(out, c)
	}
	return out
}

func checkBind(_ context.Context, d *Deps) []Check {
	var want []string
	for _, ib := range inbounds(d) {
		if ip := net.ParseIP(ib.Listen); ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() {
			want = append(want, ib.Listen)
		}
	}
	if len(want) == 0 {
		return []Check{{ID: "bind", Name: "Bind addresses present", Status: Skip, Detail: "no inbound binds a specific address"}}
	}
	have := map[string]bool{}
	for _, ip := range d.localIPs() {
		have[ip.String()] = true
	}
	var missing []string
	for _, w := range want {
		if !have[net.ParseIP(w).String()] {
			missing = append(missing, w)
		}
	}
	if len(missing) > 0 {
		return []Check{{ID: "bind", Name: "Bind addresses present", Status: Fail, Detail: "not on any interface: " + strings.Join(uniq(missing), ", ")}}
	}
	return []Check{{ID: "bind", Name: "Bind addresses present", Status: OK}}
}

func checkForwards(ctx context.Context, d *Deps) []Check {
	if len(d.Forwards) == 0 {
		return []Check{{ID: "forwards", Name: "Forwards", Status: Skip, Detail: "no forward rules"}}
	}
	var out []Check
	for _, f := range d.Forwards {
		c := Check{ID: "forward:" + f.Tag, Name: "Forward " + f.Tag}
		if strings.EqualFold(f.Protocol, "udp") {
			c.Status, c.Detail = Skip, "udp"
			out = append(out, c)
			continue
		}
		host := f.Listen
		if host == "" || host == "::" || host == "0.0.0.0" {
			host = "127.0.0.1"
		}
		if err := d.dial(ctx, net.JoinHostPort(host, strconv.Itoa(f.Port))); err != nil {
			c.Status, c.Detail = Fail, "listener: "+err.Error()
		} else if !f.Up {
			c.Status, c.Detail = Warn, "target "+f.Target+" down: "+f.Error
		} else {
			c.Status, c.Detail = OK, "-> "+f.Target
		}
		out = append(out, c)
	}
	return out
}

func checkCerts(_ context.Context, d *Deps) []Check {
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	var names []string
	for _, ib := range inbounds(d) {
		if ib.TLS != nil && ib.TLS.Mode == spec.TLSStandard && ib.TLS.ServerName != "" {
			names = append(names, ib.TLS.ServerName)
		}
	}
	if len(names) == 0 {
		return []Check{{ID: "certs", Name: "Certificates", Status: Skip, Detail: "no TLS inbounds"}}
	}
	byDomain := map[string]CertState{}
	for _, c := range d.Certs {
		byDomain[strings.ToLower(c.Domain)] = c
	}
	var out []Check
	for _, n := range uniq(names) {
		c := Check{ID: "cert:" + n, Name: "Certificate " + n}
		st, ok := byDomain[strings.ToLower(n)]
		if !ok {
			// a wildcard may cover it
			for dom, s := range byDomain {
				if strings.HasPrefix(dom, "*.") && strings.HasSuffix(n, dom[1:]) && !strings.Contains(strings.TrimSuffix(n, dom[1:]), ".") {
					st, ok = s, true
				}
			}
		}
		switch {
		case !ok:
			c.Status, c.Detail = Fail, "no certificate"
		case st.Error != "":
			c.Status, c.Detail = Fail, st.Error
		case st.NotAfter.IsZero():
			c.Status, c.Detail = Warn, "not issued yet"
		case st.NotAfter.Before(now()):
			c.Status, c.Detail = Fail, "expired "+st.NotAfter.Format("2006-01-02")
		case st.NotAfter.Sub(now()) < 14*24*time.Hour:
			c.Status, c.Detail = Warn, fmt.Sprintf("expires in %d days", int(st.NotAfter.Sub(now()).Hours()/24))
		default:
			c.Status, c.Detail = OK, "expires "+st.NotAfter.Format("2006-01-02")
		}
		out = append(out, c)
	}
	return out
}

func checkPorts(_ context.Context, d *Deps) []Check {
	owner := map[string]string{}
	var clashes []string
	claim := func(proto string, port int, who string) {
		key := proto + "/" + strconv.Itoa(port)
		if prev, ok := owner[key]; ok && prev != who {
			clashes = append(clashes, key+" ("+prev+", "+who+")")
			return
		}
		owner[key] = who
	}
	for _, ib := range inbounds(d) {
		protos := []string{"tcp"}
		switch {
		case udpOnly(ib):
			protos = []string{"udp"}
		case ib.Protocol == spec.Mieru && strings.EqualFold(ib.MieruTransport, "BOTH"):
			claim("udp", ib.Port+1, "inbound "+ib.Tag)
		}
		for _, p := range protos {
			claim(p, ib.Port, "inbound "+ib.Tag)
		}
	}
	for _, f := range d.Forwards {
		protos := []string{"tcp", "udp"}
		if strings.EqualFold(f.Protocol, "tcp") || strings.EqualFold(f.Protocol, "udp") {
			protos = []string{strings.ToLower(f.Protocol)}
		}
		for _, p := range protos {
			claim(p, f.Port, "forward "+f.Tag)
		}
	}
	if len(owner) == 0 {
		return []Check{{ID: "ports", Name: "Port conflicts", Status: Skip, Detail: "nothing listens"}}
	}
	if len(clashes) > 0 {
		return []Check{{ID: "ports", Name: "Port conflicts", Status: Fail, Detail: strings.Join(clashes, "; ")}}
	}
	return []Check{{ID: "ports", Name: "Port conflicts", Status: OK}}
}

// checkFirewall is best effort: a default DROP/REJECT input policy with no
// accept rule mentioning an inbound port is worth a warning.
func checkFirewall(ctx context.Context, d *Deps) []Check {
	c := Check{ID: "firewall", Name: "Firewall"}
	ibs := inbounds(d)
	if len(ibs) == 0 {
		c.Status, c.Detail = Skip, "no inbounds"
		return []Check{c}
	}
	rules, err := d.run(ctx, "nft", "list", "ruleset")
	tool := "nft"
	if err != nil {
		rules, err = d.run(ctx, "iptables", "-S", "INPUT")
		tool = "iptables"
	}
	if err != nil {
		c.Status, c.Detail = Skip, "nft/iptables not available"
		return []Check{c}
	}
	text := string(rules)
	restrictive := false
	if tool == "nft" {
		restrictive = strings.Contains(text, "hook input") && (strings.Contains(text, "policy drop") || strings.Contains(text, "policy reject"))
	} else {
		restrictive = strings.Contains(text, "-P INPUT DROP") || strings.Contains(text, "-P INPUT REJECT")
	}
	if !restrictive {
		c.Status, c.Detail = OK, tool+": input not restricted"
		return []Check{c}
	}
	var blocked []string
	for _, ib := range ibs {
		p := strconv.Itoa(ib.Port)
		if !strings.Contains(text, "dport "+p) && !strings.Contains(text, "--dport "+p) && !strings.Contains(text, "dport { ") {
			blocked = append(blocked, ib.Tag+":"+p)
		}
	}
	if len(blocked) > 0 {
		c.Status, c.Detail = Warn, tool+" input policy drops by default and no accept rule names: "+strings.Join(blocked, ", ")
		return []Check{c}
	}
	c.Status, c.Detail = OK, tool+": restrictive policy with accept rules for every inbound"
	return []Check{c}
}

func checkDisk(_ context.Context, d *Deps) []Check {
	c := Check{ID: "disk", Name: "Disk space"}
	if d.Host.DiskTotal == 0 {
		c.Status, c.Detail = Skip, "unknown"
		return []Check{c}
	}
	free := float64(d.Host.DiskTotal-d.Host.DiskUsed) / float64(d.Host.DiskTotal) * 100
	c.Detail = fmt.Sprintf("%.0f%% free", free)
	switch {
	case free < 3:
		c.Status = Fail
	case free < 10:
		c.Status = Warn
	default:
		c.Status = OK
	}
	return []Check{c}
}

func checkMemory(_ context.Context, d *Deps) []Check {
	c := Check{ID: "memory", Name: "Memory"}
	if d.Host.MemTotal == 0 {
		c.Status, c.Detail = Skip, "unknown"
		return []Check{c}
	}
	c.Status = OK
	c.Detail = fmt.Sprintf("%.0f%% used", float64(d.Host.MemUsed)/float64(d.Host.MemTotal)*100)
	if d.Host.SwapTotal > 0 && d.Host.SwapUsed*2 > d.Host.SwapTotal {
		c.Status = Warn
		c.Detail += fmt.Sprintf(", swap %.0f%% used", float64(d.Host.SwapUsed)/float64(d.Host.SwapTotal)*100)
	}
	return []Check{c}
}

func checkPanel(_ context.Context, d *Deps) []Check {
	c := Check{ID: "panel", Name: "Panel contact"}
	if !d.Managed {
		c.Status, c.Detail = Skip, "standalone"
		return []Check{c}
	}
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	iv := d.PushInterval
	if iv <= 0 {
		iv = time.Minute
	}
	switch {
	case d.LastReport.IsZero():
		c.Status, c.Detail = Warn, "no report accepted yet"
	case now().Sub(d.LastReport) > 3*iv:
		c.Status, c.Detail = Warn, "last report "+now().Sub(d.LastReport).Truncate(time.Second).String()+" ago"
	default:
		c.Status, c.Detail = OK, "last report "+now().Sub(d.LastReport).Truncate(time.Second).String()+" ago"
	}
	if d.LastError != "" {
		c.Detail += "; " + d.LastError
	}
	return []Check{c}
}

func checkPublic(_ context.Context, _ *Deps) []Check {
	return []Check{{ID: "public", Name: "Public reachability", Status: Skip, Detail: "needs an external vantage point (panel speed test)"}}
}

func checkKomari(_ context.Context, d *Deps) []Check {
	c := Check{ID: "komari", Name: "Komari reporting"}
	switch {
	case !d.KomariEnabled:
		c.Status, c.Detail = Skip, "off"
	case d.KomariError != "":
		c.Status, c.Detail = Warn, d.KomariError
	default:
		c.Status = OK
	}
	return []Check{c}
}

func checkTime(ctx context.Context, d *Deps) []Check {
	c := Check{ID: "time", Name: "Clock sync"}
	out, err := d.run(ctx, "timedatectl", "show", "-p", "NTPSynchronized")
	if err != nil {
		c.Status, c.Detail = Skip, "timedatectl not available"
		return []Check{c}
	}
	if strings.Contains(strings.ToLower(string(out)), "=no") {
		c.Status, c.Detail = Warn, "NTP not synchronized"
		return []Check{c}
	}
	c.Status = OK
	return []Check{c}
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// checkShaper reports on per-user speed limits.
func checkShaper(_ context.Context, d *Deps) []Check {
	c := Check{ID: "shaper", Name: "Per-user speed limits", Status: Skip, Detail: "no limits configured"}
	if d.Shaper == nil {
		return []Check{c}
	}
	switch {
	case !d.Shaper.Supported:
		c.Status, c.Detail = Warn, "limits are configured but this host cannot shape (needs Linux with nft and tc); users run unlimited"
	case d.Shaper.Error != "":
		c.Status, c.Detail = Fail, d.Shaper.Error
	default:
		c.Status, c.Detail = OK, fmt.Sprintf("%d users shaped on %s", d.Shaper.Users, d.Shaper.Interface)
	}
	return []Check{c}
}
