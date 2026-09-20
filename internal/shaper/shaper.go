// Package shaper enforces per-user bandwidth limits with the kernel. The
// cores route each limited user's traffic through an outbound that stamps
// a firewall mark (see spec.SpeedMark); nftables copies that mark onto the
// connection and tc shapes by mark: an HTB class per user on the egress
// interface (the user's upload) and, through an ifb device that mirrors
// ingress traffic, another for what comes back (the user's download).
// Linux only; needs the nft and tc binaries.
package shaper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Limit is one user's cap.
type Limit struct {
	UserID int64
	Mbps   int
}

// Status is what the UI and doctor show.
type Status struct {
	Supported bool   `json:"supported"`
	Interface string `json:"interface,omitempty"`
	Users     int    `json:"users"`
	Error     string `json:"error,omitempty"`
	// NestedUnder is set when someone else already shapes this interface
	// (a VPS init script capping the line, say) and the per-user classes
	// hang under their class instead of replacing their root qdisc.
	NestedUnder string `json:"nested_under,omitempty"`
}

const (
	ifbDev   = "ifb-bosun"
	nftTable = "bosun_shaper"
)

// Shaper keeps the kernel state in step with the desired limits.
type Shaper struct {
	// Interface overrides the egress interface (default: the default route's).
	Interface string
	// Run overrides command execution (tests).
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)

	mu      sync.Mutex
	applied string
	synced  bool // the kernel has been brought in line at least once
	status  Status
	// lineLeaf is the qdisc a foreign line class had before bosun nested
	// under it, put back when the limits go.
	lineLeaf leafQdisc
}

func (s *Shaper) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if s.Run != nil {
		return s.Run(ctx, name, args...)
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err != nil {
		return out.Bytes(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return out.Bytes(), nil
}

func (s *Shaper) runStdin(ctx context.Context, stdin string, name string, args ...string) error {
	if s.Run != nil {
		_, err := s.Run(ctx, name, append(args, "<<", stdin)...)
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(out.String()))
	}
	return nil
}

// Status returns the last known state.
func (s *Shaper) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// Supported reports whether this host can shape at all.
func (s *Shaper) Supported() bool {
	if runtime.GOOS != "linux" && s.Run == nil {
		return false
	}
	if s.Run != nil {
		return true
	}
	_, e1 := exec.LookPath("nft")
	_, e2 := exec.LookPath("tc")
	return e1 == nil && e2 == nil
}

// Apply installs exactly these limits (an empty list removes everything).
// Unchanged input is a no-op.
func (s *Shaper) Apply(ctx context.Context, limits []Limit) error {
	sort.Slice(limits, func(i, j int) bool { return limits[i].UserID < limits[j].UserID })
	var key strings.Builder
	for _, l := range limits {
		fmt.Fprintf(&key, "%d=%d;", l.UserID, l.Mbps)
	}
	s.mu.Lock()
	// synced, not just a matching key: the first apply after a restart has
	// to run even when it is the empty one, or classes this process never
	// installed stay in the kernel forever.
	if s.synced && key.String() == s.applied {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	if !s.Supported() {
		s.setStatus(Status{Supported: false, Users: len(limits), Error: "needs Linux with nft and tc"})
		if len(limits) == 0 {
			return nil
		}
		return errors.New("shaper: needs Linux with nft and tc")
	}
	if len(limits) == 0 {
		err := s.clear(ctx)
		s.setStatus(Status{Supported: true, Users: 0, Error: errText(err)})
		if err == nil {
			s.setApplied(key.String())
		}
		return err
	}
	iface, err := s.iface(ctx)
	if err != nil {
		s.setStatus(Status{Supported: true, Users: len(limits), Error: err.Error()})
		return err
	}
	err = s.install(ctx, iface, limits)
	s.setStatus(Status{Supported: true, Interface: iface, Users: len(limits), Error: errText(err)})
	if err == nil {
		s.setApplied(key.String())
	}
	return err
}

// ensureRoot makes dev's root qdisc an HTB of ours, and leaves one that
// already is alone: HTB has no qdisc-level change operation, so replacing
// our own root fails outright ("Change operation not supported by specified
// qdisc") — which is what every bosun restart with limits in place would
// otherwise run into.
func (s *Shaper) ensureRoot(ctx context.Context, dev string, root rootInfo) error {
	if root.ours {
		return nil
	}
	if root.kind != "" {
		_, _ = s.run(ctx, "tc", "qdisc", "del", "dev", dev, "root")
	}
	if _, err := s.run(ctx, "tc", "qdisc", "replace", "dev", dev, "root", "handle", "1:", "htb", "default", "0"); err != nil {
		return fmt.Errorf("shaper: %w", err)
	}
	return nil
}

// reconcile removes the classes, and the fw filters pointing at them, of
// users who no longer have a limit. What the kernel holds is the truth:
// bosun may have been restarted since the classes were installed, so its
// own memory of them is not to be trusted.
func (s *Shaper) reconcile(ctx context.Context, dev string, root rootInfo, want map[string]bool) {
	out, err := s.run(ctx, "tc", "class", "show", "dev", dev)
	if err != nil {
		return
	}
	var stale []string
	for _, cls := range htbChildren(string(out), root.parent) {
		if want[cls] || cls == root.major+":"+catchAll {
			continue
		}
		stale = append(stale, cls)
	}
	if len(stale) == 0 {
		return
	}
	drop := make(map[string]bool, len(stale))
	for _, cls := range stale {
		drop[cls] = true
	}
	if out, err := s.run(ctx, "tc", "filter", "show", "dev", dev, "parent", root.major+":"); err == nil {
		for _, f := range fwFilters(string(out)) {
			if drop[f.flowid] {
				_, _ = s.run(ctx, "tc", "filter", "del", "dev", dev, "parent", root.major+":", "protocol", "all", "prio", "1", "handle", f.handle, "fw")
			}
		}
	}
	for _, cls := range stale {
		_, _ = s.run(ctx, "tc", "class", "del", "dev", dev, "classid", cls)
	}
}

// htbChildren lists the HTB classes hanging directly off parent, which is
// either a root qdisc ("1:") or a class ("1:10").
func htbChildren(out, parent string) []string {
	var ids []string
	underRoot := strings.HasSuffix(parent, ":")
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[0] != "class" || f[1] != "htb" {
			continue
		}
		if underRoot {
			if f[3] != "root" || !strings.HasPrefix(f[2], parent) {
				continue
			}
		} else if f[3] != "parent" || len(f) < 5 || f[4] != parent {
			continue
		}
		ids = append(ids, f[2])
	}
	return ids
}

// fwFilter is one "handle 0x10007 fw ... classid 1:8" line.
type fwFilter struct{ handle, flowid string }

func fwFilters(out string) []fwFilter {
	var res []fwFilter
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "filter" {
			continue
		}
		var got fwFilter
		fw := false
		for i, w := range f {
			switch {
			case w == "fw":
				fw = true
			case w == "handle" && i+1 < len(f):
				got.handle = f[i+1]
			case (w == "classid" || w == "flowid") && i+1 < len(f):
				got.flowid = f[i+1]
			}
		}
		if fw && got.handle != "" && got.flowid != "" {
			res = append(res, got)
		}
	}
	return res
}

// removeCatchAll takes the catch-all class and its filter away again and
// gives the line class back the qdisc it had before bosun nested under it.
func (s *Shaper) removeCatchAll(ctx context.Context, dev string, root rootInfo) {
	cls := root.major + ":" + catchAll
	s.mu.Lock()
	leaf := s.lineLeaf
	s.mu.Unlock()
	if leaf.kind == "" {
		// Restarted since the nesting: the catch-all's own qdisc is the
		// copy of the line's that was made back then, so read it off
		// there. Its handle is the catch-all's, not the line's — let the
		// kernel pick a new one.
		if out, err := s.run(ctx, "tc", "qdisc", "show", "dev", dev); err == nil {
			leaf = leafOf(string(out), cls)
			leaf.handle = ""
		}
	}
	_, _ = s.run(ctx, "tc", "filter", "del", "dev", dev, "parent", root.major+":", "protocol", "all", "prio", "900")
	_, _ = s.run(ctx, "tc", "class", "del", "dev", dev, "classid", cls)
	if leaf.kind == "" || root.parent == "" || strings.HasSuffix(root.parent, ":") {
		return
	}
	args := []string{"qdisc", "replace", "dev", dev, "parent", root.parent}
	if leaf.handle != "" {
		args = append(args, "handle", leaf.handle)
	}
	args = append(args, leaf.kind)
	if leaf.kind == "fq" && leaf.maxrate != "" {
		args = append(args, "maxrate", leaf.maxrate)
	}
	_, _ = s.run(ctx, "tc", args...)
}

func (s *Shaper) setNested(parent string) { s.mu.Lock(); s.status.NestedUnder = parent; s.mu.Unlock() }

func (s *Shaper) setStatus(st Status) {
	s.mu.Lock()
	st.NestedUnder = s.status.NestedUnder
	s.status = st
	s.mu.Unlock()
}
func (s *Shaper) setApplied(k string) { s.mu.Lock(); s.applied, s.synced = k, true; s.mu.Unlock() }

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// catchAll is the leaf class that takes the traffic of everyone without a
// limit when bosun moves in under a line shaper. HTB drops unclassified
// traffic into its direct queue — unshaped, past the line cap — as soon as
// the class the root's "default" points at stops being a leaf, which is
// exactly what happens when the per-user classes hang under it.
const catchAll = "fffe"

// rootInfo describes the egress interface's root qdisc.
type rootInfo struct {
	kind    string // "htb", "fq", "" (none), ...
	ours    bool   // an HTB we installed: handle 1: with default 0
	foreign bool   // someone else's HTB: move in under it, never replace it
	major   string // the handle the classes live in: "1", or theirs
	parent  string // where per-user classes go: "1:" or a foreign line class
	// The foreign line class and the shaping it was doing, so the same
	// shaping can be put on the catch-all and restored on the way out.
	lineRate string
	lineCeil string
	leaf     leafQdisc
}

// leafQdisc is the qdisc a foreign line class had before bosun nested
// under it (HTB removes it once the class has children).
type leafQdisc struct {
	kind    string // "fq", "fq_codel", ...
	handle  string // "100:"
	maxrate string // fq only
}

// inspectRoot reads the root qdisc so the shaper can decide whether to take
// the interface over or move in under what is already there. Ours is the
// HTB with "default 0"; a line shaper (quench, a hand-written tc script)
// sends unclassified traffic to a class instead, which is where the
// per-user classes belong so the line cap still applies above them.
func (s *Shaper) inspectRoot(ctx context.Context, dev string) rootInfo {
	bare := rootInfo{major: "1", parent: "1:"}
	out, err := s.run(ctx, "tc", "qdisc", "show", "dev", dev, "root")
	if err != nil {
		return bare
	}
	line := strings.TrimSpace(string(out))
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	f := strings.Fields(line)
	if len(f) < 2 || f[0] != "qdisc" {
		return bare
	}
	info := bare
	info.kind = f[1]
	if info.kind != "htb" {
		return info
	}
	def := ""
	for i, w := range f {
		if w == "default" && i+1 < len(f) {
			def = strings.TrimPrefix(f[i+1], "0x")
			break
		}
	}
	handle := "1"
	if len(f) > 2 {
		if h := strings.TrimSuffix(f[2], ":"); h != "" {
			handle = h
		}
	}
	if def == "" || def == "0" {
		// Ours, as long as it is where we put it; an HTB of that shape
		// under another handle is nobody's and gets replaced.
		info.ours = handle == "1"
		return info
	}
	// Someone else's HTB: hang under the class its unclassified traffic
	// goes to, when that class exists.
	info.foreign = true
	info.major = handle
	cls := handle + ":" + def
	classes, err := s.run(ctx, "tc", "class", "show", "dev", dev)
	if err != nil || !strings.Contains(string(classes), " "+cls+" ") {
		info.parent = handle + ":"
		return info
	}
	info.parent = cls
	info.lineRate, info.lineCeil = classRates(string(classes), cls)
	if out, err := s.run(ctx, "tc", "qdisc", "show", "dev", dev); err == nil {
		info.leaf = leafOf(string(out), cls)
	}
	return info
}

// classRates reads a class's rate and ceil out of "tc class show".
func classRates(out, cls string) (rate, ceil string) {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "class" || f[2] != cls {
			continue
		}
		for i, w := range f {
			if i+1 >= len(f) {
				break
			}
			switch w {
			case "rate":
				rate = f[i+1]
			case "ceil":
				ceil = f[i+1]
			}
		}
		return rate, ceil
	}
	return "", ""
}

// leafOf reads the qdisc hanging under a class out of "tc qdisc show".
func leafOf(out, cls string) leafQdisc {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[0] != "qdisc" {
			continue
		}
		var parent string
		for i, w := range f {
			if w == "parent" && i+1 < len(f) {
				parent = f[i+1]
			}
		}
		if parent != cls {
			continue
		}
		l := leafQdisc{kind: f[1], handle: f[2]}
		for i, w := range f {
			if w == "maxrate" && i+1 < len(f) {
				l.maxrate = f[i+1]
			}
		}
		return l
	}
	return leafQdisc{}
}

// keepUnlimitedShaped gives the traffic of users without a limit a leaf
// class of its own under the line class, with the shaping the line class
// itself was doing, and a lowest-priority filter that sends everything
// unmatched there. Without it HTB's direct queue would carry that traffic
// past the line shaper entirely.
func (s *Shaper) keepUnlimitedShaped(ctx context.Context, dev string, root rootInfo) error {
	cls := root.major + ":" + catchAll
	if classes, err := s.run(ctx, "tc", "class", "show", "dev", dev); err == nil && strings.Contains(string(classes), " "+cls+" ") {
		return nil // already there; leave its shaping alone
	}
	rate, ceil := root.lineRate, root.lineCeil
	if rate == "" {
		rate = "1gbit"
	}
	if ceil == "" {
		ceil = rate
	}
	if _, err := s.run(ctx, "tc", "class", "replace", "dev", dev, "parent", root.parent, "classid", cls, "htb", "rate", rate, "ceil", ceil); err != nil {
		return fmt.Errorf("shaper: catch-all class: %w", err)
	}
	leaf := []string{"tc", "qdisc", "replace", "dev", dev, "parent", cls, "handle", catchAll + ":"}
	switch {
	case root.leaf.kind == "fq" && root.leaf.maxrate != "":
		leaf = append(leaf, "fq", "maxrate", root.leaf.maxrate)
	case root.leaf.kind != "":
		leaf = append(leaf, root.leaf.kind)
	default:
		leaf = append(leaf, "fq_codel")
	}
	_, _ = s.run(ctx, leaf[0], leaf[1:]...)
	// Lowest priority: the per-user filters (prio 1) are matched first.
	_, err := s.run(ctx, "tc", "filter", "replace", "dev", dev, "parent", root.major+":", "protocol", "all", "prio", "900",
		"u32", "match", "u32", "0", "0", "flowid", cls)
	return err
}

// iface is the interface the default route leaves through.
func (s *Shaper) iface(ctx context.Context) (string, error) {
	if s.Interface != "" {
		return s.Interface, nil
	}
	out, err := s.run(ctx, "ip", "-o", "route", "get", "1.1.1.1")
	if err != nil {
		return "", fmt.Errorf("shaper: default interface: %w", err)
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", errors.New("shaper: cannot find the default interface")
}

// install (re)builds the whole rule set: cheap, and the set only changes
// when limited users do.
func (s *Shaper) install(ctx context.Context, iface string, limits []Limit) error {
	// nft: keep the socket mark on the connection, restore it for replies.
	rules := "table inet " + nftTable + " {\n" +
		"  chain output { type filter hook output priority mangle; policy accept;\n    meta mark != 0 ct mark set meta mark\n  }\n" +
		"  chain prerouting { type filter hook prerouting priority mangle; policy accept;\n    ct mark != 0 meta mark set ct mark\n  }\n}\n"
	if err := s.runStdin(ctx, "delete table inet "+nftTable+"\n"+rules, "nft", "-f", "-"); err != nil {
		// A missing table makes the delete fail on older nft; retry plain.
		if err2 := s.runStdin(ctx, rules, "nft", "-f", "-"); err2 != nil {
			return fmt.Errorf("shaper: nft: %w", err2)
		}
	}
	// ifb mirrors ingress so the download side can be shaped too.
	_, _ = s.run(ctx, "ip", "link", "add", ifbDev, "type", "ifb")
	if _, err := s.run(ctx, "ip", "link", "set", ifbDev, "up"); err != nil {
		return fmt.Errorf("shaper: ifb: %w", err)
	}
	// The ifb device is the shaper's own; the egress interface may belong
	// to someone else's line shaper, and then the per-user classes go
	// under it rather than over it.
	root := s.inspectRoot(ctx, iface)
	if root.foreign && !strings.HasSuffix(root.parent, ":") {
		if root.leaf.kind != "" {
			s.mu.Lock()
			s.lineLeaf = root.leaf
			s.mu.Unlock()
		}
		if err := s.keepUnlimitedShaped(ctx, iface, root); err != nil {
			return err
		}
	}
	for _, dev := range []string{iface, ifbDev} {
		r := root
		if dev == ifbDev {
			// Nobody else has a claim on the ifb device.
			r = s.inspectRoot(ctx, dev)
			r.foreign, r.major, r.parent = false, "1", "1:"
		}
		if !r.foreign {
			if err := s.ensureRoot(ctx, dev, r); err != nil {
				return err
			}
		}
		want := make(map[string]bool, len(limits))
		for _, l := range limits {
			cls := r.major + ":" + strconv.FormatInt(spec.SpeedClass(l.UserID), 16)
			want[cls] = true
			rate := strconv.Itoa(l.Mbps) + "mbit"
			if _, err := s.run(ctx, "tc", "class", "replace", "dev", dev, "parent", r.parent, "classid", cls, "htb", "rate", rate, "ceil", rate); err != nil {
				return fmt.Errorf("shaper: %w", err)
			}
			_, _ = s.run(ctx, "tc", "qdisc", "replace", "dev", dev, "parent", cls, "fq_codel")
			mark := "0x" + strconv.FormatInt(spec.SpeedMark(l.UserID), 16)
			if _, err := s.run(ctx, "tc", "filter", "replace", "dev", dev, "parent", r.major+":", "protocol", "all", "prio", "1", "handle", mark, "fw", "flowid", cls); err != nil {
				return fmt.Errorf("shaper: %w", err)
			}
		}
		// A root we rebuilt came up empty, but one we keep — a line
		// shaper's, or our own from before a restart — still carries the
		// classes of users who no longer have a limit.
		s.reconcile(ctx, dev, r, want)
	}
	nested := ""
	if root.foreign {
		nested = root.parent
	}
	s.setNested(nested)

	// Ingress on the real interface: restore the connection mark onto the
	// packet, then hand it to the ifb where the fw filters apply.
	_, _ = s.run(ctx, "tc", "qdisc", "replace", "dev", iface, "ingress")
	_, _ = s.run(ctx, "tc", "filter", "del", "dev", iface, "ingress")
	if _, err := s.run(ctx, "tc", "filter", "add", "dev", iface, "ingress", "protocol", "all", "prio", "1", "matchall",
		"action", "connmark", "action", "mirred", "egress", "redirect", "dev", ifbDev); err != nil {
		return fmt.Errorf("shaper: ingress redirect: %w", err)
	}
	return nil
}

// clear removes everything the shaper installed. An interface whose root
// qdisc belongs to someone else keeps it: only the per-user classes and
// filters go.
func (s *Shaper) clear(ctx context.Context) error {
	iface, err := s.iface(ctx)
	if err == nil {
		_, _ = s.run(ctx, "tc", "qdisc", "del", "dev", iface, "ingress")
		// Only a root qdisc of our own is thrown away. Someone else's HTB
		// gives its classes back; any other root (an init script's fq
		// pacing the line for BBR, say) is none of our business, and we
		// never put classes under it.
		switch root := s.inspectRoot(ctx, iface); {
		case root.ours:
			_, _ = s.run(ctx, "tc", "qdisc", "del", "dev", iface, "root")
		case root.foreign:
			s.reconcile(ctx, iface, root, nil)
			s.removeCatchAll(ctx, iface, root)
		}
	}
	s.setNested("")
	_, _ = s.run(ctx, "ip", "link", "del", ifbDev)
	_ = s.runStdin(ctx, "delete table inet "+nftTable+"\n", "nft", "-f", "-")
	return nil
}
