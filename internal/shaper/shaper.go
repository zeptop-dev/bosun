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
	status  Status
	// installed are the users whose classes exist right now, so stale ones
	// can be removed one by one when the root qdisc is not ours to replace.
	installed map[int64]bool
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
	if key.String() == s.applied {
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

// removeUser deletes one user's class and filter from an interface whose
// root qdisc is not ours to throw away.
func (s *Shaper) removeUser(ctx context.Context, dev string, userID int64) {
	cls := "1:" + strconv.FormatInt(spec.SpeedClass(userID), 16)
	mark := "0x" + strconv.FormatInt(spec.SpeedMark(userID), 16)
	_, _ = s.run(ctx, "tc", "filter", "del", "dev", dev, "parent", "1:", "protocol", "all", "prio", "1", "handle", mark, "fw")
	_, _ = s.run(ctx, "tc", "class", "del", "dev", dev, "classid", cls)
}

// removeCatchAll takes the catch-all class and its filter away again and
// gives the line class back the qdisc it had before bosun nested under it.
func (s *Shaper) removeCatchAll(ctx context.Context, dev string, root rootInfo) {
	cls := "1:" + catchAll
	_, _ = s.run(ctx, "tc", "filter", "del", "dev", dev, "parent", "1:", "protocol", "all", "prio", "900")
	_, _ = s.run(ctx, "tc", "class", "del", "dev", dev, "classid", cls)
	s.mu.Lock()
	leaf := s.lineLeaf
	s.mu.Unlock()
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

func (s *Shaper) installedUsers() map[int64]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[int64]bool, len(s.installed))
	for id := range s.installed {
		out[id] = true
	}
	return out
}

func (s *Shaper) setInstalled(limits []Limit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(limits) == 0 {
		s.installed = nil
		return
	}
	s.installed = make(map[int64]bool, len(limits))
	for _, l := range limits {
		s.installed[l.UserID] = true
	}
}

func (s *Shaper) setNested(parent string) { s.mu.Lock(); s.status.NestedUnder = parent; s.mu.Unlock() }

func (s *Shaper) setStatus(st Status) {
	s.mu.Lock()
	st.NestedUnder = s.status.NestedUnder
	s.status = st
	s.mu.Unlock()
}
func (s *Shaper) setApplied(k string) { s.mu.Lock(); s.applied = k; s.mu.Unlock() }

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
	kind   string // "htb", "fq", "" (none), ...
	ours   bool   // an HTB we installed: handle 1: with default 0
	parent string // where per-user classes go: "1:" or a foreign line class
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
	out, err := s.run(ctx, "tc", "qdisc", "show", "dev", dev, "root")
	if err != nil {
		return rootInfo{parent: "1:"}
	}
	line := strings.TrimSpace(string(out))
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	f := strings.Fields(line)
	if len(f) < 2 || f[0] != "qdisc" {
		return rootInfo{parent: "1:"}
	}
	info := rootInfo{kind: f[1], parent: "1:"}
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
	if def == "" || def == "0" {
		info.ours = true
		return info
	}
	// Someone else's HTB: hang under the class its unclassified traffic
	// goes to, when that class exists.
	handle := strings.TrimSuffix(f[2], ":")
	if handle == "" {
		handle = "1"
	}
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
	cls := "1:" + catchAll
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
	_, err := s.run(ctx, "tc", "filter", "replace", "dev", dev, "parent", "1:", "protocol", "all", "prio", "900",
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
	nested := ""
	if !root.ours && root.kind == "htb" {
		nested = root.parent
		if strings.Contains(nested, ":") && !strings.HasSuffix(nested, ":") {
			if root.leaf.kind != "" {
				s.mu.Lock()
				s.lineLeaf = root.leaf
				s.mu.Unlock()
			}
			if err := s.keepUnlimitedShaped(ctx, iface, root); err != nil {
				return err
			}
		}
	}
	for _, dev := range []string{iface, ifbDev} {
		parent := "1:"
		if dev == iface && nested != "" {
			parent = nested
		} else if _, err := s.run(ctx, "tc", "qdisc", "replace", "dev", dev, "root", "handle", "1:", "htb", "default", "0"); err != nil {
			return fmt.Errorf("shaper: %w", err)
		}
		for _, l := range limits {
			cls := "1:" + strconv.FormatInt(spec.SpeedClass(l.UserID), 16)
			rate := strconv.Itoa(l.Mbps) + "mbit"
			if _, err := s.run(ctx, "tc", "class", "replace", "dev", dev, "parent", parent, "classid", cls, "htb", "rate", rate, "ceil", rate); err != nil {
				return fmt.Errorf("shaper: %w", err)
			}
			_, _ = s.run(ctx, "tc", "qdisc", "replace", "dev", dev, "parent", cls, "fq_codel")
			mark := "0x" + strconv.FormatInt(spec.SpeedMark(l.UserID), 16)
			if _, err := s.run(ctx, "tc", "filter", "replace", "dev", dev, "parent", "1:", "protocol", "all", "prio", "1", "handle", mark, "fw", "flowid", cls); err != nil {
				return fmt.Errorf("shaper: %w", err)
			}
		}
	}
	// A root we replaced came up empty, but a root we moved in under keeps
	// the classes of users who no longer have a limit: remove those.
	if nested != "" {
		want := make(map[int64]bool, len(limits))
		for _, l := range limits {
			want[l.UserID] = true
		}
		for id := range s.installedUsers() {
			if !want[id] {
				s.removeUser(ctx, iface, id)
			}
		}
	}
	s.setInstalled(limits)
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
		if root := s.inspectRoot(ctx, iface); root.ours || root.kind != "htb" {
			_, _ = s.run(ctx, "tc", "qdisc", "del", "dev", iface, "root")
		} else {
			for id := range s.installedUsers() {
				s.removeUser(ctx, iface, id)
			}
			s.removeCatchAll(ctx, iface, root)
		}
	}
	s.setInstalled(nil)
	s.setNested("")
	_, _ = s.run(ctx, "ip", "link", "del", ifbDev)
	_ = s.runStdin(ctx, "delete table inet "+nftTable+"\n", "nft", "-f", "-")
	return nil
}
