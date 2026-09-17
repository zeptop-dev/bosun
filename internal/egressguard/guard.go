// Package egressguard keeps the proxy cores away from the node's own
// private surroundings: an nftables output rule drops new connections
// made by the core account (see runas) to link-local, cloud-metadata,
// RFC 1918 and CGNAT ranges, so a client of a compromised or misconfigured
// core cannot reach the cloud metadata service, the provider's internal
// network or the panel's private side. Established flows are untouched
// (replies to clients that happen to sit in private space still work),
// loopback stays open (the local DNS stub), and cidrs the operator lists
// in cores.egress_allow are exempt.
//
//	table inet bosun_egress { chain output { type filter hook output priority filter; policy accept;
//	  meta skuid 998 ct state new ip daddr { 10.0.0.0/8, ... } drop
//	} }
//
// bosun owns only that table.
package egressguard

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Status is what the doctor shows.
type Status struct {
	Supported bool   `json:"supported"`
	UID       int    `json:"uid"`
	Allowed   int    `json:"allowed"`
	Loopback  bool   `json:"loopback"` // loopback closed except LoopbackPorts
	Error     string `json:"error,omitempty"`
}

const table = "bosun_egress"

// Blocked ranges. Loopback is blocked as well, except for the ports in
// Options.LoopbackPorts: a core that can reach 127.0.0.1 freely can talk
// to the node's own control services (the cores' own API sockets, bosun's
// metrics and web panel) on behalf of any paying user.
var (
	blocked4 = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16"}
	blocked6 = []string{"fc00::/7", "fe80::/10"}
	loop4    = "127.0.0.0/8"
	loop6    = "::1/128"
)

// Options are the guard's inputs besides the account.
type Options struct {
	// Allow are operator-configured destinations that stay reachable.
	Allow []string
	// LoopbackPorts are the local TCP/UDP ports a core may still reach
	// (53 for a DNS stub, hysteria's auth callback, the decoy site).
	// Everything else on loopback is dropped.
	LoopbackPorts []int
}

// Guard installs the table and keeps it in step with the desired state.
type Guard struct {
	// Run overrides command execution (tests).
	Run func(ctx context.Context, stdin string, name string, args ...string) ([]byte, error)

	mu      sync.Mutex
	applied string
	status  Status
}

func (g *Guard) run(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
	if g.Run != nil {
		return g.Run(ctx, stdin, name, args...)
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(out.String()))
	}
	return out.Bytes(), nil
}

// Supported reports whether this host can enforce at all.
func (g *Guard) Supported() bool {
	if g.Run != nil {
		return true
	}
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := exec.LookPath("nft")
	return err == nil
}

// Status returns the last known state.
func (g *Guard) Status() Status {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.status
}

// Script renders the nft script for uid; opt.Allow lists cidrs (sorted, so
// the text is stable) that stay reachable. uid < 0 renders nothing.
func Script(uid int, opt Options) string {
	if uid < 0 {
		return ""
	}
	var a4, a6 []string
	for _, c := range opt.Allow {
		ip, n, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			if ip = net.ParseIP(strings.TrimSpace(c)); ip == nil {
				continue // never interpolate anything that is not a literal address
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			_, n, _ = net.ParseCIDR(fmt.Sprintf("%s/%d", ip, bits))
		}
		if n.IP.To4() != nil {
			a4 = append(a4, n.String())
		} else {
			a6 = append(a6, n.String())
		}
	}
	sort.Strings(a4)
	sort.Strings(a6)
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n  chain output {\n    type filter hook output priority filter; policy accept;\n", table)
	if len(a4) > 0 {
		fmt.Fprintf(&b, "    meta skuid %d ip daddr { %s } accept\n", uid, strings.Join(a4, ", "))
	}
	if len(a6) > 0 {
		fmt.Fprintf(&b, "    meta skuid %d ip6 daddr { %s } accept\n", uid, strings.Join(a6, ", "))
	}
	// Loopback: keep the few local services a core needs, drop the rest.
	ports := make([]int, 0, len(opt.LoopbackPorts))
	seen := map[int]bool{}
	for _, p := range opt.LoopbackPorts {
		if p > 0 && p < 65536 && !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	sort.Ints(ports)
	if len(ports) > 0 {
		list := make([]string, 0, len(ports))
		for _, p := range ports {
			list = append(list, strconv.Itoa(p))
		}
		set := strings.Join(list, ", ")
		fmt.Fprintf(&b, "    meta skuid %d ip daddr %s tcp dport { %s } accept\n", uid, loop4, set)
		fmt.Fprintf(&b, "    meta skuid %d ip daddr %s udp dport { %s } accept\n", uid, loop4, set)
		fmt.Fprintf(&b, "    meta skuid %d ip6 daddr %s tcp dport { %s } accept\n", uid, loop6, set)
		fmt.Fprintf(&b, "    meta skuid %d ip6 daddr %s udp dport { %s } accept\n", uid, loop6, set)
	}
	fmt.Fprintf(&b, "    meta skuid %d ct state new ip daddr { %s } drop\n", uid, strings.Join(append([]string{loop4}, blocked4...), ", "))
	fmt.Fprintf(&b, "    meta skuid %d ct state new ip6 daddr { %s } drop\n", uid, strings.Join(append([]string{loop6}, blocked6...), ", "))
	b.WriteString("  }\n}\n")
	return b.String()
}

// Apply installs the table for uid (uid < 0 removes it). Unchanged input
// is a no-op.
func (g *Guard) Apply(ctx context.Context, uid int, opt Options) error {
	script := Script(uid, opt)
	g.mu.Lock()
	same := script == g.applied
	g.mu.Unlock()
	if same {
		return nil
	}
	if !g.Supported() {
		g.set(Status{Supported: false, UID: uid, Allowed: len(opt.Allow), Error: "needs Linux with nft"})
		if script == "" {
			return nil
		}
		return fmt.Errorf("egressguard: needs Linux with nft")
	}
	var err error
	if script == "" {
		_, _ = g.run(ctx, "delete table inet "+table+"\n", "nft", "-f", "-") // a missing table is fine
	} else {
		if _, err = g.run(ctx, "delete table inet "+table+"\n"+script, "nft", "-f", "-"); err != nil {
			_, err = g.run(ctx, script, "nft", "-f", "-")
		}
	}
	st := Status{Supported: true, UID: uid, Allowed: len(opt.Allow), Loopback: len(opt.LoopbackPorts) > 0}
	if err != nil {
		st.Error = err.Error()
		g.set(st)
		return fmt.Errorf("egressguard: %w", err)
	}
	g.mu.Lock()
	g.applied = script
	g.status = st
	g.mu.Unlock()
	return nil
}

func (g *Guard) set(st Status) {
	g.mu.Lock()
	g.status = st
	g.mu.Unlock()
}

// ResolverAllow reads /etc/resolv.conf and returns the nameservers that
// fall inside the blocked ranges: on many cloud images the resolver is a
// private or link-local address (169.254.169.254, 100.100.2.136, the VPC
// .2 address), and dropping it would leave the cores unable to resolve
// anything at all.
func ResolverAllow(path string) []string {
	if path == "" {
		path = "/etc/resolv.conf"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(fields[1]))
		if ip == nil || ip.IsLoopback() || seen[ip.String()] {
			continue // loopback stubs are covered by the port exceptions
		}
		seen[ip.String()] = true
		if blockedIP(ip) {
			out = append(out, ip.String())
		}
	}
	return out
}

// blockedIP reports whether the address is inside a blocked range.
func blockedIP(ip net.IP) bool {
	for _, c := range append(append([]string{}, blocked4...), blocked6...) {
		if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}
