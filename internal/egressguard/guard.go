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
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Status is what the doctor shows.
type Status struct {
	Supported bool   `json:"supported"`
	UID       int    `json:"uid"`
	Allowed   int    `json:"allowed"`
	Error     string `json:"error,omitempty"`
}

const table = "bosun_egress"

// Blocked ranges; loopback is deliberately absent.
var (
	blocked4 = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16"}
	blocked6 = []string{"fc00::/7", "fe80::/10"}
)

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

// Script renders the nft script for uid; allow lists cidrs (sorted, so the
// text is stable) that stay reachable. uid < 0 renders nothing.
func Script(uid int, allow []string) string {
	if uid < 0 {
		return ""
	}
	var a4, a6 []string
	for _, c := range allow {
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
	fmt.Fprintf(&b, "    meta skuid %d ct state new ip daddr { %s } drop\n", uid, strings.Join(blocked4, ", "))
	fmt.Fprintf(&b, "    meta skuid %d ct state new ip6 daddr { %s } drop\n", uid, strings.Join(blocked6, ", "))
	b.WriteString("  }\n}\n")
	return b.String()
}

// Apply installs the table for uid (uid < 0 removes it). Unchanged input
// is a no-op.
func (g *Guard) Apply(ctx context.Context, uid int, allow []string) error {
	script := Script(uid, allow)
	g.mu.Lock()
	same := script == g.applied
	g.mu.Unlock()
	if same {
		return nil
	}
	if !g.Supported() {
		g.set(Status{Supported: false, UID: uid, Allowed: len(allow), Error: "needs Linux with nft"})
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
	st := Status{Supported: true, UID: uid, Allowed: len(allow)}
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
