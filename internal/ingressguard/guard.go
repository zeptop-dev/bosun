// Package ingressguard enforces a bind address for cores that cannot bind
// one themselves. mita listens on every address; when its inbound sits
// behind a line ingress with a local address, packets arriving for the
// same port on any other address are dropped by an nftables input rule
// (nobrand's "strict ingress" fallback):
//
//	table inet bosun_ingress { chain input { type filter hook input priority filter; policy accept;
//	  ip daddr != 10.10.0.2 tcp dport 17701 drop
//	} }
//
// bosun owns only that table; nothing else in the ruleset is touched.
package ingressguard

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

// Rule keeps one port reachable only through IP.
type Rule struct {
	IP    string
	Proto string // "tcp" or "udp"
	Port  int
}

// Status is what the doctor shows.
type Status struct {
	Supported bool   `json:"supported"`
	Rules     int    `json:"rules"`
	Error     string `json:"error,omitempty"`
}

const table = "bosun_ingress"

// Guard installs the table and keeps it in step with the desired rules.
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

// Script renders the nft script for the rules (sorted, so the text is
// stable); empty rules render a delete-only script.
func Script(rules []Rule) string {
	sorted := append([]Rule(nil), rules...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].IP != sorted[j].IP {
			return sorted[i].IP < sorted[j].IP
		}
		if sorted[i].Port != sorted[j].Port {
			return sorted[i].Port < sorted[j].Port
		}
		return sorted[i].Proto < sorted[j].Proto
	})
	var b strings.Builder
	b.WriteString("table inet " + table + " {\n  chain input {\n    type filter hook input priority filter; policy accept;\n")
	for _, r := range sorted {
		fam := "ip"
		if ip := net.ParseIP(r.IP); ip != nil && ip.To4() == nil {
			fam = "ip6"
		}
		fmt.Fprintf(&b, "    %s daddr != %s %s dport %d drop\n", fam, r.IP, r.Proto, r.Port)
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

// Apply installs exactly these rules (none removes the table). Unchanged
// input is a no-op.
func (g *Guard) Apply(ctx context.Context, rules []Rule) error {
	script := ""
	if len(rules) > 0 {
		script = Script(rules)
	}
	g.mu.Lock()
	same := script == g.applied
	g.mu.Unlock()
	if same {
		return nil
	}
	if !g.Supported() {
		g.set(Status{Supported: false, Rules: len(rules), Error: "needs Linux with nft"})
		if len(rules) == 0 {
			return nil
		}
		return fmt.Errorf("ingressguard: needs Linux with nft")
	}
	var err error
	if script == "" {
		_, err = g.run(ctx, "delete table inet "+table+"\n", "nft", "-f", "-")
		err = nil // a missing table is fine
	} else {
		// Replace atomically: delete + create in one transaction; on an
		// older nft the delete of a missing table fails, so retry plain.
		if _, err = g.run(ctx, "delete table inet "+table+"\n"+script, "nft", "-f", "-"); err != nil {
			_, err = g.run(ctx, script, "nft", "-f", "-")
		}
	}
	st := Status{Supported: true, Rules: len(rules)}
	if err != nil {
		st.Error = err.Error()
		g.set(st)
		return fmt.Errorf("ingressguard: %w", err)
	}
	g.mu.Lock()
	g.applied = script
	g.status = st
	g.mu.Unlock()
	return nil
}

func (g *Guard) set(st Status) { g.mu.Lock(); g.status = st; g.mu.Unlock() }
