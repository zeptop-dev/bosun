package forward

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// nftables backend: kernel-path DNAT for rules with Backend "nft". The
// whole table is regenerated on every apply so the ruleset always mirrors
// the desired set; bosun never touches other tables.

const nftTable = "bosun_fwd"

// nftTarget is a rule's target resolved to a literal address.
type nftTarget struct {
	IP   string
	Port int
}

// resolveNFT preserves the IPv4 preference for dual-stack hostnames.
// An explicit listen address selects its address family instead.
func resolveNFT(ctx context.Context, target string) (nftTarget, error) {
	return resolveNFTFamily(ctx, target, "")
}

func resolveNFTFamily(ctx context.Context, target, listen string) (nftTarget, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nftTarget{}, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nftTarget{}, fmt.Errorf("bad target port %q", portStr)
	}
	if ip := net.ParseIP(host); ip != nil {
		if err := (spec.Forward{Backend: "nft", Listen: listen, Target: target}).ValidateTargets(); err != nil {
			return nftTarget{}, err
		}
		return nftTarget{IP: ip.String(), Port: port}, nil
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	network := "ip"
	if listen != "" {
		network = "ip4"
		if spec.IsIPv6(listen) {
			network = "ip6"
		}
	}
	ips, err := net.DefaultResolver.LookupIP(rctx, network, host)
	if err != nil || len(ips) == 0 {
		return nftTarget{}, fmt.Errorf("target %s has no usable %s address", host, network)
	}
	if network == "ip" {
		for _, ip := range ips {
			if ip.To4() != nil {
				return nftTarget{IP: ip.String(), Port: port}, nil
			}
		}
	}
	return nftTarget{IP: ips[0].String(), Port: port}, nil
}

// renderNFT builds the nft script for the given rules (already resolved).
// Rules are emitted sorted by tag so the text is stable.
func renderNFT(rules []spec.Forward, targets map[string]nftTarget) string {
	sorted := append([]spec.Forward(nil), rules...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Tag < sorted[j].Tag })
	var pre, post []string
	for _, f := range sorted {
		t, ok := targets[f.Tag]
		if !ok {
			continue
		}
		family := "ip"
		if spec.IsIPv6(t.IP) {
			family = "ip6"
		}
		match := ""
		if ip := net.ParseIP(f.Listen); ip != nil {
			if (ip.To4() == nil) != spec.IsIPv6(t.IP) {
				continue
			}
			if !ip.IsUnspecified() {
				match = family + " daddr " + ip.String() + " "
			}
		}
		for _, p := range protocols(f) {
			pre = append(pre, fmt.Sprintf("\t\t%s%s dport %d dnat %s to %s comment \"%s\"", match, p, f.Port, family, net.JoinHostPort(t.IP, strconv.Itoa(t.Port)), f.Tag))
			if !f.PreserveSource {
				post = append(post, fmt.Sprintf("\t\t%s daddr %s %s dport %d masquerade comment \"%s\"", family, t.IP, p, t.Port, f.Tag))
			}
		}
	}
	var b strings.Builder
	// "table" creates it when missing so the delete below never fails.
	fmt.Fprintf(&b, "table inet %s\n", nftTable)
	fmt.Fprintf(&b, "delete table inet %s\n", nftTable)
	if len(pre) == 0 {
		return b.String()
	}
	fmt.Fprintf(&b, "table inet %s {\n", nftTable)
	b.WriteString("\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n")
	for _, l := range pre {
		b.WriteString(l + "\n")
	}
	b.WriteString("\t}\n")
	b.WriteString("\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
	for _, l := range post {
		b.WriteString(l + "\n")
	}
	b.WriteString("\t}\n")
	b.WriteString("\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n\t\tct status dnat accept\n\t}\n")
	b.WriteString("}\n")
	return b.String()
}

// nftRun feeds a script to `nft -f -`.
var nftRun = func(ctx context.Context, script string) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return errors.New("nftables not installed")
	}
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft: %s", strings.TrimSpace(out.String()))
	}
	return nil
}

// enableForwarding turns on IPv4 forwarding; failures only warn since the
// operator may manage sysctl elsewhere.
var enableForwarding = func(ctx context.Context) error {
	if _, err := exec.LookPath("sysctl"); err != nil {
		return err
	}
	return exec.CommandContext(ctx, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1").Run()
}

// Preserve hosts that learn their IPv6 default route via router advertisements:
// Linux otherwise stops accepting RA when forwarding becomes enabled.
var enableIPv6Forwarding = func(ctx context.Context) error {
	paths, err := filepath.Glob("/proc/sys/net/ipv6/conf/*/accept_ra")
	if err != nil {
		return err
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(raw)) == "1" {
			if err := os.WriteFile(path, []byte("2\n"), 0644); err != nil {
				return err
			}
		}
	}
	return exec.CommandContext(ctx, "sysctl", "-q", "-w", "net.ipv6.conf.all.forwarding=1").Run()
}

// applyNFT installs the table for the rules (or removes it when empty) and
// reports the per-rule outcome. An incomplete installation or cleanup must
// also fail the enclosing apply, including when no rules remain to report.
func (m *Manager) applyNFT(ctx context.Context, rules []spec.Forward) error {
	targets := map[string]nftTarget{}
	errs := map[string]error{}
	for _, f := range rules {
		t, err := resolveNFTFamily(ctx, f.Target, f.Listen)
		if err != nil {
			errs[f.Tag] = err
			continue
		}
		targets[f.Tag] = t
	}
	script := renderNFT(rules, targets)
	var applyErr error
	if len(rules) == 0 {
		if m.nftApplied != "" {
			applyErr = nftRun(ctx, script)
			if applyErr == nil {
				m.nftApplied = ""
			}
		}
	} else if script != m.nftApplied {
		if err := enableForwarding(ctx); err != nil {
			m.log.Warn("could not enable ip_forward", "err", err)
		}
		for _, target := range targets {
			if spec.IsIPv6(target.IP) {
				if err := enableIPv6Forwarding(ctx); err != nil {
					m.log.Warn("could not enable IPv6 forwarding", "err", err)
				}
				break
			}
		}
		applyErr = nftRun(ctx, script)
		if applyErr == nil {
			m.nftApplied = script
			m.log.Info("nftables forwards applied", "rules", len(targets))
		} else {
			m.log.Error("nftables apply failed", "err", applyErr)
		}
	}
	for _, r := range m.rules {
		if r.spec.Backend != "nft" {
			continue
		}
		var problem error
		switch {
		case errs[r.spec.Tag] != nil:
			problem = errs[r.spec.Tag]
		case applyErr != nil:
			problem = applyErr
		}
		resolved := ""
		if target, ok := targets[r.spec.Tag]; ok {
			resolved = net.JoinHostPort(target.IP, strconv.Itoa(target.Port))
		}
		r.setBackendTarget(problem, resolved)
	}
	problems := []error{applyErr}
	for _, f := range rules {
		if err := errs[f.Tag]; err != nil {
			problems = append(problems, fmt.Errorf("forward %q: %w", f.Tag, err))
		}
	}
	return errors.Join(problems...)
}
