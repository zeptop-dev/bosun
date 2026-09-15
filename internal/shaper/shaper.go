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

func (s *Shaper) setStatus(st Status) { s.mu.Lock(); s.status = st; s.mu.Unlock() }
func (s *Shaper) setApplied(k string) { s.mu.Lock(); s.applied = k; s.mu.Unlock() }

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
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
	for _, dev := range []string{iface, ifbDev} {
		if _, err := s.run(ctx, "tc", "qdisc", "replace", "dev", dev, "root", "handle", "1:", "htb", "default", "0"); err != nil {
			return fmt.Errorf("shaper: %w", err)
		}
		for _, l := range limits {
			cls := "1:" + strconv.FormatInt(spec.SpeedClass(l.UserID), 16)
			rate := strconv.Itoa(l.Mbps) + "mbit"
			if _, err := s.run(ctx, "tc", "class", "replace", "dev", dev, "parent", "1:", "classid", cls, "htb", "rate", rate, "ceil", rate); err != nil {
				return fmt.Errorf("shaper: %w", err)
			}
			_, _ = s.run(ctx, "tc", "qdisc", "replace", "dev", dev, "parent", cls, "fq_codel")
			mark := "0x" + strconv.FormatInt(spec.SpeedMark(l.UserID), 16)
			if _, err := s.run(ctx, "tc", "filter", "replace", "dev", dev, "parent", "1:", "protocol", "all", "prio", "1", "handle", mark, "fw", "flowid", cls); err != nil {
				return fmt.Errorf("shaper: %w", err)
			}
		}
	}
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

// clear removes everything the shaper installed.
func (s *Shaper) clear(ctx context.Context) error {
	iface, err := s.iface(ctx)
	if err == nil {
		_, _ = s.run(ctx, "tc", "qdisc", "del", "dev", iface, "ingress")
		_, _ = s.run(ctx, "tc", "qdisc", "del", "dev", iface, "root")
	}
	_, _ = s.run(ctx, "ip", "link", "del", ifbDev)
	_ = s.runStdin(ctx, "delete table inet "+nftTable+"\n", "nft", "-f", "-")
	return nil
}
