// Package firewall opens the ports bosun listens on in the host firewall
// when one of the common front ends (ufw, firewalld) is active, and closes
// the ones it opened earlier once they are gone. Raw nftables/iptables
// policies are left alone: the doctor warns about those instead. bosun
// never disables a firewall.
package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Port is one listener to allow.
type Port struct {
	Proto string `json:"proto"` // "tcp" or "udp"
	Port  int    `json:"port"`
}

func (p Port) String() string { return strconv.Itoa(p.Port) + "/" + p.Proto }

// Status is what the doctor shows.
type Status struct {
	Kind   string `json:"kind"` // "ufw", "firewalld" or "" (none detected)
	Opened int    `json:"opened"`
	Error  string `json:"error,omitempty"`
}

// Manager keeps the set of ports it opened in StateFile so a later apply
// (or a restart) can close what is no longer needed.
type Manager struct {
	StateFile string
	// Run overrides command execution (tests).
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)

	mu     sync.Mutex
	opened map[string]bool // "port/proto"
	loaded bool
	status Status
}

func (m *Manager) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if m.Run != nil {
		return m.Run(ctx, name, args...)
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return out.Bytes(), nil
}

// Detect reports which front end is active: ufw when "Status: active",
// firewalld when firewall-cmd says running. "" when neither.
func (m *Manager) Detect(ctx context.Context) string {
	if m.Run == nil && runtime.GOOS != "linux" {
		return ""
	}
	if m.Run != nil || lookPath("ufw") {
		if out, err := m.run(ctx, "ufw", "status"); err == nil && strings.Contains(string(out), "Status: active") {
			return "ufw"
		}
	}
	if m.Run != nil || lookPath("firewall-cmd") {
		if out, err := m.run(ctx, "firewall-cmd", "--state"); err == nil && strings.Contains(string(out), "running") {
			return "firewalld"
		}
	}
	return ""
}

func lookPath(name string) bool { _, err := exec.LookPath(name); return err == nil }

// Status returns the last known state.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

func (m *Manager) load() {
	if m.loaded {
		return
	}
	m.loaded = true
	m.opened = map[string]bool{}
	if m.StateFile == "" {
		return
	}
	b, err := os.ReadFile(m.StateFile)
	if err != nil {
		return
	}
	var list []string
	if json.Unmarshal(b, &list) == nil {
		for _, s := range list {
			m.opened[s] = true
		}
	}
}

func (m *Manager) save() {
	if m.StateFile == "" {
		return
	}
	list := make([]string, 0, len(m.opened))
	for k := range m.opened {
		list = append(list, k)
	}
	sort.Strings(list)
	b, _ := json.Marshal(list)
	_ = os.WriteFile(m.StateFile, b, 0o600)
}

// Apply allows exactly these ports: new ones are opened, ones bosun opened
// before and no longer needs are closed. Ports the operator opened by hand
// are never closed (only entries in the state file are).
func (m *Manager) Apply(ctx context.Context, ports []Port) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	kind := m.Detect(ctx)
	if kind == "" {
		m.status = Status{Kind: "", Opened: len(m.opened)}
		return nil
	}
	want := map[string]bool{}
	for _, p := range ports {
		if p.Port > 0 && (p.Proto == "tcp" || p.Proto == "udp") {
			want[p.String()] = true
		}
	}
	var firstErr error
	changed := false
	for k := range want {
		if m.opened[k] {
			continue
		}
		if err := m.allow(ctx, kind, k, true); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		m.opened[k] = true
		changed = true
	}
	for k := range m.opened {
		if want[k] {
			continue
		}
		if err := m.allow(ctx, kind, k, false); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		delete(m.opened, k)
		changed = true
	}
	if changed && kind == "firewalld" {
		if _, err := m.run(ctx, "firewall-cmd", "--reload"); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if changed {
		m.save()
	}
	m.status = Status{Kind: kind, Opened: len(m.opened)}
	if firstErr != nil {
		m.status.Error = firstErr.Error()
	}
	return firstErr
}

func (m *Manager) allow(ctx context.Context, kind, portProto string, open bool) error {
	var err error
	switch kind {
	case "ufw":
		if open {
			_, err = m.run(ctx, "ufw", "allow", portProto)
		} else {
			_, err = m.run(ctx, "ufw", "delete", "allow", portProto)
		}
	case "firewalld":
		if open {
			_, err = m.run(ctx, "firewall-cmd", "--permanent", "--add-port="+portProto)
		} else {
			_, err = m.run(ctx, "firewall-cmd", "--permanent", "--remove-port="+portProto)
		}
	}
	return err
}
