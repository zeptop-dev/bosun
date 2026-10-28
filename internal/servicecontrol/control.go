// Package servicecontrol isolates the host's managed proxy traffic from its
// control plane. It owns one nft table; it never changes routes, qdiscs, user
// firewall tables, or the SSH/bosun account's unmarked sockets.
package servicecontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

const table = "bosun_service_control"

// Scope identifies kernel forwards that do not have a socket owner. NFT
// entries store the original destination, never the remote target. This also
// matches replies and established NAT mappings after the NAT rule is removed.
type Scope struct {
	Forwards   []spec.Forward `json:"forwards,omitempty"`
	Interfaces []string       `json:"interfaces,omitempty"`
}

// Manager is serialized with proxy/forward applies. Run replaces nft execution
// for tests; production paths require root, nft and an isolated non-root UID.
type Manager struct {
	Dir          string
	Run          func(context.Context, []string, string) ([]byte, error)
	mu           sync.Mutex
	scope        Scope
	loaded       bool
	installed    string
	fingerprint  string
	normalSynced bool
	status       agentproto.ServiceControlReport
}

func (m *Manager) run(ctx context.Context, args []string, stdin string) ([]byte, error) {
	if m.Run != nil {
		return m.Run(ctx, args, stdin)
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "nft", args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nft service control: %w: %.512s", err, strings.TrimSpace(out.String()))
	}
	if out.Len() > 4<<20 {
		return nil, errors.New("nft ruleset exceeds service control inspection limit")
	}
	return out.Bytes(), nil
}

func (m *Manager) Status() agentproto.ServiceControlReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

func (m *Manager) prerequisites(ctx context.Context, uid int, monitor bool) error {
	if monitor {
		return errors.New("service control requires full server mode")
	}
	if uid <= 0 {
		return errors.New("service control requires a dedicated non-root proxy account")
	}
	if m.Run == nil {
		if runtime.GOOS != "linux" || os.Geteuid() != 0 {
			return errors.New("service control requires Linux root")
		}
		if _, err := exec.LookPath("nft"); err != nil {
			return errors.New("service control requires nftables")
		}
	}
	// A host flowtable can bypass the forward hook after the first packet.
	// Never advertise complete enforcement when such an offload path exists.
	out, err := m.run(ctx, []string{"-j", "list", "ruleset"}, "")
	if err != nil {
		return err
	}
	var doc struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return fmt.Errorf("inspect nft service control: %w", err)
	}
	for _, obj := range doc.NFTables {
		if _, ok := obj["flowtable"]; ok {
			return errors.New("service control is incompatible with host nft flowtable offload")
		}
	}
	// A dry-run also tests kernel named byte-limit support and CAP_NET_ADMIN.
	_, err = m.run(ctx, []string{"-c", "-f", "-"}, render(uid, Scope{}, &spec.ServiceControl{Mode: spec.ServiceControlLimit, LimitMbps: 1}, "capability"))
	return err
}

// Apply verifies support and reconciles the table. Repeated identical input
// retains the token bucket, but verifies the table's policy digest. Scope is
// retained while controlled so old DNAT conntrack entries cannot escape after
// a simultaneous topology edit. Only normal mode releases those old scopes.
func (m *Manager) Apply(ctx context.Context, desired *spec.ServiceControl, uid int, monitor bool, scope Scope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	mode := spec.ServiceControlNormal
	if desired != nil {
		mode = desired.Mode
		m.status.DesiredRevision = desired.Revision
	} else {
		m.status.DesiredRevision = ""
	}
	m.status.AppliedRevision = ""
	m.status.CheckedAt = time.Now().Unix()
	m.status.Error = ""
	fail := func(err error) error { m.status.Error = err.Error(); return err }
	if err := desired.Validate(); err != nil {
		return fail(err)
	}
	if err := validateScope(scope); err != nil {
		return fail(err)
	}
	supportedErr := m.prerequisites(ctx, uid, monitor)
	m.status.Supported = supportedErr == nil
	m.status.Reason = ""
	if supportedErr != nil {
		m.status.Reason = supportedErr.Error()
	}
	if mode != spec.ServiceControlNormal && supportedErr != nil {
		return fail(supportedErr)
	}
	// Capability detection is observational for legacy/uncontrolled nodes.
	// A root container may have nft but lack CAP_NET_ADMIN; that must not stop
	// existing proxies. An ownership journal or prior installed policy, however,
	// is evidence that failing to remove a guard must be reported as an error.
	_, journalErr := os.Stat(filepath.Join(m.Dir, "service-control-owned.json"))
	hasHistory := m.Dir != "" && !errors.Is(journalErr, os.ErrNotExist) || m.installed != ""
	if mode == spec.ServiceControlNormal && (!hasHistory || m.normalSynced) {
		m.status.Mode = mode
		m.status.LimitMbps = 0
		if desired != nil {
			m.status.AppliedRevision = desired.Revision
		}
		return nil
	}
	usable := m.Run != nil || runtime.GOOS == "linux" && os.Geteuid() == 0
	if m.Run == nil {
		_, err := exec.LookPath("nft")
		usable = usable && err == nil
	}
	if !usable {
		return fail(errors.New("cannot remove existing service control guard: Linux root and nftables are required"))
	}
	if mode == spec.ServiceControlNormal {
		if _, err := m.run(ctx, []string{"-f", "-"}, "table inet "+table+"\ndelete table inet "+table+"\n"); err != nil {
			return fail(err)
		}
		if err := clearScope(m.Dir); err != nil {
			return fail(err)
		}
		m.scope = Scope{}
		m.installed = ""
		m.fingerprint = ""
		m.normalSynced = true
		m.status.Mode = mode
		m.status.LimitMbps = 0
	} else {
		if !m.loaded {
			var err error
			m.scope, err = readScope(m.Dir)
			if err != nil {
				return fail(err)
			}
			m.loaded = true
		}
		merged := mergeScope(m.scope, scope)
		// Persist ownership before creating rules. No credentials/remote targets
		// are retained. A restart can still cover an old established NAT mapping.
		if err := saveScope(m.Dir, merged); err != nil {
			return fail(err)
		}
		m.scope = merged
		script := render(uid, merged, desired, "")
		sum := sha256.Sum256([]byte(script))
		digest := hex.EncodeToString(sum[:])
		found := false
		if m.installed == digest {
			raw, err := m.run(ctx, []string{"-j", "list", "table", "inet", table}, "")
			if err == nil {
				found = m.fingerprint != "" && rulesFingerprint(raw) == m.fingerprint
			}
		}
		if !found {
			if _, err := m.run(ctx, []string{"-f", "-"}, render(uid, merged, desired, digest)); err != nil {
				return fail(err)
			}
		}
		raw, err := m.run(ctx, []string{"-j", "list", "table", "inet", table}, "")
		if err != nil {
			return fail(err)
		}
		fingerprint := rulesFingerprint(raw)
		if fingerprint == "" {
			return fail(errors.New("cannot verify installed service control rules"))
		}
		if found && fingerprint != m.fingerprint {
			return fail(errors.New("service control rules changed during verification"))
		}
		m.fingerprint = fingerprint
		m.normalSynced = false
		m.installed = digest
		m.status.Mode = mode
		m.status.LimitMbps = desired.LimitMbps
	}
	if desired != nil {
		m.status.AppliedRevision = desired.Revision
	}
	return nil
}

// nft includes dynamic counter values and runtime handles. Compare every
// other table/chain/rule/limit expression so flushing a chain or changing one
// matcher cannot be mistaken for a complete policy just because a comment stayed.
func rulesFingerprint(raw []byte) string {
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return ""
	}
	entries, ok := doc["nftables"].([]any)
	if !ok || len(entries) == 0 {
		return ""
	}
	var normalized []any
	for _, entry := range entries {
		obj, ok := entry.(map[string]any)
		if !ok {
			return ""
		}
		if _, meta := obj["metainfo"]; meta {
			continue
		}
		normalized = append(normalized, normalizeNFT(obj, ""))
	}
	if len(normalized) == 0 {
		return ""
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
func normalizeNFT(v any, parent string) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, value := range x {
			if k == "handle" || parent == "counter" && (k == "packets" || k == "bytes") {
				continue
			}
			out[k] = normalizeNFT(value, k)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, value := range x {
			out[i] = normalizeNFT(value, parent)
		}
		return out
	default:
		return v
	}
}

func validateScope(s Scope) error {
	if len(s.Forwards) > 4096 || len(s.Interfaces) > 128 {
		return errors.New("service control scope is too large")
	}
	for _, f := range s.Forwards {
		if f.Backend != "nft" || !spec.ValidListen(f.Listen) || f.Port < 1 || f.Port > 65535 || (f.Protocol != "tcp" && f.Protocol != "udp" && f.Protocol != "both") {
			return errors.New("invalid service control forward scope")
		}
	}
	for _, dev := range s.Interfaces {
		if !strings.HasPrefix(dev, "bwg") {
			return errors.New("invalid service control interface")
		}
		n, err := strconv.Atoi(strings.TrimPrefix(dev, "bwg"))
		if err != nil || n < 1 || n > 16383 || dev != "bwg"+strconv.Itoa(n) {
			return errors.New("invalid service control interface")
		}
	}
	return nil
}

func mergeScope(a, b Scope) Scope {
	fs := map[string]spec.Forward{}
	ds := map[string]bool{}
	for _, s := range []Scope{a, b} {
		for _, f := range s.Forwards {
			f = spec.Forward{Listen: f.Listen, Port: f.Port, Protocol: f.Protocol, Backend: "nft"}
			fs[fmt.Sprintf("%s/%d/%s", f.Listen, f.Port, f.Protocol)] = f
		}
		for _, d := range s.Interfaces {
			ds[d] = true
		}
	}
	keys := make([]string, 0, len(fs))
	for k := range fs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := Scope{}
	for _, k := range keys {
		out.Forwards = append(out.Forwards, fs[k])
	}
	for d := range ds {
		out.Interfaces = append(out.Interfaces, d)
	}
	sort.Strings(out.Interfaces)
	return out
}

func render(uid int, scope Scope, c *spec.ServiceControl, digest string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\ntable inet %s {\n", table, table, table)
	if digest != "" {
		fmt.Fprintf(&b, "comment %q\n", digest)
	}
	if c.Mode == spec.ServiceControlLimit {
		fmt.Fprintf(&b, "limit aggregate { rate over %d bytes/second burst 65536 bytes; }\n", int64(c.LimitMbps)*125000)
	}
	b.WriteString("chain controlled {\n")
	if c.Mode == spec.ServiceControlPause {
		b.WriteString("counter drop\n")
	} else {
		b.WriteString("limit name aggregate counter drop\nreturn\n")
	}
	b.WriteString("}\n")
	b.WriteString("chain output { type filter hook output priority -5; policy accept;\noifname \"lo\" return\n")
	// goto avoids counting twice if a socket matches more than one classifier.
	fmt.Fprintf(&b, "meta skuid %d goto controlled\nmeta mark %d goto controlled\n}\n", uid, spec.ServiceControlSocketMark)
	b.WriteString("chain forward { type filter hook forward priority -5; policy accept;\n")
	for _, d := range scope.Interfaces {
		fmt.Fprintf(&b, "iifname %q goto controlled\noifname %q goto controlled\n", d, d)
	}
	for _, f := range scope.Forwards {
		for _, p := range []string{"tcp", "udp"} {
			if f.Protocol != "both" && f.Protocol != p {
				continue
			}
			match := "ct status dnat meta l4proto " + p + " ct original proto-dst " + strconv.Itoa(f.Port)
			if f.Listen != "" && f.Listen != "0.0.0.0" && f.Listen != "::" {
				family := "ip"
				if spec.IsIPv6(f.Listen) {
					family = "ip6"
				}
				match += " ct original " + family + " daddr " + f.Listen
			} else if f.Listen == "::" {
				match += " meta nfproto ipv6"
			} else {
				match += " meta nfproto ipv4"
			}
			fmt.Fprintf(&b, "%s goto controlled\n", match)
		}
	}
	b.WriteString("}\n}\n")
	return b.String()
}
