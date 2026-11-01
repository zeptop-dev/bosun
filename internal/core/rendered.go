package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"io"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/zeptop-dev/bosun/internal/core/subprocess"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

const renderedLimit = 16384

type renderedPart struct {
	digest         [sha256.Size]byte
	files          int
	processes      map[string]uint64
	activatedAt    time.Time
	runtimeUpdates bool
}

// RenderedTracker remembers accepted activation files, never raw configuration
// or a dump of runtime memory. Its zero value is ready for use; do not copy it
// after first use. All methods are safe for concurrent use. Callers must keep
// supplied maps and file bytes immutable for the duration of a call.
//
// Invalidate before an apply attempt, Forget parts left unknown by a failed or
// partial mutation, and Activate only after a full activation succeeds. Hot
// runtime changes use RuntimeUpdate instead. Accept completes the entire known
// set; it cannot manufacture evidence for an absent or failed part.
type RenderedTracker struct {
	mu       sync.Mutex
	secret   [32]byte
	keyReady bool
	entropy  io.Reader // tests only; nil uses crypto/rand.Reader
	coreName string
	parts    map[string]renderedPart
	accepted bool
}

// Activate records the actual accepted bytes for one private adapter part.
// Invalid inputs erase that part's evidence. No input names or bytes appear in
// the exported artifact; only a process-local keyed digest can leave the tracker.
func (t *RenderedTracker) Activate(coreName, part string, files map[string][]byte, processes map[string]uint64, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.accepted = false
	at = at.UTC()
	if renderedFormat(coreName) == "" || part == "" || len(files) == 0 || len(files) > renderedLimit || !validRenderedProcesses(processes) || !validRenderedTime(at) || (t.coreName != "" && t.coreName != coreName) {
		delete(t.parts, part)
		return
	}
	for name, content := range files {
		if name == "" || len(content) == 0 {
			delete(t.parts, part)
			return
		}
	}
	// Bound retained state as well as the exported artifact. Counting private
	// bindings conservatively also bounds aliases shared by several parts.
	fileCount, bindingCount := len(files), len(processes)
	for name, old := range t.parts {
		if name != part {
			fileCount += old.files
			bindingCount += len(old.processes)
		}
	}
	if fileCount > renderedLimit || bindingCount > renderedLimit {
		delete(t.parts, part)
		return
	}
	if !t.keyReady {
		reader := t.entropy
		if reader == nil {
			reader = rand.Reader
		}
		var secret [32]byte
		if _, err := io.ReadFull(reader, secret[:]); err != nil {
			delete(t.parts, part)
			return
		}
		t.secret, t.keyReady = secret, true
	}
	if t.parts == nil {
		t.parts = make(map[string]renderedPart)
	}
	if _, exists := t.parts[part]; !exists && len(t.parts) >= renderedLimit {
		return
	}
	t.coreName = coreName
	h := hmac.New(sha256.New, t.secret[:])
	renderedField(h, []byte("bosun-rendered-part-v1"))
	renderedField(h, []byte(coreName))
	for _, name := range slices.Sorted(maps.Keys(files)) {
		renderedField(h, []byte(name))
		renderedField(h, files[name])
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	if old, ok := t.parts[part]; ok && old.digest == digest && maps.Equal(old.processes, processes) {
		// A no-op retry does not create a new activation or erase accepted hot
		// updates made after the original files were loaded.
		return
	}
	t.parts[part] = renderedPart{digest: digest, files: len(files), processes: maps.Clone(processes), activatedAt: at.UTC()}
}

// RuntimeUpdate marks a later accepted user/API/auth update outside the loaded
// files. Missing activation evidence remains missing; Accept must still verify
// the complete set before Snapshot may expose anything.
func (t *RenderedTracker) RuntimeUpdate(part string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.accepted = false
	if p, ok := t.parts[part]; ok {
		p.runtimeUpdates = true
		t.parts[part] = p
	}
}

func (t *RenderedTracker) Forget(part string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.accepted = false
	delete(t.parts, part)
}

// Invalidate suppresses output until the caller successfully accepts a known
// complete set. It does not discard untouched parts; Forget handles mutation
// failures that leave a part's activation identity unknown.
func (t *RenderedTracker) Invalidate() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.accepted = false
}

// Accept prunes removed parts and publishes only a complete, nonempty known
// activation set. An empty set clears evidence; the agent separately represents
// a successfully configured node with no active proxy cores.
func (t *RenderedTracker) Accept(parts []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.accepted = false
	if len(parts) > renderedLimit {
		return
	}
	wanted := make(map[string]bool, len(parts))
	for _, part := range parts {
		if part == "" || wanted[part] {
			return
		}
		wanted[part] = true
	}
	for part := range t.parts {
		if !wanted[part] {
			delete(t.parts, part)
		}
	}
	if len(wanted) == 0 || len(t.parts) != len(wanted) {
		return
	}
	t.accepted = true
}

// Snapshot returns an independent allowlisted DTO only while every accepted
// part belongs to exactly the observed process set. Once a mismatch is observed,
// stale evidence is removed and cannot reappear just by passing old identities.
func (t *RenderedTracker) Snapshot(coreName string, processes map[string]uint64) *agentproto.RenderedArtifact {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.accepted || !t.keyReady || coreName != t.coreName || len(t.parts) == 0 {
		return nil
	}
	expected := make(map[string]uint64)
	for part, p := range t.parts {
		for key, generation := range p.processes {
			if processes[key] != generation {
				delete(t.parts, part)
				t.accepted = false
				break
			}
			if prior := expected[key]; prior != 0 && prior != generation {
				t.accepted = false
			}
			expected[key] = generation
		}
	}
	if !t.accepted || !validRenderedProcesses(processes) || !maps.Equal(expected, processes) {
		t.accepted = false
		return nil
	}
	h := hmac.New(sha256.New, t.secret[:])
	renderedField(h, []byte("bosun-rendered-artifact-v1"))
	renderedField(h, []byte(coreName))
	a := &agentproto.RenderedArtifact{Core: coreName, DigestScope: "process", Scope: "activation_files", Format: renderedFormat(coreName)}
	for _, part := range slices.Sorted(maps.Keys(t.parts)) {
		p := t.parts[part]
		renderedField(h, []byte(part))
		renderedField(h, p.digest[:])
		a.Files += p.files
		a.RuntimeUpdates = a.RuntimeUpdates || p.runtimeUpdates
		if a.ActivatedAt.IsZero() || p.activatedAt.Before(a.ActivatedAt) {
			a.ActivatedAt = p.activatedAt
		}
	}
	unique := make(map[uint64]bool, len(processes))
	for _, generation := range processes {
		unique[generation] = true
	}
	a.Processes = len(unique)
	a.Digest = "rcf1-" + hex.EncodeToString(h.Sum(nil))
	if agentproto.ValidateRenderedConfigReport(&agentproto.RenderedConfigReport{Version: 1, Status: "observed", Artifacts: []agentproto.RenderedArtifact{*a}}) != nil {
		t.accepted = false
		return nil
	}
	return a
}

func renderedField(h hash.Hash, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(value)
}

func renderedFormat(name string) string {
	switch name {
	case "xray", "singbox", "singbox-extended", "mita":
		return "json"
	case "hysteria":
		return "yaml"
	case "snell":
		return "ini"
	default:
		return ""
	}
}

func validRenderedTime(at time.Time) bool {
	// Keep this check aligned with agentproto's accepted observation timestamps.
	return !at.IsZero() && at.Year() >= 2000 && at.Year() <= 9999
}

func validRenderedProcesses(processes map[string]uint64) bool {
	if len(processes) == 0 || len(processes) > renderedLimit {
		return false
	}
	for name, generation := range processes {
		if name == "" || generation == 0 {
			return false
		}
	}
	return true
}

// RenderedProcesses observes only adapter-owned children. Re-reading both the
// listener mapping and supervisor generations rejects replacement races. This
// is a best-effort observation, not a process lifetime lock.
func RenderedProcesses(c Core) map[string]uint64 {
	owner, ok := c.(ListenerProcesses)
	if !ok {
		return nil
	}
	return renderedProcesses(owner.ListenerPIDs, subprocess.ActiveGenerations)
}

func renderedProcesses(pids func() map[string]int, generations func() map[int]uint64) map[string]uint64 {
	first := maps.Clone(pids())
	processes := renderedProcessSet(first, generations)
	if processes == nil || !maps.Equal(first, pids()) {
		return nil
	}
	last := renderedProcessSet(first, generations)
	if !maps.Equal(processes, last) || !maps.Equal(first, pids()) {
		return nil
	}
	return processes
}

// RenderedProcessSet is for adapters already holding their own instance lock.
// The caller supplies a stable private tag-to-PID map; no PID is exported.
func RenderedProcessSet(pids map[string]int) map[string]uint64 {
	return renderedProcessSet(pids, subprocess.ActiveGenerations)
}

func renderedProcessSet(pids map[string]int, generations func() map[int]uint64) map[string]uint64 {
	if len(pids) == 0 || len(pids) > renderedLimit {
		return nil
	}
	before := generations()
	result := make(map[string]uint64, len(pids))
	for name, pid := range pids {
		if name == "" || pid <= 0 || before[pid] == 0 {
			return nil
		}
		result[name] = before[pid]
	}
	after := generations()
	for name, pid := range pids {
		if after[pid] != result[name] {
			return nil
		}
	}
	return result
}
