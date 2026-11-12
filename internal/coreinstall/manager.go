package coreinstall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"

	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Manager separates cached packages from active runtime selections. The
// caller serializes lifecycle changes with the agent's apply/report loop.
type Manager struct {
	Install *Installer
	Factory func(distribution, binary, workDir string) (core.Core, error)
	AutoPin map[string]bool // configured without an explicit version or binary; set before use
	op      sync.Mutex
	mu      sync.Mutex
	path    string
	state   selections
	initial map[string]spec.CoreInstance
}

type selections struct {
	Defaults map[string]string `json:"defaults,omitempty"`
	Order    []string          `json:"order,omitempty"`
	Last     *spec.CoreRequest `json:"last,omitempty"`
	Revision uint64            `json:"revision"`
	Versions map[string]string `json:"versions"`
}

func NewManager(i *Installer, initial map[string]spec.CoreInstance) (*Manager, error) {
	m := &Manager{Install: i, path: filepath.Join(i.Root, "active.json"), initial: initial, state: selections{Revision: 1, Versions: map[string]string{}}}
	f, err := os.OpenFile(m.path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() || info.Size() > 16<<10 {
		return nil, errors.New("invalid core selection file")
	}
	if err := json.NewDecoder(io.LimitReader(f, 16<<10)).Decode(&m.state); err != nil {
		return nil, err
	}
	if m.state.Revision == 0 || m.state.Versions == nil {
		return nil, errors.New("invalid core selection state")
	}
	for name, version := range m.state.Defaults {
		if (spec.CoreRequest{Action: "activate", Distribution: name, Version: version}).Validate() != nil {
			return nil, errors.New("invalid persisted default core selection")
		}
	}
	for name, version := range m.state.Versions {
		if (spec.CoreRequest{Action: "activate", Distribution: name, Version: version}).Validate() != nil {
			return nil, errors.New("invalid persisted core selection")
		}
		if _, ok := Resolve(name, version); !ok {
			return nil, fmt.Errorf("persisted core %s %s is no longer in the catalog", name, version)
		}
	}
	seen := map[string]bool{}
	for _, name := range m.state.Order {
		if seen[name] || (spec.CoreRequest{Action: "download", Distribution: name, Version: "1"}).Validate() != nil {
			return nil, errors.New("invalid persisted core order")
		}
		seen[name] = true
	}
	return m, nil
}

func (m *Manager) TryLock() bool { return m.op.TryLock() }
func (m *Manager) Unlock()       { m.op.Unlock() }

func (m *Manager) Selected() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.selectedLocked()
}
func (m *Manager) selectedLocked() map[string]string {
	out := map[string]string{}
	for name, version := range m.state.Defaults {
		if rel, ok := Resolve(name, version); m.AutoPin[name] && ok && rel.Status != StatusBroken {
			out[name] = version
		}
	}
	for name, version := range m.state.Versions {
		out[name] = version
	}
	return out
}

func (m *Manager) Inventory() *spec.CoreInventory {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := &spec.CoreInventory{Revision: m.state.Revision, Packages: []spec.CorePackage{}, Instances: []spec.CoreInstance{}}
	for _, name := range Cores() {
		if (spec.CoreRequest{Action: "download", Distribution: name, Version: "1"}).Validate() != nil {
			continue
		}
		for _, rel := range Releases(name) {
			_, platform := rel.Assets[m.Install.platform()]
			out.Packages = append(out.Packages, spec.CorePackage{Distribution: name, Family: spec.CoreFamily(name), Version: rel.Version, Status: string(rel.Status), Note: rel.Note, Installed: m.Install.Installed(name, rel.Version), Available: platform || rel.Build != nil})
		}
	}
	instances := map[string]spec.CoreInstance{}
	for k, v := range m.initial {
		instances[k] = v
	}
	for k, v := range m.selectedLocked() {
		instances[k] = spec.CoreInstance{Distribution: k, Version: v}
	}
	for _, v := range instances {
		out.Instances = append(out.Instances, v)
	}
	sort.Slice(out.Instances, func(i, j int) bool { return out.Instances[i].Distribution < out.Instances[j].Distribution })
	return out
}

func (m *Manager) Validate(r spec.CoreRequest) (Release, error) {
	if err := r.Validate(); err != nil {
		return Release{}, err
	}
	rel, ok := Resolve(r.Distribution, r.Version)
	if !ok || rel.Version != r.Version {
		return Release{}, errors.New("version is not in this node's catalog")
	}
	if rel.Status == StatusBroken {
		return Release{}, errors.New("this core version is marked broken")
	}
	if r.Action == "activate" {
		m.mu.Lock()
		defer m.mu.Unlock()
		if r.Revision != m.state.Revision {
			return Release{}, errors.New("core selection changed; refresh and try again")
		}
		if m.initial[r.Distribution].External {
			return Release{}, errors.New("config.yaml pins an external binary; remove that pin before using core management")
		}
		if !m.Install.Installed(r.Distribution, r.Version) {
			return Release{}, errors.New("download this version before activating it")
		}
	}
	return rel, nil
}

func (m *Manager) Download(ctx context.Context, r spec.CoreRequest) error {
	rel, err := m.Validate(r)
	if err != nil {
		return err
	}
	_, err = m.Install.Ensure(ctx, rel.Core, rel.Version)
	return err
}

// Commit runs only after the new process is healthy. A failed durable write
// leaves the prior selection in memory and on disk so the caller can roll back.
func (m *Manager) Commit(r spec.CoreRequest, order []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.Revision != m.state.Revision {
		return errors.New("core selection changed")
	}
	next := selections{Defaults: m.state.Defaults, Revision: m.state.Revision + 1, Versions: map[string]string{}, Order: append([]string(nil), order...), Last: &r}
	found := false
	for _, name := range next.Order {
		if name == r.Distribution {
			found = true
		}
	}
	if !found {
		next.Order = append(next.Order, r.Distribution)
	}
	for k, v := range m.state.Versions {
		next.Versions[k] = v
	}
	next.Versions[r.Distribution] = r.Version
	return m.save(next)
}

// save requires m.mu; disk publication precedes the in-memory selection.
func (m *Manager) save(next selections) error {
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(m.Install.Root, 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(m.Install.Root, ".active-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), m.path); err != nil {
		return err
	}
	m.state = next
	return nil
}

func (m *Manager) AlreadyApplied(r spec.CoreRequest) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.Last != nil && *m.state.Last == r
}

// Order preserves the preference order across restarts, including instances
// appended by the UI after an installation whose YAML enabled fewer cores.
func (m *Manager) Order(defaults []string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]string(nil), m.state.Order...)
	for _, name := range defaults {
		found := false
		for _, n := range out {
			if n == name {
				found = true
			}
		}
		if !found {
			out = append(out, name)
		}
	}
	return out
}

// RememberInitial pins a successfully started configured version. A later agent
// upgrade must not silently select a different catalog default. Manual selections
// and explicit external binaries remain authoritative.
func (m *Manager) RememberInitial(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.AutoPin[name] || m.state.Versions[name] != "" || m.selectedLocked()[name] != "" || m.initial[name].External {
		return nil
	}
	version := m.initial[name].Version
	if version == "" {
		return nil
	}
	next := selections{Revision: m.state.Revision + 1, Order: append([]string(nil), m.state.Order...), Last: m.state.Last, Versions: m.state.Versions, Defaults: map[string]string{}}
	for k, v := range m.state.Defaults {
		next.Defaults[k] = v
	}
	next.Defaults[name] = version
	return m.save(next)
}

// ExplicitSelection distinguishes administrator activation from remembered
// defaults, so remembering a version does not relocate its existing runtime data.
func (m *Manager) ExplicitSelection(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.Versions[name] != ""
}
