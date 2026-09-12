package local

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zeptop-dev/bosun/internal/authutil"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// ErrNotFound is returned for unknown tags and IDs.
var ErrNotFound = errors.New("not found")

// Store owns the state file and doubles as the local panel driver.
type Store struct {
	path string
	log  *slog.Logger

	mu sync.Mutex
	st State

	// changed wakes the agent after a mutation (panel.Notifier).
	changed chan struct{}
	// modes wakes the supervisor when the mode flips.
	modes chan Mode

	// runtime, not persisted
	nodeSeen, usersSeen, fwdSeen int64
	online                       map[string][]string
	host                         spec.SystemStatus
	cores                        map[string]agentproto.CoreStatus
	forwardStatus                []agentproto.ForwardStatus
	lastReport                   time.Time
	history                      []DayPoint
}

// DayPoint is one day's node-wide traffic, kept for the overview chart.
type DayPoint struct {
	Day  int64 `json:"day"` // unix seconds at UTC midnight
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// Open loads the state file, creating it with a fresh admin login when it
// does not exist. The generated password is returned once, for the log.
func Open(path string, log *slog.Logger) (*Store, string, error) {
	s := &Store{path: path, log: log.With("component", "local"), changed: make(chan struct{}, 1), modes: make(chan Mode, 1),
		online: map[string][]string{}, cores: map[string]agentproto.CoreStatus{}}
	raw, err := os.ReadFile(path)
	initial := ""
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &s.st); err != nil {
			return nil, "", fmt.Errorf("local: %s: %w", path, err)
		}
	case os.IsNotExist(err):
		initial = authutil.Password(16)
		hash, err := authutil.HashPassword(initial)
		if err != nil {
			return nil, "", err
		}
		s.st = State{Admin: Admin{Username: "admin", PasswordHash: hash}, Mode: ModeLocal}
		if err := s.saveLocked(); err != nil {
			return nil, "", err
		}
	default:
		return nil, "", err
	}
	if s.st.Mode == "" {
		s.st.Mode = ModeLocal
	}
	s.loadHistory()
	return s, initial, nil
}

func (s *Store) historyPath() string { return strings.TrimSuffix(s.path, ".json") + ".history.json" }

func (s *Store) loadHistory() {
	raw, err := os.ReadFile(s.historyPath())
	if err == nil {
		_ = json.Unmarshal(raw, &s.history)
	}
}

// saveLocked writes the state atomically. Callers hold s.mu.
func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(&s.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// commit bumps the revision, persists and wakes the agent. Callers hold s.mu.
func (s *Store) commit() error {
	s.st.Revision++
	if err := s.saveLocked(); err != nil {
		return err
	}
	select {
	case s.changed <- struct{}{}:
	default:
	}
	return nil
}

// Changed implements panel.Notifier.
func (s *Store) Changed() <-chan struct{} { return s.changed }

// ModeChanges delivers the new mode whenever Adopt or Detach flips it.
func (s *Store) ModeChanges() <-chan Mode { return s.modes }

// Mode returns the current mode and panel info.
func (s *Store) Mode() (Mode, *Managed, *Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var m *Managed
	if s.st.Managed != nil {
		c := *s.st.Managed
		m = &c
	}
	var snap *Snapshot
	if s.st.Snapshot != nil {
		snap = &Snapshot{TakenAt: s.st.Snapshot.TakenAt, Inbounds: append([]Inbound(nil), s.st.Snapshot.Inbounds...),
			Users: append([]User(nil), s.st.Snapshot.Users...), Forwards: append([]spec.Forward(nil), s.st.Snapshot.Forwards...)}
	}
	return s.st.Mode, m, snap
}

// ---- admin -----------------------------------------------------------------

// Login checks the admin credentials.
func (s *Store) Login(username, password string) bool {
	s.mu.Lock()
	a := s.st.Admin
	s.mu.Unlock()
	return username == a.Username && authutil.VerifyPassword(a.PasswordHash, password)
}

// Username returns the admin login name.
func (s *Store) Username() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Admin.Username
}

// SetAdmin changes the login; an empty password keeps the current one.
func (s *Store) SetAdmin(username, password string) error {
	if strings.TrimSpace(username) == "" {
		return errors.New("username is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Admin.Username = username
	if password != "" {
		if len(password) < 8 {
			return errors.New("password must be at least 8 characters")
		}
		h, err := authutil.HashPassword(password)
		if err != nil {
			return err
		}
		s.st.Admin.PasswordHash = h
	}
	return s.saveLocked()
}

// ---- settings --------------------------------------------------------------

// Settings returns node-wide settings.
func (s *Store) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Settings
}

// SetSettings replaces node-wide settings.
func (s *Store) SetSettings(v Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Settings = v
	return s.saveLocked()
}

// ---- inbounds --------------------------------------------------------------

// Inbounds returns a copy sorted by port.
func (s *Store) Inbounds() []Inbound {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]Inbound(nil), s.st.Inbounds...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// Inbound returns one inbound by tag.
func (s *Store) Inbound(tag string) (Inbound, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ib := range s.st.Inbounds {
		if ib.Tag == tag {
			return ib, true
		}
	}
	return Inbound{}, false
}

func validateInbound(ib *Inbound) error {
	ib.Tag = strings.TrimSpace(ib.Tag)
	if ib.Tag == "" {
		return errors.New("tag is required")
	}
	if strings.ContainsAny(ib.Tag, " /") {
		return errors.New("tag may not contain spaces or slashes")
	}
	if ib.Protocol == "" {
		return errors.New("protocol is required")
	}
	if ib.Port <= 0 || ib.Port > 65535 {
		return errors.New("port must be 1-65535")
	}
	if ib.Protocol == spec.Shadowsocks && ib.Cipher == "" {
		return errors.New("shadowsocks needs a cipher")
	}
	if ib.TLS != nil && ib.TLS.Mode == spec.TLSReality {
		if ib.TLS.Reality == nil || ib.TLS.Reality.PrivateKey == "" {
			return errors.New("reality needs a private key")
		}
	}
	// Scoped users are decided per pull from user.InboundTags, never stored.
	ib.ScopedUsers, ib.Users = false, nil
	return nil
}

// PutInbound creates or replaces an inbound. prevTag names the inbound being
// edited when its tag changes ("" for create).
func (s *Store) PutInbound(ib Inbound, prevTag string) error {
	if err := validateInbound(&ib); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, cur := range s.st.Inbounds {
		if cur.Tag == prevTag && prevTag != "" {
			idx = i
		}
		if cur.Tag == ib.Tag && cur.Tag != prevTag {
			return fmt.Errorf("tag %q already exists", ib.Tag)
		}
		if cur.Port == ib.Port && cur.Tag != prevTag && cur.Enabled && ib.Enabled && sameL4(cur.Protocol, ib.Protocol) {
			return fmt.Errorf("port %d is already used by %q", ib.Port, cur.Tag)
		}
	}
	if prevTag != "" && idx < 0 {
		return ErrNotFound
	}
	if idx < 0 {
		s.st.Inbounds = append(s.st.Inbounds, ib)
	} else {
		s.st.Inbounds[idx] = ib
		if prevTag != ib.Tag {
			for i := range s.st.Users {
				for j, t := range s.st.Users[i].InboundTags {
					if t == prevTag {
						s.st.Users[i].InboundTags[j] = ib.Tag
					}
				}
			}
		}
	}
	return s.commit()
}

// sameL4 reports whether two protocols would collide on one port: UDP-only
// protocols can share a port number with TCP ones.
func sameL4(a, b spec.Protocol) bool {
	udp := func(p spec.Protocol) bool { return p == spec.Hysteria2 || p == spec.TUIC }
	return udp(a) == udp(b)
}

// DeleteInbound removes an inbound and any user scoping that referenced it.
func (s *Store) DeleteInbound(tag string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, cur := range s.st.Inbounds {
		if cur.Tag == tag {
			idx = i
		}
	}
	if idx < 0 {
		return ErrNotFound
	}
	s.st.Inbounds = append(s.st.Inbounds[:idx], s.st.Inbounds[idx+1:]...)
	for i := range s.st.Users {
		var keep []string
		for _, t := range s.st.Users[i].InboundTags {
			if t != tag {
				keep = append(keep, t)
			}
		}
		s.st.Users[i].InboundTags = keep
	}
	return s.commit()
}

// ---- users -----------------------------------------------------------------

// ListUsers returns a copy sorted by ID.
func (s *Store) ListUsers() []User {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]User(nil), s.st.Users...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// User returns one user by ID.
func (s *Store) User(id int64) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.st.Users {
		if u.ID == id {
			return u, true
		}
	}
	return User{}, false
}

// UserBySubToken finds a user for the subscription endpoint.
func (s *Store) UserBySubToken(tok string) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.st.Users {
		if u.SubToken != "" && u.SubToken == tok {
			return u, true
		}
	}
	return User{}, false
}

// CreateUser adds a user, filling identity fields that are empty.
func (s *Store) CreateUser(u User) (User, error) {
	u.Name = strings.TrimSpace(u.Name)
	if u.Name == "" {
		return User{}, errors.New("name is required")
	}
	if u.UUID == "" {
		u.UUID = authutil.UUID()
	}
	if u.SubToken == "" {
		u.SubToken = authutil.Token(24)
	}
	u.CreatedAt = time.Now()
	u.Up, u.Down = 0, 0
	s.mu.Lock()
	defer s.mu.Unlock()
	var maxID int64
	for _, cur := range s.st.Users {
		if cur.ID > maxID {
			maxID = cur.ID
		}
		if cur.UUID == u.UUID {
			return User{}, errors.New("uuid already exists")
		}
	}
	u.ID = maxID + 1
	s.st.Users = append(s.st.Users, u)
	return u, s.commit()
}

// UpdateUser replaces editable fields, keeping accounting and identity that
// the caller left empty.
func (s *Store) UpdateUser(u User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, cur := range s.st.Users {
		if cur.ID != u.ID {
			continue
		}
		if strings.TrimSpace(u.Name) != "" {
			cur.Name = strings.TrimSpace(u.Name)
		}
		if u.UUID != "" {
			cur.UUID = u.UUID
		}
		cur.Password = u.Password
		cur.Enabled = u.Enabled
		cur.QuotaBytes = u.QuotaBytes
		cur.ExpiresAt = u.ExpiresAt
		cur.InboundTags = u.InboundTags
		s.st.Users[i] = cur
		return s.commit()
	}
	return ErrNotFound
}

// ResetTraffic zeroes a user's counters.
func (s *Store) ResetTraffic(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.st.Users {
		if s.st.Users[i].ID == id {
			s.st.Users[i].Up, s.st.Users[i].Down = 0, 0
			return s.commit()
		}
	}
	return ErrNotFound
}

// RotateSubToken invalidates the user's subscription link.
func (s *Store) RotateSubToken(id int64) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.st.Users {
		if s.st.Users[i].ID == id {
			s.st.Users[i].SubToken = authutil.Token(24)
			return s.st.Users[i].SubToken, s.saveLocked()
		}
	}
	return "", ErrNotFound
}

// DeleteUser removes a user.
func (s *Store) DeleteUser(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, cur := range s.st.Users {
		if cur.ID == id {
			s.st.Users = append(s.st.Users[:i], s.st.Users[i+1:]...)
			delete(s.online, cur.UUID)
			return s.commit()
		}
	}
	return ErrNotFound
}

// ---- forwards --------------------------------------------------------------

// ListForwards returns a copy.
func (s *Store) ListForwards() []spec.Forward {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]spec.Forward(nil), s.st.Forwards...)
}

// PutForward creates or replaces a relay rule by tag.
func (s *Store) PutForward(f spec.Forward, prevTag string) error {
	f.Tag = strings.TrimSpace(f.Tag)
	if f.Tag == "" {
		f.Tag = fmt.Sprintf("forward-%d", f.Port)
	}
	if f.Port <= 0 || f.Port > 65535 {
		return errors.New("port must be 1-65535")
	}
	if f.Protocol == "" {
		f.Protocol = "tcp"
	}
	if f.Protocol != "tcp" && f.Protocol != "udp" && f.Protocol != "both" {
		return errors.New("protocol must be tcp, udp or both")
	}
	if !strings.Contains(f.Target, ":") {
		return errors.New("target must be host:port")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, cur := range s.st.Forwards {
		if cur.Tag == prevTag && prevTag != "" {
			idx = i
		}
		if cur.Tag == f.Tag && cur.Tag != prevTag {
			return fmt.Errorf("tag %q already exists", f.Tag)
		}
	}
	if prevTag != "" && idx < 0 {
		return ErrNotFound
	}
	if idx < 0 {
		s.st.Forwards = append(s.st.Forwards, f)
	} else {
		s.st.Forwards[idx] = f
	}
	return s.commit()
}

// DeleteForward removes a rule.
func (s *Store) DeleteForward(tag string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, cur := range s.st.Forwards {
		if cur.Tag == tag {
			s.st.Forwards = append(s.st.Forwards[:i], s.st.Forwards[i+1:]...)
			return s.commit()
		}
	}
	return ErrNotFound
}

// ---- takeover --------------------------------------------------------------

// Adopt hands the node to a Captain panel: the local objects are snapshotted
// and the mode flips to managed. The caller has already verified pairing.
func (s *Store) Adopt(url string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Mode == ModeManaged {
		return errors.New("already managed")
	}
	s.st.Snapshot = &Snapshot{TakenAt: time.Now(), Inbounds: s.st.Inbounds, Users: s.st.Users, Forwards: s.st.Forwards}
	s.st.Inbounds, s.st.Users, s.st.Forwards = nil, nil, nil
	s.st.Mode = ModeManaged
	s.st.Managed = &Managed{URL: url, PairedAt: time.Now()}
	if err := s.commit(); err != nil {
		return err
	}
	s.notifyMode(ModeManaged)
	return nil
}

// Detach returns to local mode. With keep set, the last state the panel
// pushed becomes the local config; otherwise the pre-takeover snapshot is
// restored (or the node comes back empty when there is none).
func (s *Store) Detach(keep *agentproto.State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Mode != ModeManaged {
		return errors.New("not managed")
	}
	switch {
	case keep != nil:
		s.st.Inbounds, s.st.Users, s.st.Forwards = FromManaged(keep)
	case s.st.Snapshot != nil:
		s.st.Inbounds, s.st.Users, s.st.Forwards = s.st.Snapshot.Inbounds, s.st.Snapshot.Users, s.st.Snapshot.Forwards
	default:
		s.st.Inbounds, s.st.Users, s.st.Forwards = nil, nil, nil
	}
	s.st.Snapshot = nil
	s.st.Managed = nil
	s.st.Mode = ModeLocal
	if err := s.commit(); err != nil {
		return err
	}
	s.notifyMode(ModeLocal)
	return nil
}

func (s *Store) notifyMode(m Mode) {
	select {
	case s.modes <- m:
	default:
	}
}

// FromManaged converts a panel state into local objects.
func FromManaged(st *agentproto.State) ([]Inbound, []User, []spec.Forward) {
	var ibs []Inbound
	for _, ib := range st.Node.Inbounds {
		ib.ScopedUsers, ib.Users = false, nil
		ibs = append(ibs, Inbound{Inbound: ib, Enabled: true})
	}
	var users []User
	seen := map[string]bool{}
	add := func(u spec.User) {
		if seen[u.UUID] {
			return
		}
		seen[u.UUID] = true
		name := u.Name
		if name == "" || name == u.UUID {
			name = fmt.Sprintf("user-%d", u.ID)
		}
		pw := u.Password
		if pw == u.UUID {
			pw = ""
		}
		users = append(users, User{ID: int64(len(users) + 1), Name: name, UUID: u.UUID, Password: pw, SubToken: authutil.Token(24), Enabled: true, CreatedAt: time.Now()})
	}
	for _, u := range st.Users {
		add(u)
	}
	for _, ib := range st.Node.Inbounds {
		for _, u := range ib.Users {
			add(u)
		}
	}
	return ibs, users, append([]spec.Forward(nil), st.Forwards...)
}

// ---- panel.Driver ----------------------------------------------------------

// Name implements panel.Driver.
func (s *Store) Name() string { return "local" }

// Intervals implements panel.Driver. Pull is only a safety net because
// mutations wake the agent directly; push is short so the UI stays fresh.
func (s *Store) Intervals() spec.Intervals {
	return spec.Intervals{Pull: 5 * time.Minute, Push: 10 * time.Second}
}

// buildNode renders the local objects into a spec.Node. Callers hold s.mu.
func (s *Store) buildNode(now time.Time) (*spec.Node, []spec.User) {
	var usable []User
	for _, u := range s.st.Users {
		if u.Usable(now) {
			usable = append(usable, u)
		}
	}
	nodeUsers := make([]spec.User, 0, len(usable))
	for _, u := range usable {
		nodeUsers = append(nodeUsers, u.Spec())
	}
	node := &spec.Node{ID: "local", Forwards: append([]spec.Forward(nil), s.st.Forwards...)}
	if s.st.Settings.ACMEEmail != "" || s.st.Settings.CloudflareToken != "" {
		node.ACME = &spec.ACME{Email: s.st.Settings.ACMEEmail, CloudflareToken: s.st.Settings.CloudflareToken}
	}
	for _, ib := range s.st.Inbounds {
		if !ib.Enabled {
			continue
		}
		si := ib.Inbound
		var scoped []spec.User
		restricted := false
		for _, u := range usable {
			if len(u.InboundTags) == 0 {
				scoped = append(scoped, u.Spec())
				continue
			}
			restricted = true
			for _, t := range u.InboundTags {
				if t == ib.Tag {
					scoped = append(scoped, u.Spec())
					break
				}
			}
		}
		if restricted {
			si.ScopedUsers = true
			si.Users = scoped
			if si.Users == nil {
				si.Users = []spec.User{}
			}
		}
		node.Inbounds = append(node.Inbounds, si)
	}
	return node, nodeUsers
}

// Node implements panel.Driver.
func (s *Store) Node(ctx context.Context) (*spec.Node, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nodeSeen == s.st.Revision && s.nodeSeen != 0 {
		return nil, false, nil
	}
	s.nodeSeen = s.st.Revision
	node, _ := s.buildNode(time.Now())
	return node, true, nil
}

// Users implements panel.Driver.
func (s *Store) Users(ctx context.Context) ([]spec.User, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.usersSeen == s.st.Revision && s.usersSeen != 0 {
		return nil, false, nil
	}
	s.usersSeen = s.st.Revision
	_, users := s.buildNode(time.Now())
	return users, true, nil
}

// Forwards implements panel.ForwardSource.
func (s *Store) Forwards(ctx context.Context) ([]spec.Forward, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fwdSeen == s.st.Revision && s.fwdSeen != 0 {
		return nil, false, nil
	}
	s.fwdSeen = s.st.Revision
	return append([]spec.Forward{}, s.st.Forwards...), true, nil
}

// Report implements panel.Reporter: traffic lands on users, everything else
// is kept for the UI. Users that just crossed their quota trigger a re-pull.
func (s *Store) Report(ctx context.Context, rep agentproto.Report) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	byID := map[int64]int{}
	for i, u := range s.st.Users {
		byID[u.ID] = i
	}
	var dayUp, dayDown int64
	changed := false
	for _, t := range rep.Traffic {
		i, ok := byID[t.UserID]
		if !ok {
			continue
		}
		u := &s.st.Users[i]
		wasUsable := u.Usable(now)
		u.Up += t.Up
		u.Down += t.Down
		dayUp += t.Up
		dayDown += t.Down
		if wasUsable != u.Usable(now) {
			changed = true
		}
	}
	if dayUp+dayDown > 0 {
		s.addHistory(now, dayUp, dayDown)
	}
	s.online = rep.Online
	if s.online == nil {
		s.online = map[string][]string{}
	}
	s.host = rep.Host
	s.cores = rep.Cores
	s.forwardStatus = rep.Forwards
	s.lastReport = now
	if changed {
		return true, s.commit()
	}
	if len(rep.Traffic) > 0 {
		return false, s.saveLocked()
	}
	return false, nil
}

func (s *Store) addHistory(now time.Time, up, down int64) {
	day := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC).Unix()
	if n := len(s.history); n > 0 && s.history[n-1].Day == day {
		s.history[n-1].Up += up
		s.history[n-1].Down += down
	} else {
		s.history = append(s.history, DayPoint{Day: day, Up: up, Down: down})
		if len(s.history) > 30 {
			s.history = s.history[len(s.history)-30:]
		}
	}
	if raw, err := json.Marshal(s.history); err == nil {
		_ = os.WriteFile(s.historyPath(), raw, 0o600)
	}
}

// PushTraffic and PushStatus satisfy panel.Driver; the agent uses Report.
func (s *Store) PushTraffic(ctx context.Context, traffic []spec.UserTraffic) error {
	_, err := s.Report(ctx, agentproto.Report{Traffic: traffic})
	return err
}

// PushStatus satisfies panel.Driver.
func (s *Store) PushStatus(ctx context.Context, st spec.SystemStatus) error {
	s.mu.Lock()
	s.host = st
	s.mu.Unlock()
	return nil
}

// Runtime is what the UI shows about the running node.
type Runtime struct {
	Host       spec.SystemStatus                `json:"host"`
	Cores      map[string]agentproto.CoreStatus `json:"cores"`
	Forwards   []agentproto.ForwardStatus       `json:"forwards"`
	Online     map[string][]string              `json:"online"`
	LastReport time.Time                        `json:"last_report"`
	History    []DayPoint                       `json:"history"`
	Revision   int64                            `json:"revision"`
}

// Runtime returns the latest report data.
func (s *Store) Runtime() Runtime {
	s.mu.Lock()
	defer s.mu.Unlock()
	online := make(map[string][]string, len(s.online))
	for k, v := range s.online {
		online[k] = append([]string(nil), v...)
	}
	return Runtime{Host: s.host, Cores: s.cores, Forwards: append([]agentproto.ForwardStatus(nil), s.forwardStatus...),
		Online: online, LastReport: s.lastReport, History: append([]DayPoint(nil), s.history...), Revision: s.st.Revision}
}
