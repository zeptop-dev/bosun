package servicecontrol

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Offline is owned by the serial agent loop. Every accepted meter transition
// is durable before its result can remove or strengthen a service guard.
type Offline struct {
	Dir    string
	state  *offlineState
	report *agentproto.OfflineControlReport
}
type offlineState struct {
	Version         int                    `json:"version"`
	PolicyID        string                 `json:"policy_id"`
	CommandRevision string                 `json:"command_revision"`
	Cycle           int64                  `json:"cycle"`
	PeriodStart     int64                  `json:"period_start"`
	Up              int64                  `json:"up"`
	Down            int64                  `json:"down"`
	At              int64                  `json:"at"`
	Epoch           string                 `json:"epoch"`
	Sequence        uint64                 `json:"sequence"`
	Networks        []spec.NetworkResource `json:"networks"`
	Automatic       bool                   `json:"automatic"`
}

func (o *Offline) Report() *agentproto.OfflineControlReport {
	if o.report == nil {
		return nil
	}
	r := *o.report
	return &r
}
func (o *Offline) path() string { return filepath.Join(o.Dir, "offline-traffic.json") }
func (o *Offline) read() error {
	f, err := os.OpenFile(o.path(), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || !ownedByProcess(st) || st.Size() > 1<<20 {
		return errors.New("invalid offline traffic journal")
	}
	var s offlineState
	dec := json.NewDecoder(io.LimitReader(f, 1<<20))
	if err = dec.Decode(&s); err != nil {
		return errors.New("unreadable offline traffic journal")
	}
	var extra any
	if err = dec.Decode(&extra); err != io.EOF {
		return errors.New("invalid offline traffic journal tail")
	}
	if s.Version != 1 || s.CommandRevision == "" || s.PolicyID == "" || s.Cycle < 1 || s.PeriodStart <= 0 || s.At < s.PeriodStart || s.Epoch == "" || s.Sequence == 0 || s.Up < 0 || s.Down < 0 || len(s.Networks) == 0 || len(s.Networks) > 256 {
		return errors.New("invalid offline traffic journal")
	}
	names := map[string]bool{}
	for _, n := range s.Networks {
		if !n.Included || n.Name == "" || n.ID == "" || names[n.Name] {
			return errors.New("invalid offline traffic journal counters")
		}
		names[n.Name] = true
	}
	o.state = &s
	return nil
}
func (o *Offline) save(s *offlineState) error {
	if o.Dir == "" {
		return errors.New("offline traffic journal directory is required")
	}
	if err := os.MkdirAll(o.Dir, 0700); err != nil {
		return err
	}
	st, err := os.Lstat(o.Dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 || !ownedByProcess(st) {
		return errors.New("unsafe offline traffic directory")
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(o.Dir, ".offline-traffic-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil {
		return err
	}
	if ce != nil {
		return ce
	}
	if err = os.Rename(f.Name(), o.path()); err != nil {
		return err
	}
	d, err := os.Open(o.Dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func anchorState(p *spec.OfflineServiceControl) *offlineState {
	return &offlineState{Version: 1, PolicyID: p.PolicyID, Cycle: p.Cycle, PeriodStart: p.PeriodStart, Up: p.Anchor.UsedUp, Down: p.Anchor.UsedDown, At: p.Anchor.At, Epoch: p.Anchor.Epoch, Sequence: p.Anchor.Sequence, Networks: p.Anchor.Networks, Automatic: p.Automatic}
}
func charged(up, down int64, mode string) int64 {
	switch mode {
	case "up":
		return up
	case "down":
		return down
	case "max":
		return max(up, down)
	}
	if down > math.MaxInt64-up {
		return math.MaxInt64
	}
	return up + down
}
func addBytes(v int64, d uint64) int64 {
	if d > uint64(math.MaxInt64-v) {
		return math.MaxInt64
	}
	return v + int64(d)
}
func selectedNetworks(r *spec.Resources) []spec.NetworkResource {
	var out []spec.NetworkResource
	if r != nil {
		for _, n := range r.Networks {
			if n.Included {
				n.UpRate = nil
				n.DownRate = nil
				out = append(out, n)
			}
		}
	}
	return out
}
func meterDelta(old, next []spec.NetworkResource) (up, down uint64, err error) {
	if len(old) == 0 || len(next) != len(old) {
		return 0, 0, errors.New("traffic interface selection changed or is unavailable")
	}
	prev := map[string]spec.NetworkResource{}
	for _, n := range old {
		prev[n.Name] = n
	}
	seen := map[string]bool{}
	for _, n := range next {
		p, ok := prev[n.Name]
		if !ok || seen[n.Name] || n.ID == "" || n.ID != p.ID || n.Up < p.Up || n.Down < p.Down {
			return 0, 0, errors.New("traffic counter identity changed or reset")
		}
		seen[n.Name] = true
		du, dd := n.Up-p.Up, n.Down-p.Down
		if du > math.MaxUint64-up || dd > math.MaxUint64-down {
			return 0, 0, errors.New("traffic counter overflow")
		}
		up += du
		down += dd
	}
	return
}

// RecoveryGuard prevents a stale cached state from retiring or replacing a newer
// durable protection policy. Only a fresh panel state can resolve that conflict.
func (o *Offline) RecoveryGuard(desired *spec.ServiceControl) (*spec.ServiceControl, error) {
	fail := func(err error) (*spec.ServiceControl, error) {
		out := spec.ServiceControl{Revision: "offline-recovery", Mode: spec.ServiceControlPause}
		if desired != nil {
			out.Revision = desired.Revision
		}
		o.report = &agentproto.OfflineControlReport{State: "error", Error: err.Error()}
		if o.state != nil {
			o.report.PolicyID = o.state.PolicyID
			o.report.Cycle = o.state.Cycle
		}
		return &out, err
	}
	if o.Dir == "" {
		return fail(errors.New("offline traffic journal directory is required"))
	}
	if o.state == nil {
		if err := o.read(); err != nil {
			return fail(err)
		}
	}
	if desired == nil || desired.Offline == nil {
		if o.state != nil {
			return fail(errors.New("cached state cannot disable a saved offline traffic policy"))
		}
		return desired, nil
	}
	if o.state == nil || o.state.PolicyID != desired.Offline.PolicyID || o.state.CommandRevision != desired.Revision {
		return fail(errors.New("cached state does not match the saved offline traffic policy"))
	}
	return desired, nil
}

// Disable retires only our own journal after an authoritative disabled policy.
func (o *Offline) Disable() error {
	if o.Dir == "" {
		return errors.New("offline traffic journal directory is required")
	}
	o.state = nil
	o.report = nil
	st, err := os.Lstat(o.path())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !ownedByProcess(st) || st.IsDir() {
		return errors.New("invalid offline traffic journal ownership")
	}
	if err = os.Remove(o.path()); err != nil {
		return err
	}
	d, err := os.Open(o.Dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (o *Offline) Resolve(desired *spec.ServiceControl, r *spec.Resources, now time.Time) (*spec.ServiceControl, error) {
	if desired == nil || desired.Offline == nil {
		o.report = nil
		return desired, nil
	}
	p := desired.Offline
	out := *desired
	out.Offline = nil
	o.report = &agentproto.OfflineControlReport{PolicyID: p.PolicyID, Cycle: p.Cycle, PeriodStart: p.PeriodStart, State: "waiting"}
	fail := func(err error) (*spec.ServiceControl, error) {
		out.Mode = spec.ServiceControlPause
		out.LimitMbps = 0
		o.report.State = "error"
		o.report.Error = err.Error()
		return &out, err
	}
	if o.Dir == "" {
		return fail(errors.New("offline traffic journal directory is required"))
	}
	if err := p.Validate(); err != nil {
		return fail(err)
	}
	if o.state == nil {
		if err := o.read(); err != nil {
			return fail(err)
		}
	}
	// An explicit new policy replaces the old one, but only from a current meter
	// anchor. A stale cached command after reinstall cannot authorize reopening.
	s := o.state
	if s == nil || s.PolicyID != p.PolicyID {
		if p.Anchor.At > now.Unix()+5 || now.Unix()-p.Anchor.At > 180 {
			return fail(errors.New("waiting for a fresh authenticated traffic anchor"))
		}
		s = anchorState(p)
	} else {
		cp := *s
		s = &cp
		// A current server anchor can repair missing local observations. Same-policy
		// refreshes never erase a locally triggered hold in the same period.
		if p.Cycle >= s.Cycle && p.Anchor.At > s.At && r != nil && p.Anchor.Epoch == r.Epoch && p.Anchor.Sequence <= r.Sequence {
			hold := s.Automatic && (p.Cycle == s.Cycle || !p.AutoResume)
			s = anchorState(p)
			s.Automatic = s.Automatic || hold
		}
	}
	if r == nil || r.Epoch == "" || r.Sequence == 0 || r.At <= 0 || r.At > now.Add(5*time.Second).UnixMilli() || now.UnixMilli()-r.At > 45000 {
		return fail(errors.New("fresh local traffic counters are unavailable"))
	}
	at := r.At / 1000
	if at < s.At-5 {
		return fail(errors.New("local traffic clock moved backwards"))
	}
	if r.Epoch == s.Epoch && r.Sequence < s.Sequence {
		return fail(errors.New("local traffic sequence moved backwards"))
	}
	nets := selectedNetworks(r)
	du, dd, err := meterDelta(s.Networks, nets)
	if err != nil {
		return fail(err)
	}
	if r.Epoch == s.Epoch && r.Sequence == s.Sequence && (du != 0 || dd != 0) {
		return fail(errors.New("traffic sample identity was reused"))
	}
	end := int64(0)
	for _, v := range p.PeriodEnds {
		if v > s.PeriodStart {
			end = v
			break
		}
	}
	if end == 0 {
		return fail(errors.New("traffic period schedule expired"))
	}
	if at >= end {
		// Only a short uninterrupted crossing proves a fresh cycle. Missing an
		// entire boundary never turns unknown usage into zero or releases a hold.
		if s.At >= end || at-s.At > 45 || s.At < end-45 {
			return fail(errors.New("traffic period boundary was not observed"))
		}
		s.PeriodStart = end
		s.Cycle++
		s.Up = 0
		s.Down = 0
		if p.AutoResume {
			s.Automatic = false
		}
	}
	s.Up = addBytes(s.Up, du)
	s.Down = addBytes(s.Down, dd)
	s.At = max(at, s.At)
	s.Epoch = r.Epoch
	s.Sequence = r.Sequence
	s.Networks = nets
	used := charged(s.Up, s.Down, p.Direction)
	exempt := p.Exempt && s.Cycle == p.Cycle
	threshold := p.QuotaBytes/100*int64(p.ThresholdPercent) + (p.QuotaBytes%100*int64(p.ThresholdPercent)+99)/100
	if !exempt && used >= threshold {
		s.Automatic = true
	}
	if exempt {
		s.Automatic = false
	}
	out.Mode = p.ManualMode
	out.LimitMbps = p.ManualLimitMbps
	if s.Automatic {
		if p.Action == "pause" {
			out.Mode = "pause"
			out.LimitMbps = 0
		} else if out.Mode != "pause" && (out.Mode == "normal" || p.LimitMbps < out.LimitMbps) {
			out.Mode = "limit"
			out.LimitMbps = p.LimitMbps
		}
	}
	s.CommandRevision = desired.Revision
	if err = o.save(s); err != nil {
		return fail(fmt.Errorf("persist offline traffic: %w", err))
	}
	o.state = s
	o.report = &agentproto.OfflineControlReport{PolicyID: p.PolicyID, Cycle: s.Cycle, PeriodStart: s.PeriodStart, UsedBytes: used, Automatic: s.Automatic, State: "ready"}
	if s.Automatic {
		o.report.State = "active"
	}
	return &out, nil
}
