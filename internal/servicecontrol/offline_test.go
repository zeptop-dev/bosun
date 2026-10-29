package servicecontrol

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func offlineFixture(t *testing.T) (*Offline, *spec.ServiceControl, *spec.Resources, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	n := spec.NetworkResource{Name: "eth0", ID: "boot:1", Included: true, Up: 1000, Down: 1000}
	p := &spec.OfflineServiceControl{PolicyID: "policy-one", Cycle: 1, Action: "limit", ThresholdPercent: 80, LimitMbps: 10, QuotaBytes: 1000, Direction: "sum", AutoResume: true, ManualMode: "normal", PeriodStart: now.Add(-time.Hour).Unix(), PeriodEnds: []int64{now.Add(time.Hour).Unix(), now.Add(48 * time.Hour).Unix()}, Anchor: spec.OfflineTrafficAnchor{Epoch: "sampler", Sequence: 1, At: now.Unix(), UsedUp: 300, UsedDown: 300, Networks: []spec.NetworkResource{n}}}
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return &Offline{Dir: dir}, &spec.ServiceControl{Revision: "command", Mode: "normal", Offline: p}, &spec.Resources{Epoch: "sampler", Sequence: 1, At: now.UnixMilli(), Networks: []spec.NetworkResource{n}}, now
}
func nextSample(r *spec.Resources, at time.Time, up, down uint64) {
	r.Sequence++
	r.At = at.UnixMilli()
	r.Networks[0].Up += up
	r.Networks[0].Down += down
}
func TestOfflineTrafficDisconnectedCrossesThresholdAndRestarts(t *testing.T) {
	o, c, r, now := offlineFixture(t)
	if got, err := o.Resolve(c, r, now); err != nil || got.Mode != "normal" {
		t.Fatal(got, err)
	}
	now = now.Add(15 * time.Second)
	nextSample(r, now, 100, 100)
	got, err := o.Resolve(c, r, now)
	if err != nil || got.Mode != "limit" || got.LimitMbps != 10 || !o.Report().Automatic {
		t.Fatal(got, err, o.Report())
	}
	// New evaluator and sampler process, unchanged boot/interface cumulative counters.
	o = &Offline{Dir: o.Dir}
	r.Epoch = "restarted"
	r.Sequence = 1
	now = now.Add(15 * time.Second)
	r.At = now.UnixMilli()
	got, err = o.Resolve(c, r, now)
	if err != nil || got.Mode != "limit" {
		t.Fatal(got, err)
	}
}
func TestOfflineTrafficPeriodPreservesManualAndExpiresExemption(t *testing.T) {
	for _, manual := range []string{"normal", "limit", "pause"} {
		t.Run(manual, func(t *testing.T) {
			o, c, r, now := offlineFixture(t)
			c.Offline.PeriodEnds[0] = now.Add(20 * time.Second).Unix()
			c.Offline.Automatic = true
			c.Offline.ManualMode = manual
			if manual == "limit" {
				c.Offline.ManualLimitMbps = 5
			}
			if _, err := o.Resolve(c, r, now); err != nil {
				t.Fatal(err)
			}
			now = now.Add(30 * time.Second)
			nextSample(r, now, 10, 10)
			got, err := o.Resolve(c, r, now)
			if err != nil || got.Mode != manual || o.Report().Automatic || o.Report().Cycle != 2 {
				t.Fatal(got, err, o.Report())
			}
		})
	}
	o, c, r, now := offlineFixture(t)
	c.Offline.Exempt = true
	c.Offline.PeriodEnds[0] = now.Add(20 * time.Second).Unix()
	c.Offline.Anchor.UsedUp = 900
	if got, err := o.Resolve(c, r, now); err != nil || got.Mode != "normal" {
		t.Fatal(got, err)
	}
	now = now.Add(30 * time.Second)
	nextSample(r, now, 800, 0)
	got, err := o.Resolve(c, r, now)
	if err != nil || got.Mode != "limit" || o.Report().Cycle != 2 {
		t.Fatal(got, err)
	}
}
func TestOfflineTrafficMissingEvidenceNeverReleases(t *testing.T) {
	cases := map[string]func(*spec.Resources, *time.Time){
		"boot changed":      func(r *spec.Resources, _ *time.Time) { r.Networks[0].ID = "new-boot:1" },
		"counter reset":     func(r *spec.Resources, _ *time.Time) { r.Networks[0].Up = 0 },
		"interface removed": func(r *spec.Resources, _ *time.Time) { r.Networks = nil },
		"stale sample":      func(_ *spec.Resources, n *time.Time) { *n = n.Add(time.Minute) },
		"missing boundary":  func(r *spec.Resources, n *time.Time) { *n = n.Add(2 * time.Hour); r.At = n.UnixMilli() },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			o, c, r, now := offlineFixture(t)
			c.Offline.Automatic = true
			if _, err := o.Resolve(c, r, now); err != nil {
				t.Fatal(err)
			}
			change(r, &now)
			got, err := o.Resolve(c, r, now)
			if err == nil || got.Mode != "pause" {
				t.Fatal("unknown evidence reopened traffic", got, err)
			}
		})
	}
}
func TestOfflineTrafficReinstallCorruptionAndPersistenceFailure(t *testing.T) {
	o, c, r, now := offlineFixture(t)
	now = now.Add(4 * time.Minute)
	r.At = now.UnixMilli()
	if got, err := o.Resolve(c, r, now); err == nil || got.Mode != "pause" {
		t.Fatal("stale anchor after reinstall", got, err)
	}
	o, c, r, now = offlineFixture(t)
	if err := os.WriteFile(filepath.Join(o.Dir, "offline-traffic.json"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := o.Resolve(c, r, now); err == nil || got.Mode != "pause" {
		t.Fatal("corrupt journal", got, err)
	}
	o, c, r, now = offlineFixture(t)
	o.Dir = filepath.Join(o.Dir, "not-dir")
	if err := os.WriteFile(o.Dir, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := o.Resolve(c, r, now); err == nil || got.Mode != "pause" {
		t.Fatal("failed journal save", got, err)
	}
}
func TestOfflineTrafficManualHoldAndRefresh(t *testing.T) {
	o, c, r, now := offlineFixture(t)
	c.Offline.ManualMode = "pause"
	if got, err := o.Resolve(c, r, now); err != nil || got.Mode != "pause" {
		t.Fatal(got, err)
	}
	c.Offline.PolicyID = "new-policy"
	c.Offline.ManualMode = "normal"
	c.Offline.Automatic = true
	if got, err := o.Resolve(c, r, now); err != nil || got.Mode != "limit" {
		t.Fatal(got, err)
	}
	// A later same-policy panel anchor cannot clear the node's autonomous hold.
	now = now.Add(15 * time.Second)
	nextSample(r, now, 1, 1)
	c.Offline.Anchor.At = now.Unix()
	c.Offline.Anchor.Sequence = r.Sequence
	c.Offline.Anchor.Networks = append([]spec.NetworkResource(nil), r.Networks...)
	c.Offline.Automatic = false
	if got, err := o.Resolve(c, r, now); err != nil || got.Mode != "limit" {
		t.Fatal(got, err)
	}
}

func TestOfflineTrafficNoAutoResumeRetainsHoldAcrossPeriod(t *testing.T) {
	o, c, r, now := offlineFixture(t)
	c.Offline.AutoResume = false
	c.Offline.Automatic = true
	c.Offline.PeriodEnds[0] = now.Add(20 * time.Second).Unix()
	if _, err := o.Resolve(c, r, now); err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Second)
	nextSample(r, now, 0, 0)
	if got, err := o.Resolve(c, r, now); err != nil || got.Mode != "limit" || !o.Report().Automatic || o.Report().UsedBytes != 0 {
		t.Fatal(got, err, o.Report())
	}
}
func TestOfflineTrafficDisableRecoversCorruptJournalExplicitly(t *testing.T) {
	o, c, r, now := offlineFixture(t)
	if err := os.WriteFile(o.path(), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Resolve(c, r, now); err == nil {
		t.Fatal("corrupt journal was accepted")
	}
	if err := o.Disable(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(o.path()); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if got, err := o.Resolve(c, r, now); err != nil || got.Mode != "normal" {
		t.Fatal(got, err)
	}
}

func TestOfflineTrafficRecoveryCannotReplaceNewerJournal(t *testing.T) {
	o, c, r, now := offlineFixture(t)
	c.Offline.ManualMode = "pause"
	if _, err := o.Resolve(c, r, now); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(o.path())
	if err != nil {
		t.Fatal(err)
	}
	for _, cached := range []*spec.ServiceControl{nil, {Revision: "cached", Mode: "normal"}, {Revision: "cached", Mode: "normal", Offline: &spec.OfflineServiceControl{PolicyID: "older-policy"}}} {
		restarted := &Offline{Dir: o.Dir}
		if got, err := restarted.RecoveryGuard(cached); err == nil || got.Mode != "pause" {
			t.Fatal("cached state relaxed newer journal", got, err)
		}
		after, err := os.ReadFile(o.path())
		if err != nil || string(after) != string(before) {
			t.Fatal("recovery changed journal", err)
		}
	}
	for _, change := range []string{"manual", "exemption"} {
		cached := *c
		cp := *c.Offline
		cached.Offline = &cp
		cached.Revision = "older-command"
		if change == "manual" {
			cp.ManualMode = "normal"
		} else {
			cp.Exempt = true
		}
		restarted := &Offline{Dir: o.Dir}
		if got, err := restarted.RecoveryGuard(&cached); err == nil || got.Mode != "pause" {
			t.Fatal("same policy stale command relaxed protection", change, got, err)
		}
	}
	restarted := &Offline{Dir: o.Dir}
	if got, err := restarted.RecoveryGuard(c); err != nil || got != c {
		t.Fatal(got, err)
	}
	if err := os.Remove(o.path()); err != nil {
		t.Fatal(err)
	}
	restarted = &Offline{Dir: o.Dir}
	if got, err := restarted.RecoveryGuard(c); err == nil || got.Mode != "pause" {
		t.Fatal("lost journal treated as fresh cached anchor", got, err)
	}
}
