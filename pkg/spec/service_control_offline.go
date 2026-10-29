package spec

import "errors"

// OfflineServiceControl is an optional, authenticated snapshot of host metering.
// It never changes subscriber accounting. PeriodEnds are absolute boundaries
// computed by the panel, preserving its timezone and month-end billing rules.
type OfflineServiceControl struct {
	PolicyID         string               `json:"policy_id"`
	Cycle            int64                `json:"cycle"`
	Action           string               `json:"action"`
	ThresholdPercent int                  `json:"threshold_percent"`
	LimitMbps        int                  `json:"limit_mbps"`
	QuotaBytes       int64                `json:"quota_bytes"`
	Direction        string               `json:"direction"`
	AutoResume       bool                 `json:"auto_resume"`
	Automatic        bool                 `json:"automatic"`
	Exempt           bool                 `json:"exempt"`
	ManualMode       string               `json:"manual_mode"`
	ManualLimitMbps  int                  `json:"manual_limit_mbps"`
	PeriodStart      int64                `json:"period_start"`
	PeriodEnds       []int64              `json:"period_ends"`
	Anchor           OfflineTrafficAnchor `json:"anchor"`
}

type OfflineTrafficAnchor struct {
	Epoch    string            `json:"epoch"`
	Sequence uint64            `json:"sequence"`
	At       int64             `json:"at"` // panel receipt time, seconds
	UsedUp   int64             `json:"used_up"`
	UsedDown int64             `json:"used_down"`
	Networks []NetworkResource `json:"networks"`
}

func (p *OfflineServiceControl) Validate() error {
	if p == nil {
		return nil
	}
	bad := func() error { return errors.New("invalid offline server traffic policy") }
	if !serviceControlRevision.MatchString(p.PolicyID) || p.Cycle < 1 || p.QuotaBytes <= 0 || p.ThresholdPercent < 1 || p.ThresholdPercent > 100 || p.PeriodStart <= 0 || len(p.PeriodEnds) == 0 || len(p.PeriodEnds) > 24 {
		return bad()
	}
	if p.Action != ServiceControlPause && p.Action != ServiceControlLimit {
		return bad()
	}
	for _, v := range []ServiceControl{{Revision: p.PolicyID, Mode: p.Action, LimitMbps: p.LimitMbps}, {Revision: p.PolicyID, Mode: p.ManualMode, LimitMbps: p.ManualLimitMbps}} {
		if err := v.Validate(); err != nil {
			return bad()
		}
	}
	if p.Direction != "up" && p.Direction != "down" && p.Direction != "max" && p.Direction != "sum" {
		return bad()
	}
	prev := p.PeriodStart
	for _, end := range p.PeriodEnds {
		if end <= prev || end-prev > 32*86400 {
			return bad()
		}
		prev = end
	}
	a := p.Anchor
	if a.Epoch == "" || len(a.Epoch) > 128 || a.Sequence == 0 || a.At < p.PeriodStart || a.At >= p.PeriodEnds[0] || a.UsedUp < 0 || a.UsedDown < 0 || len(a.Networks) == 0 || len(a.Networks) > 256 {
		return bad()
	}
	names := map[string]bool{}
	for _, n := range a.Networks {
		if !n.Included || n.ID == "" || len(n.ID) > 256 || n.Name == "" || len(n.Name) > 128 || names[n.Name] {
			return bad()
		}
		names[n.Name] = true
	}
	return nil
}
