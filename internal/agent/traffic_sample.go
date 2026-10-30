package agent

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/core/subprocess"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

type trafficReadBoundary struct {
	at        time.Time
	process   string
	uncertain string
}

func trafficProcess(c core.Core) string {
	p, ok := c.(core.ListenerProcesses)
	if !ok {
		return ""
	}
	pids := p.ListenerPIDs()
	if len(pids) == 0 {
		return ""
	}
	active := subprocess.ActiveGenerations()
	parts := make([]string, 0, len(pids))
	for tag, pid := range pids {
		generation := active[pid]
		if pid <= 0 || generation == 0 {
			return ""
		}
		parts = append(parts, fmt.Sprintf("%s:%d", tag, generation))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func addSampleReason(reasons []string, reason string) []string {
	if !slices.Contains(reasons, reason) {
		reasons = append(reasons, reason)
	}
	return reasons
}

// All reads remain on the original serialized accounting path. Observability
// never performs an additional reset or changes the traffic window/rate input.
func (a *Agent) noteTrafficRead(c core.Core, kind, processBefore string, err error) {
	if a.trafficSample == nil {
		return
	}
	if a.trafficReads == nil {
		a.trafficReads = map[string]trafficReadBoundary{}
	}
	end := time.Now()
	process := trafficProcess(c)
	key := c.Name() + "/" + kind
	prior, known := a.trafficReads[key]
	source := agentproto.TrafficSampleSource{Core: c.Name(), Counter: kind, EndedAt: end.UTC(), Quality: "observed", Reasons: []string{}, Segments: 1}
	unknown := func(reason string) {
		source.Quality = "unknown"
		source.Reasons = addSampleReason(source.Reasons, reason)
	}
	if !known {
		unknown("first_read")
	}
	if process == "" || processBefore == "" {
		unknown("process_unverified")
	} else if process != processBefore || known && prior.process != process {
		unknown("process_changed")
	}
	if err != nil {
		unknown("counter_error")
	}
	if prior.uncertain != "" {
		unknown(prior.uncertain)
	}
	if known && !prior.at.IsZero() {
		elapsed := end.Sub(prior.at)
		wall := end.UTC().Sub(prior.at.UTC())
		if wall < 0 || wall-elapsed > time.Second || elapsed-wall > time.Second {
			unknown("clock_discontinuity")
		} else if source.Quality == "observed" {
			start := prior.at.UTC()
			duration := elapsed.Milliseconds()
			source.StartedAt, source.DurationMS = &start, &duration
		}
	}
	// A failed API may have partially reset counters. It cannot establish the
	// next interval's baseline, even if a later successful read returns bytes.
	boundary := trafficReadBoundary{at: end, process: process}
	if err != nil {
		boundary.uncertain = "counter_error"
	} else if process != processBefore {
		boundary.uncertain = "process_changed"
	}
	a.trafficReads[key] = boundary
	if len(a.trafficSample.Sources) < 18 {
		a.trafficSample.Sources = append(a.trafficSample.Sources, source)
	} else {
		a.trafficSample.Reasons = addSampleReason(a.trafficSample.Reasons, "source_limit")
	}
}

func finishTrafficSample(s *agentproto.TrafficSample) {
	s.Quality = "observed"
	observed := 0
	if len(s.Sources) == 0 {
		s.Quality = "unknown"
		s.Reasons = addSampleReason(s.Reasons, "no_running_sources")
	}
	for _, source := range s.Sources {
		if source.Quality == "observed" {
			observed++
		}
		if source.EndedAt.After(s.CollectionEndedAt) {
			s.CollectionEndedAt = source.EndedAt
			s.Reasons = addSampleReason(s.Reasons, "clock_discontinuity")
		}
		if source.Quality != "observed" {
			s.Quality = "partial"
		}
		for _, reason := range source.Reasons {
			s.Reasons = addSampleReason(s.Reasons, reason)
		}
	}
	if observed == 0 {
		s.Quality = "unknown"
	}
	if len(s.Reasons) > 0 && s.Quality == "observed" {
		s.Quality = "partial"
	}
	if s.CollectionEndedAt.Before(s.CollectionStartedAt) {
		// Retain the read endpoint, but do not serialize a reversed interval.
		s.CollectionStartedAt = s.CollectionEndedAt
		s.Reasons = addSampleReason(s.Reasons, "clock_discontinuity")
		s.Quality = "unknown"
	}
	boundTrafficSample(s)
}

func boundTrafficSample(s *agentproto.TrafficSample) {
	for len(s.Sources) > 0 {
		raw, _ := json.Marshal(s)
		if len(raw) <= agentproto.MaxTrafficSampleBytes {
			break
		}
		s.Sources = s.Sources[:len(s.Sources)-1]
		s.Reasons = addSampleReason(s.Reasons, "source_limit")
		s.Quality = "partial"
	}
}

// Coalescing preserves bounded per-source envelopes and explicitly withdraws
// continuous coverage. It cannot recreate the individual checkpoint segments.
func mergeTrafficSamples(old, next *agentproto.TrafficSample) *agentproto.TrafficSample {
	if old == nil && next == nil {
		return nil
	}
	out := &agentproto.TrafficSample{Version: 1, Quality: "partial", Reasons: []string{"coalesced"}, Sources: []agentproto.TrafficSampleSource{}}
	for _, sample := range []*agentproto.TrafficSample{old, next} {
		if agentproto.ValidateTrafficSample(sample) != nil {
			out.Reasons = addSampleReason(out.Reasons, "legacy_metadata")
			continue
		}
		if out.CollectionStartedAt.IsZero() || sample.CollectionStartedAt.Before(out.CollectionStartedAt) {
			out.CollectionStartedAt = sample.CollectionStartedAt
		}
		if sample.CollectionEndedAt.After(out.CollectionEndedAt) {
			out.CollectionEndedAt = sample.CollectionEndedAt
		}
		out.Segments = min(1_000_000, out.Segments+sample.Segments)
		for _, reason := range sample.Reasons {
			out.Reasons = addSampleReason(out.Reasons, reason)
		}
		for _, source := range sample.Sources {
			i := slices.IndexFunc(out.Sources, func(v agentproto.TrafficSampleSource) bool {
				return v.Core == source.Core && v.Counter == source.Counter
			})
			if i < 0 {
				if len(out.Sources) == 18 {
					out.Reasons = addSampleReason(out.Reasons, "source_limit")
					continue
				}
				out.Sources = append(out.Sources, source)
				continue
			}
			v := &out.Sources[i]
			if v.StartedAt == nil || source.StartedAt == nil {
				v.StartedAt = nil
			} else if source.StartedAt.Before(*v.StartedAt) {
				v.StartedAt = source.StartedAt
			}
			if source.EndedAt.After(v.EndedAt) {
				v.EndedAt = source.EndedAt
			}
			v.DurationMS = nil
			v.Quality = "partial"
			v.Segments = min(1_000_000, v.Segments+source.Segments)
			v.Reasons = addSampleReason(v.Reasons, "coalesced")
			for _, reason := range source.Reasons {
				v.Reasons = addSampleReason(v.Reasons, reason)
			}
		}
	}
	boundTrafficSample(out)
	return out
}
