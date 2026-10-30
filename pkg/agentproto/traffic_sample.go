package agentproto

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// TrafficSample describes counter-read provenance, never a billing instruction.
// Collection timestamps cover the read operations. Source intervals describe
// independent reset-read boundaries; neither promises lossless upstream counters.
// The object is frozen with its traffic epoch/sequence, including on retries.
type TrafficSample struct {
	Version             int                   `json:"version"`
	CollectionStartedAt time.Time             `json:"collection_started_at"`
	CollectionEndedAt   time.Time             `json:"collection_ended_at"`
	Segments            int                   `json:"segments"`
	Quality             string                `json:"quality"`
	Reasons             []string              `json:"reasons"`
	Sources             []TrafficSampleSource `json:"sources"`
}

type TrafficSampleSource struct {
	Core       string     `json:"core"`
	Counter    string     `json:"counter"` // users, inbounds, outbounds
	StartedAt  *time.Time `json:"started_at,omitempty"`
	EndedAt    time.Time  `json:"ended_at"`
	DurationMS *int64     `json:"duration_ms,omitempty"`
	Quality    string     `json:"quality"` // observed, partial, unknown
	Reasons    []string   `json:"reasons"`
	Segments   int        `json:"segments"`
}

// TrafficDelivery observes only counters already read into the durable journal.
// It excludes counters still held by cores and is not an accounting receipt.
type TrafficDelivery struct {
	SampledAt     time.Time  `json:"sampled_at"`
	PendingBytes  int64      `json:"pending_bytes"`
	BufferedBytes int64      `json:"buffered_bytes"`
	JournalBytes  int64      `json:"journal_bytes"`
	OldestAt      *time.Time `json:"oldest_at,omitempty"`
}

const MaxTrafficSampleBytes = 4 << 10

// Optional metadata must never turn a well-formed accounting report into a
// rejected batch, even when its nested fields have wrong JSON types. Invalid
// values become an explicit sentinel; the receiver records only that status.
func (s *TrafficSample) UnmarshalJSON(raw []byte) error {
	*s = TrafficSample{Version: -1}
	if len(raw) > MaxTrafficSampleBytes {
		return nil
	}
	type wire TrafficSample
	var v wire
	if json.Unmarshal(raw, &v) == nil {
		*s = TrafficSample(v)
	}
	return nil
}

func (d *TrafficDelivery) UnmarshalJSON(raw []byte) error {
	*d = TrafficDelivery{}
	if len(raw) > 1024 {
		return nil
	}
	type wire TrafficDelivery
	var v wire
	if json.Unmarshal(raw, &v) == nil {
		*d = TrafficDelivery(v)
	}
	return nil
}

var trafficSampleReasons = []string{"first_read", "counter_error", "process_changed", "process_unverified", "clock_discontinuity", "coalesced", "legacy_metadata", "no_running_sources", "source_limit"}

func sampleQuality(q string) bool { return q == "observed" || q == "partial" || q == "unknown" }
func sampleTime(t time.Time) bool { return !t.IsZero() && t.Year() >= 2000 && t.Year() <= 9999 }
func sampleReasons(reasons []string) bool {
	if len(reasons) > len(trafficSampleReasons) {
		return false
	}
	seen := map[string]bool{}
	for _, reason := range reasons {
		if seen[reason] || !slices.Contains(trafficSampleReasons, reason) {
			return false
		}
		seen[reason] = true
	}
	return true
}

// ValidateTrafficSample bounds optional observability data. A receiver must not
// reject otherwise valid customer accounting because this metadata is invalid.
func ValidateTrafficSample(s *TrafficSample) error {
	bad := func() error { return fmt.Errorf("invalid traffic sample metadata") }
	if s == nil || s.Version != 1 || !sampleTime(s.CollectionStartedAt) || !sampleTime(s.CollectionEndedAt) || s.CollectionEndedAt.Before(s.CollectionStartedAt) || s.Segments < 1 || s.Segments > 1_000_000 || !sampleQuality(s.Quality) || !sampleReasons(s.Reasons) || len(s.Sources) > 18 {
		return bad()
	}
	seen := map[string]bool{}
	for _, source := range s.Sources {
		if len(source.Core) == 0 || len(source.Core) > 64 || !slices.Contains([]string{"users", "inbounds", "outbounds"}, source.Counter) || !sampleTime(source.EndedAt) || source.EndedAt.After(s.CollectionEndedAt) || !sampleQuality(source.Quality) || !sampleReasons(source.Reasons) || source.Segments < 1 || source.Segments > s.Segments {
			return bad()
		}
		for _, c := range source.Core {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return bad()
			}
		}
		key := source.Core + "/" + source.Counter
		if seen[key] {
			return bad()
		}
		seen[key] = true
		if source.StartedAt != nil && (!sampleTime(*source.StartedAt) || source.StartedAt.After(source.EndedAt)) {
			return bad()
		}
		if source.DurationMS != nil && (*source.DurationMS < 0 || source.StartedAt == nil) {
			return bad()
		}
		if source.DurationMS != nil {
			// Supported timestamp years bound this subtraction well inside
			// int64. Compare before subtracting the untrusted duration itself.
			wallMS := source.EndedAt.UnixMilli() - source.StartedAt.UnixMilli()
			if *source.DurationMS > wallMS+1000 || *source.DurationMS < wallMS-1000 {
				return bad()
			}
		}
		if source.Quality == "observed" && (source.StartedAt == nil || source.DurationMS == nil || len(source.Reasons) != 0) {
			return bad()
		}
	}
	if s.Quality == "observed" {
		if len(s.Reasons) != 0 || len(s.Sources) == 0 {
			return bad()
		}
		for _, source := range s.Sources {
			if source.Quality != "observed" {
				return bad()
			}
		}
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > MaxTrafficSampleBytes {
		return bad()
	}
	return nil
}

func ValidateTrafficDelivery(d *TrafficDelivery) bool {
	return d != nil && sampleTime(d.SampledAt) && d.PendingBytes >= 0 && d.BufferedBytes >= 0 && d.JournalBytes >= 0 && d.JournalBytes <= 64<<20 && (d.OldestAt == nil || sampleTime(*d.OldestAt) && !d.OldestAt.After(d.SampledAt))
}
