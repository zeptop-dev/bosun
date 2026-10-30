package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/core/subprocess"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

type sampleCounter struct {
	*lifecycleCounter
	process *subprocess.Supervisor
}

func (c *sampleCounter) ListenerPIDs() map[string]int { return map[string]int{"*": c.process.PID()} }

func TestTrafficSampleReadContinuityAndFailures(t *testing.T) {
	a, old, _ := checkpointRig(t)
	sup := subprocess.New("sample", "sleep", []string{"30"}, "", slog.Default())
	if err := sup.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer sup.Stop(context.Background())
	c := &sampleCounter{old, sup}
	a.reg.Replace(c.Name(), c)
	if err := a.loadTrafficJournal(); err != nil {
		t.Fatal(err)
	}
	read := func() *agentproto.TrafficSample {
		s := a.collectTrafficBatch(context.Background()).Sample
		if err := agentproto.ValidateTrafficSample(s); err != nil {
			t.Fatalf("invalid own metadata %+v: %v", s, err)
		}
		return s
	}
	if s := read(); s.Quality != "unknown" || !slices.Contains(s.Reasons, "first_read") {
		t.Fatalf("invented first baseline: %+v", s)
	}
	if s := read(); s.Quality != "observed" || s.Sources[0].StartedAt == nil {
		t.Fatalf("lost observed boundary: %+v", s)
	}
	c.statsErr = errors.New("private failure details")
	if s := read(); s.Quality == "observed" || !slices.Contains(s.Reasons, "counter_error") {
		t.Fatal(s)
	}
	c.statsErr = nil
	if s := read(); s.Quality == "observed" {
		t.Fatal("uncertain partial reset reported continuous", s)
	}
	if s := read(); s.Quality != "observed" {
		t.Fatal(s)
	}
	if err := sup.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := sup.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := read(); s.Quality == "observed" || !slices.Contains(s.Reasons, "process_changed") {
		t.Fatal("process replacement inherited old interval", s)
	}
	if err := a.checkpointTraffic(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := read(); s.Quality == "observed" {
		t.Fatal("lifecycle inherited old interval", s)
	}
}

func TestTrafficSampleFrozenRetryAndLegacyMerge(t *testing.T) {
	a, c, _ := checkpointRig(t)
	c.bytes = 123
	rep, err := a.prepareDurableReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a.trafficJournal = nil
	a.trafficReads = nil
	retry, err := a.prepareDurableReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rep.TrafficSample, retry.TrafficSample) || retry.TrafficSeq != rep.TrafficSeq {
		t.Fatal("retry changed original sampling evidence")
	}
	if !retry.TrafficDelivery.SampledAt.After(rep.TrafficDelivery.SampledAt) {
		t.Fatal("current queue status was not separately sampled")
	}
	merged := mergeTrafficSamples(nil, rep.TrafficSample)
	if merged.Quality == "observed" || !slices.Contains(merged.Reasons, "legacy_metadata") || agentproto.ValidateTrafficSample(merged) != nil {
		t.Fatal(merged)
	}
	for range 100 {
		merged = mergeTrafficSamples(merged, rep.TrafficSample)
	}
	if agentproto.ValidateTrafficSample(merged) != nil || len(merged.Sources) != len(rep.TrafficSample.Sources) {
		t.Fatal("coalescing grew per checkpoint", merged)
	}
	// A wall-clock rollback cannot establish a precise counter duration.
	a.trafficSample = &agentproto.TrafficSample{Sources: []agentproto.TrafficSampleSource{}}
	a.trafficReads = map[string]trafficReadBoundary{c.Name() + "/users": {at: time.Now().Add(time.Hour)}}
	a.noteTrafficRead(c, "users", "", nil)
	if !slices.Contains(a.trafficSample.Sources[0].Reasons, "clock_discontinuity") {
		t.Fatal(a.trafficSample)
	}
}

func TestTrafficSampleOldAndMalformedJournalKeepAccounting(t *testing.T) {
	for _, metadata := range []any{nil, "malformed", map[string]any{"version": "wrong"}} {
		a, c, _ := checkpointRig(t)
		c.bytes = 321
		original, err := a.prepareDurableReport(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		path := a.trafficJournal.path
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}

		// Use RawMessage below so the large receipt sequence is never decoded
		// through a floating-point map during this compatibility fixture.
		var fields map[string]json.RawMessage
		json.Unmarshal(raw, &fields)
		var pending map[string]json.RawMessage
		json.Unmarshal(fields["pending"], &pending)
		if metadata == nil {
			delete(pending, "sample")
		} else {
			pending["sample"], _ = json.Marshal(metadata)
		}
		fields["pending"], _ = json.Marshal(pending)
		raw, _ = json.Marshal(fields)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		a.trafficJournal = nil
		retry, err := a.prepareDurableReport(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if original.TrafficEpoch != retry.TrafficEpoch || original.TrafficSeq != retry.TrafficSeq || original.TrafficWindowSeconds != retry.TrafficWindowSeconds || !reflect.DeepEqual(original.Traffic, retry.Traffic) {
			t.Fatal("optional provenance changed accounting")
		}
		if metadata == nil && retry.TrafficSample != nil || metadata != nil && agentproto.ValidateTrafficSample(retry.TrafficSample) == nil {
			t.Fatal("unknown journal provenance invented")
		}
	}
}
