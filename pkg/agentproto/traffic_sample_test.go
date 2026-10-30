package agentproto

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

func TestTrafficMetadataMalformedDoesNotRejectAccounting(t *testing.T) {
	for _, raw := range []string{`"wrong"`, `[]`, `42`, `{"version":"wrong"}`, `{"version":1,"collection_ended_at":42}`, `{"sources":[{"duration_ms":"x"}]}`, `{"reasons":["` + strings.Repeat("x", 5000) + `"]}`} {
		var report Report
		if err := json.Unmarshal([]byte(`{"traffic_seq":5,"traffic":[{"UserID":1,"Up":20}],"traffic_sample":`+raw+`,"traffic_delivery":`+raw+`}`), &report); err != nil {
			t.Fatalf("metadata blocked report: %v", err)
		}
		if report.TrafficSeq != 5 || len(report.Traffic) != 1 || ValidateTrafficSample(report.TrafficSample) == nil || ValidateTrafficDelivery(report.TrafficDelivery) {
			t.Fatalf("metadata trusted: %+v", report)
		}
	}
}

func TestTrafficSampleBoundedValidation(t *testing.T) {
	at := time.Now().UTC()
	start := at.Add(-time.Minute)
	duration := int64(60000)
	s := &TrafficSample{Version: 1, CollectionStartedAt: at, CollectionEndedAt: at, Segments: 1, Quality: "observed", Reasons: []string{}, Sources: []TrafficSampleSource{{Core: "xray", Counter: "users", StartedAt: &start, EndedAt: at, DurationMS: &duration, Quality: "observed", Reasons: []string{}, Segments: 1}}}
	if err := ValidateTrafficSample(s); err != nil {
		t.Fatal(err)
	}
	s.Sources[0].StartedAt = nil
	if ValidateTrafficSample(s) == nil {
		t.Fatal("claimed observed interval without baseline")
	}
}

func TestTrafficSampleDurationMatchesObservedBoundaries(t *testing.T) {
	at := time.Now().UTC()
	start := at.Add(-time.Minute)
	duration := int64(math.MaxInt64)
	s := &TrafficSample{Version: 1, CollectionStartedAt: at, CollectionEndedAt: at, Segments: 1, Quality: "observed", Sources: []TrafficSampleSource{{Core: "xray", Counter: "users", StartedAt: &start, EndedAt: at, DurationMS: &duration, Quality: "observed", Segments: 1}}}
	if ValidateTrafficSample(s) == nil {
		t.Fatal("one-minute interval accepted MaxInt64 elapsed duration")
	}
	duration = 0
	if ValidateTrafficSample(s) == nil {
		t.Fatal("one-minute interval accepted zero elapsed duration")
	}
	duration = 60000
	if err := ValidateTrafficSample(s); err != nil {
		t.Fatal(err)
	}
}
