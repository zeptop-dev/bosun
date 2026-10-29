package agentproto

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestConfigObservationWireCompatibility(t *testing.T) {
	for _, value := range []any{State{}, Report{}} {
		raw, err := json.Marshal(value)
		if err != nil || strings.Contains(string(raw), "config_") {
			t.Fatalf("absent metadata changed legacy wire form: %s %v", raw, err)
		}
	}
	old := `{"revision":"legacy","node":{},"users":[],"forwards":[]}`
	var state State
	if err := json.Unmarshal([]byte(old), &state); err != nil || state.ConfigRevision != "" || state.ConfigDelivery != nil {
		t.Fatalf("legacy state: %+v %v", state, err)
	}
	state.ConfigRevision = "cfg1-structural"
	state.ConfigDelivery = &ConfigDelivery{ID: "delivery", Session: "session"}
	raw, err := json.Marshal(state)
	var decoded State
	if err != nil || json.Unmarshal(raw, &decoded) != nil || !reflect.DeepEqual(state, decoded) {
		t.Fatalf("state metadata round trip: %s %v", raw, err)
	}
	report := Report{ConfigReceipt: &ConfigReceipt{DeliveryID: "delivery", Session: "session", ConfigRevision: state.ConfigRevision, StateRevision: state.Revision, Sequence: 7, ObservedAt: time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC), Applied: true}}
	raw, err = json.Marshal(report)
	var got Report
	if err != nil || json.Unmarshal(raw, &got) != nil || !reflect.DeepEqual(report, got) {
		t.Fatalf("receipt metadata round trip: %s %v", raw, err)
	}
}
