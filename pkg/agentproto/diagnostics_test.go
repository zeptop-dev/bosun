package agentproto

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDiagnosticsAdditiveWireAndUnavailableRates(t *testing.T) {
	plain, err := json.Marshal(State{Revision: "existing"})
	if err != nil || strings.Contains(string(plain), "diagnostics") {
		t.Fatal("legacy state changed", err)
	}
	sample := DiagnosticsSample{Session: "process", Epoch: "worker", Sequence: 1, SampledAt: time.Date(2026, 10, 29, 1, 2, 3, 0, time.UTC), Interfaces: []DiagnosticsInterface{{Name: "eth0"}}}
	raw, err := json.Marshal(sample)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["sampled_at"] != "2026-10-29T01:02:03Z" || wire["net_up_bytes_per_second"] != nil || wire["cpu_percent"] != nil {
		t.Fatal("wire units or missing metrics changed", string(raw))
	}
	zero := float64(0)
	sample.NetUpBytesPerSecond = &zero
	raw, _ = json.Marshal(sample)
	json.Unmarshal(raw, &wire)
	if wire["net_up_bytes_per_second"] != float64(0) {
		t.Fatal("measured zero lost")
	}
}
