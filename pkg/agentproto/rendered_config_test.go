package agentproto

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRenderedConfigOptionalMalformedPreservesAccounting(t *testing.T) {
	for _, raw := range []string{`42`, `"secret"`, `{"version":"bad"}`, `{"version":1,"artifacts":[{"files":"bad"}]}`, `{"version":1,"status":"observed","artifacts":[{"activated_at":"bad"}]}`, `{"padding":"` + strings.Repeat("x", MaxRenderedConfigBytes) + `"}`} {
		var r Report
		if err := json.Unmarshal([]byte(`{"traffic_seq":7,"rendered_config":`+raw+`}`), &r); err != nil || r.TrafficSeq != 7 || r.RenderedConfig == nil || ValidateRenderedConfigReport(r.RenderedConfig) == nil {
			t.Fatalf("optional metadata blocked or became valid: %v", err)
		}
	}
	var old Report
	if err := json.Unmarshal([]byte(`{"traffic_seq":7}`), &old); err != nil || old.RenderedConfig != nil {
		t.Fatal("legacy report changed")
	}
}

func TestRenderedConfigAllowlist(t *testing.T) {
	good := RenderedArtifact{Core: "xray", Digest: "rcf1-" + strings.Repeat("a", 64), DigestScope: "process", Scope: "activation_files", Format: "json", Files: 1, Processes: 1, ActivatedAt: time.Now().UTC()}
	for _, status := range []string{"observed", "unavailable"} {
		r := &RenderedConfigReport{Version: 1, Status: status, Artifacts: []RenderedArtifact{good}}
		if err := ValidateRenderedConfigReport(r); err != nil {
			t.Fatal(err)
		}
	}
	mutations := []func(*RenderedArtifact){
		func(a *RenderedArtifact) { a.Core = "private-path" },
		func(a *RenderedArtifact) { a.Digest = strings.Repeat("a", 64) },
		func(a *RenderedArtifact) { a.DigestScope = "host" },
		func(a *RenderedArtifact) { a.Scope = "runtime_memory" },
		func(a *RenderedArtifact) { a.Format = "yaml" },
		func(a *RenderedArtifact) { a.Files = 0 },
		func(a *RenderedArtifact) { a.Processes = 16385 },
		func(a *RenderedArtifact) { a.ActivatedAt = time.Time{} },
	}
	for i, mutate := range mutations {
		a := good
		mutate(&a)
		if ValidateRenderedConfigReport(&RenderedConfigReport{Version: 1, Status: "observed", Artifacts: []RenderedArtifact{a}}) == nil {
			t.Fatalf("mutation %d accepted", i)
		}
	}
	if ValidateRenderedConfigReport(&RenderedConfigReport{Version: 1, Status: "observed", Artifacts: []RenderedArtifact{good, good}}) == nil {
		t.Fatal("duplicate core accepted")
	}
	var r RenderedConfigReport
	if err := json.Unmarshal([]byte(`{"version":1,"status":"observed","artifacts":[],"password":"secret"}`), &r); err != nil || ValidateRenderedConfigReport(&r) != nil {
		t.Fatal("additive unknown field changed compatibility")
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "secret") || strings.Contains(string(b), "password") {
		t.Fatal("unknown fields retained")
	}
}
