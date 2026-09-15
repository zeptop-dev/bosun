package core

import (
	"encoding/json"
	"testing"
)

func TestApplyOverride(t *testing.T) {
	cfg := map[string]any{"log": map[string]any{"level": "info", "timestamp": true}, "inbounds": []any{"a"}, "dns": map[string]any{"servers": []any{"1.1.1.1"}}}
	if err := ApplyOverride(cfg, json.RawMessage(`{"log":{"level":"debug","output":"/tmp/x"},"inbounds":["b"],"dns":null,"extra":{"k":1}}`)); err != nil {
		t.Fatal(err)
	}
	log := cfg["log"].(map[string]any)
	if log["level"] != "debug" || log["timestamp"] != true || log["output"] != "/tmp/x" {
		t.Fatalf("log merge: %v", log)
	}
	if _, has := cfg["dns"]; has {
		t.Fatal("null must delete")
	}
	if l := cfg["inbounds"].([]any); len(l) != 1 || l[0] != "b" {
		t.Fatal("arrays must replace")
	}
	if cfg["extra"].(map[string]any)["k"].(float64) != 1 {
		t.Fatal("new key")
	}
	if err := ApplyOverride(cfg, json.RawMessage(`[1]`)); err == nil {
		t.Fatal("non-object must fail")
	}
	if err := ApplyOverride(cfg, nil); err != nil {
		t.Fatal(err)
	}
}
