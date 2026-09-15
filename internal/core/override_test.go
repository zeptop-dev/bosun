package core

import (
	"encoding/json"
	"testing"
)

func TestApplyOverride(t *testing.T) {
	cfg := map[string]any{"log": map[string]any{"level": "info", "timestamp": true}, "inbounds": []any{"a"}, "dns": map[string]any{"servers": []any{"1.1.1.1"}}}
	if err := applyOverride(cfg, json.RawMessage(`{"log":{"level":"debug","output":"/tmp/x"},"inbounds":["b"],"dns":null,"extra":{"k":1}}`)); err != nil {
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
	if err := ApplyOverride("xray", cfg, json.RawMessage(`[1]`)); err == nil {
		t.Fatal("non-object must fail")
	}
	if err := ApplyOverride("xray", cfg, nil); err != nil {
		t.Fatal(err)
	}
}

func TestCheckOverrideDenies(t *testing.T) {
	if err := CheckOverride("xray", []byte(`{"log":{"access":"/etc/x"}}`)); err == nil {
		t.Fatal("xray log override should be refused")
	}
	if err := CheckOverride("singbox", []byte(`{"inbounds":[]}`)); err == nil {
		t.Fatal("sing-box inbounds override should be refused")
	}
	if err := CheckOverride("xray", []byte(`{"policy":{"levels":{}}}`)); err != nil {
		t.Fatal(err)
	}
}
