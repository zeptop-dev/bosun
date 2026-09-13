package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestProbeConfigSpec(t *testing.T) {
	var c Config
	if err := yaml.Unmarshal([]byte("probe:\n  enabled: true\n  carriers:\n    - { name: HK, addr: hk.test:80 }\n  tasks:\n    - { name: cf, type: tcp, target: 1.1.1.1:443, interval_seconds: 30 }\n"), &c); err != nil {
		t.Fatal(err)
	}
	p := c.Probe.Spec()
	if p == nil || !p.CarrierPing || len(p.Carriers) != 1 || p.Carriers[0].Addr != "hk.test:80" || len(p.Tasks) != 1 || p.Tasks[0].ID != 1 || p.Tasks[0].IntervalSeconds != 30 {
		t.Fatalf("spec %+v", p)
	}
	if (&Config{}).Probe.Spec() != nil {
		t.Fatal("absent section must yield nil")
	}
}
