package config

import (
	"os"
	"path/filepath"
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

func TestCarrierProbeYAMLAndValidation(t *testing.T) {
	var c Config
	if err := yaml.Unmarshal([]byte("probe:\n  enabled: true\n  carrier_ping: false\n  carrier_probe:\n    protocol: icmp\n    family: dual\n    icmp_ipv6:\n      - {name: example, addr: '2001:db8::10'}\n"), &c); err != nil {
		t.Fatal(err)
	}
	p := c.Probe.Spec()
	if p.CarrierPing || p.CarrierProbe == nil || len(p.CarrierProbe.Tasks()) != 4 {
		t.Fatal(p)
	}
	p.CarrierProbe.ICMPIPv6[0].Name = "changed"
	if c.Probe.CarrierProbe.ICMPIPv6[0].Name != "example" {
		t.Fatal("spec aliases config")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("probe:\n  carrier_probe:\n    protocol: udp\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("invalid carrier config loaded")
	}
}
