package spec

import (
	"reflect"
	"strings"
	"testing"
)

func TestCarrierProbeDefaultsAndIdentity(t *testing.T) {
	for _, protocol := range []string{"tcp", "icmp"} {
		cfg := CarrierProbeConfig{Protocol: protocol, Family: "dual"}
		tasks := cfg.Tasks()
		if len(tasks) != 6 {
			t.Fatal(tasks)
		}
		seen := map[string]bool{}
		for i, task := range tasks {
			if err := task.Validate(); err != nil {
				t.Fatal(err)
			}
			wantFamily := "ipv4"
			if i >= 3 {
				wantFamily = "ipv6"
			}
			if task.Family != wantFamily || task.Type != protocol || task.IntervalSeconds != 10 || task.TCPReachability != (protocol == "tcp") || !strings.HasPrefix(task.Target, wantFamily+".pek-") || !ValidCarrierSeries(task.Series) || seen[task.Series] {
				t.Fatal(task)
			}
			seen[task.Series] = true
		}
		if !reflect.DeepEqual(tasks, cfg.Tasks()) {
			t.Fatal("unstable identities")
		}
	}
	if !reflect.DeepEqual(DefaultCarriers(), DefaultCarrierTargets("tcp", "ipv4")) {
		t.Fatal("legacy defaults differ")
	}
	cfg := CarrierProbeConfig{}
	first := cfg.Tasks()[0]
	cfg.TCPIPv4 = []Carrier{{Name: first.Name, Addr: "example.com:80"}}
	if cfg.Tasks()[0].Series == first.Series {
		t.Fatal("target change reused series")
	}
	cfg.TCPIPv4[0].Name = "other"
	if cfg.Tasks()[0].Series == CarrierSeries("tcp", "ipv4", first.Name, "example.com:80") {
		t.Fatal("name change reused series")
	}
}

func TestCarrierProbeValidationAndClone(t *testing.T) {
	invalid := []CarrierProbeConfig{
		{Protocol: "udp"}, {Family: "auto"},
		{TCPIPv4: []Carrier{{"CT", "example.com"}}},
		{TCPIPv4: []Carrier{{"CT", "[2001:db8::1]:80"}}},
		{TCPIPv6: []Carrier{{"CT", "192.0.2.10:80"}}},
		{ICMPIPv4: []Carrier{{"CT", "example.com:80"}}},
		{ICMPIPv6: []Carrier{{"CT", "192.0.2.10"}}},
		{ICMPIPv4: []Carrier{{"CT", "192.0.2.10"}, {"CT", "198.51.100.20"}}},
		{ICMPIPv4: []Carrier{{"bad\nname", "192.0.2.10"}}},
		{TCPIPv4: make([]Carrier, 17)},
	}
	for _, cfg := range invalid {
		if cfg.Validate() == nil || len(cfg.Tasks()) != 0 {
			t.Fatalf("invalid config accepted: %+v", cfg)
		}
	}
	orig := CarrierProbeConfig{Protocol: " ICMP ", Family: " IPv6 ", ICMPIPv6: []Carrier{{" CT ", " 2001:db8::1 "}}}
	got := orig.Normalize()
	if got.Validate() != nil || got.Protocol != "icmp" || got.ICMPIPv6[0].Name != "CT" {
		t.Fatal(got)
	}
	got.ICMPIPv6[0].Name = "changed"
	if orig.ICMPIPv6[0].Name != " CT " {
		t.Fatal("normalized config aliases input")
	}
	clone := orig.Clone()
	clone.ICMPIPv6[0].Name = "cloned"
	if orig.ICMPIPv6[0].Name != " CT " {
		t.Fatal("clone aliases input")
	}
	var nilConfig *CarrierProbeConfig
	if nilConfig.Clone() != nil {
		t.Fatal("nil clone")
	}
	for _, task := range []PingTask{{Type: "tcp", Target: "example.com:80", Family: "ipv4", SourceIP: "::1"}, {Type: "icmp", Target: "127.0.0.1", Family: "ipv6"}, {Type: "icmp", Target: "example.com", Family: "dual"}, {ID: 1, Type: "icmp", Target: "example.com", Series: CarrierSeries("icmp", "ipv4", "CT", "example.com")}} {
		if task.Validate() == nil {
			t.Fatal("invalid task accepted", task)
		}
	}
	for _, kind := range []string{"http", "download"} {
		if (PingTask{Type: kind, Target: "https://example.com/", Family: "ipv6"}).Validate() == nil {
			t.Fatal("unsupported HTTP family accepted", kind)
		}
	}
}

func TestLegacyCarrierFamilies(t *testing.T) {
	for _, tc := range []struct {
		targets []Carrier
		family  string
		v4, v6  int
	}{
		{nil, "ipv4", 0, 0},
		{[]Carrier{{"CT", "[2001:db8::1]:80"}}, "ipv6", 0, 1},
		{[]Carrier{{"CT", "[2001:db8::1]:80"}, {"CU", "example.com:80"}}, "dual", 1, 1},
	} {
		c := LegacyCarrierProbe(tc.targets)
		if c.Validate() != nil || c.Family != tc.family || len(c.TCPIPv4) != tc.v4 || len(c.TCPIPv6) != tc.v6 {
			t.Fatal(c)
		}
	}
}
