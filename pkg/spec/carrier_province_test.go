package spec

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestCarrierProvincePresets(t *testing.T) {
	codes := strings.Fields("he sx ln jl hl js zj ah fj jx sd ha hb hn gd hi sc gz yn sn gs qh nm gx xz nx xj bj tj sh cq")
	for _, province := range codes {
		t.Run(province, func(t *testing.T) {
			cfg := CarrierProbeConfig{Protocol: "tcp", Family: "dual", TCPProvince: province}
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			tasks := cfg.Tasks()
			if len(tasks) != 6 {
				t.Fatal(tasks)
			}
			for i, task := range tasks {
				version := "4"
				if i >= 3 {
					version = "6"
				}
				expected := province + "-" + strings.ToLower(task.Name) + "-v" + version + ".ip.zstaticcdn.com:80"
				if task.Target != expected || cfg.PresetProvince(task.Family) != province {
					t.Fatal(task)
				}
				if err := task.Validate(); err != nil {
					t.Fatal(err)
				}
			}
			for _, family := range []string{"ipv4", "ipv6"} {
				cfg.Protocol = "icmp"
				cfg.Family = family
				if !reflect.DeepEqual(cfg.Tasks(), (CarrierProbeConfig{Protocol: "icmp", Family: family}).Tasks()) || cfg.PresetProvince(family) != "" {
					t.Fatal("TCP province leaked into ICMP", cfg)
				}
			}
		})
	}
	if got := (CarrierProbeConfig{}).Normalize(); got.TCPProvince != "" || got.EffectiveTCPProvince() != "bj" {
		t.Fatal(got)
	}
	if got := (CarrierProbeConfig{TCPProvince: " GD "}).Normalize(); got.TCPProvince != "gd" || got.Validate() != nil {
		t.Fatal(got)
	}
}

func TestCarrierProvinceCustomAndLegacyExpansion(t *testing.T) {
	c := CarrierProbeConfig{Protocol: "tcp", Family: "dual", TCPProvince: "gd", TCPIPv4: []Carrier{{Name: "CT", Addr: "example.com:443"}}}
	before := *c.Clone()
	tasks := c.Tasks()
	if len(tasks) != 4 || c.PresetProvince("ipv4") != "" || c.PresetProvince("ipv6") != "gd" || c.PresetProvince("dual") != "" {
		t.Fatal(tasks)
	}
	expanded := c.Expanded()
	if !reflect.DeepEqual(before, c) || !reflect.DeepEqual(tasks, expanded.Tasks()) {
		t.Fatal("expansion altered draft or tasks")
	}
	// Model an older runtime by dropping the unknown field, retaining its four lists.
	wire, _ := json.Marshal(expanded)
	var legacy struct {
		Protocol string    `json:"protocol"`
		Family   string    `json:"family"`
		TCPIPv4  []Carrier `json:"tcp_ipv4"`
		TCPIPv6  []Carrier `json:"tcp_ipv6"`
		ICMPIPv4 []Carrier `json:"icmp_ipv4"`
		ICMPIPv6 []Carrier `json:"icmp_ipv6"`
	}
	if err := json.Unmarshal(wire, &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.TCPIPv4[0].Addr != "example.com:443" || legacy.TCPIPv6[0].Addr != "gd-ct-v6.ip.zstaticcdn.com:80" || legacy.ICMPIPv4[0].Addr != "ipv4.pek-4134.endpoint.nxtrace.org" {
		t.Fatal(legacy)
	}
	expanded.TCPIPv4[0].Addr = "changed"
	if c.TCPIPv4[0].Addr != "example.com:443" {
		t.Fatal("expansion aliases saved draft")
	}
	c.TCPProvince = "sh"
	after := c.Tasks()
	if tasks[0].Series != after[0].Series || tasks[1].Series == after[1].Series {
		t.Fatal("province change mixed preset or custom histories")
	}
	c.Family = "ipv4"
	if c.PresetProvince("ipv6") != "" {
		t.Fatal("inactive family exposed")
	}
	var absent *CarrierProbeConfig
	if absent.Expanded() != nil || (&CarrierProbeConfig{TCPProvince: "invalid"}).Expanded() != nil {
		t.Fatal("invalid expansion")
	}
}
