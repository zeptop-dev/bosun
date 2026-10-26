package local

import (
	"log/slog"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestCarrierSettingsPersistenceIsolationAndOldClient(t *testing.T) {
	s := openTest(t)
	cfg := &spec.CarrierProbeConfig{Protocol: "icmp", Family: "dual", ICMPIPv4: []spec.Carrier{{Name: "v4", Addr: "192.0.2.10"}}, ICMPIPv6: []spec.Carrier{{Name: "v6", Addr: "2001:db8::10"}}, TCPIPv4: []spec.Carrier{{Name: "unused", Addr: "example.com:443"}}}
	if err := s.SetProbe(ProbeSettings{Enabled: true, CarrierPing: true, CarrierProbe: cfg}); err != nil {
		t.Fatal(err)
	}
	cfg.ICMPIPv4[0].Name = "mutated"
	if s.ProbeSettings().CarrierProbe.ICMPIPv4[0].Name != "v4" {
		t.Fatal("input aliases stored config")
	}
	view := s.ProbeSettings()
	view.CarrierProbe.ICMPIPv4[0].Name = "view"
	state := s.Probe()
	state.CarrierProbe.ICMPIPv4[0].Name = "state"
	if s.ProbeSettings().CarrierProbe.ICMPIPv4[0].Name != "v4" {
		t.Fatal("reader aliases stored config")
	}
	// Switching the visible editor mode never discards inactive target lists.
	editing := s.ProbeSettings()
	editing.CarrierProbe.TCPIPv6 = []spec.Carrier{{Name: "unused-v6", Addr: "[2001:db8::10]:443"}}
	editing.CarrierProbe.Protocol = "tcp"
	editing.CarrierProbe.Family = "ipv6"
	if err := s.SetProbe(editing); err != nil {
		t.Fatal(err)
	}
	editing = s.ProbeSettings()
	editing.CarrierProbe.Protocol = "icmp"
	editing.CarrierProbe.Family = "dual"
	if err := s.SetProbe(editing); err != nil {
		t.Fatal(err)
	}
	preserved := s.ProbeSettings().CarrierProbe
	if len(preserved.TCPIPv4) != 1 || len(preserved.TCPIPv6) != 1 || len(preserved.ICMPIPv4) != 1 || len(preserved.ICMPIPv6) != 1 {
		t.Fatal("mode switch lost hidden target lists", preserved)
	}
	// The local switch still stops carriers without discarding saved choices.
	if err := s.SetProbe(ProbeSettings{Enabled: true, CarrierPing: false}); err != nil {
		t.Fatal(err)
	}
	if s.Probe().CarrierProbe != nil || s.ProbeSettings().CarrierProbe.Protocol != "icmp" {
		t.Fatal("disabled carriers ran or choices lost")
	}
	if err := s.SetProbe(ProbeSettings{Enabled: true, CarrierPing: true}); err != nil {
		t.Fatal(err)
	}
	if s.Probe().CarrierProbe.Protocol != "icmp" {
		t.Fatal("old client removed modern mode")
	}
	if err := s.Adopt("https://captain.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.Detach(nil); err != nil {
		t.Fatal(err)
	}
	reloaded, _, err := Open(s.path, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	got := reloaded.ProbeSettings().CarrierProbe
	if got.Protocol != "icmp" || got.Family != "dual" || len(got.TCPIPv4) != 1 || len(got.ICMPIPv6) != 1 {
		t.Fatal("adopt/detach or reload lost settings", got)
	}
}

func TestLegacyIPv6CarrierSettingsAreEditable(t *testing.T) {
	s := openTest(t)
	if err := s.SetProbe(ProbeSettings{Enabled: true, CarrierPing: true, Carriers: []spec.Carrier{{Name: "v6", Addr: "[2001:db8::10]:80"}}}); err != nil {
		t.Fatal(err)
	}
	got := s.ProbeSettings()
	if got.CarrierProbe.Family != "ipv6" || len(got.CarrierProbe.TCPIPv6) != 1 {
		t.Fatal(got)
	}
	if err := s.SetProbe(got); err != nil {
		t.Fatal("resaving legacy IPv6 rejected", err)
	}
	if err := s.SetProbe(ProbeSettings{CarrierProbe: &spec.CarrierProbeConfig{Protocol: "udp"}}); err == nil {
		t.Fatal("invalid modern mode accepted")
	}
}
