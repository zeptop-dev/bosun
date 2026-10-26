package local

import (
	"log/slog"
	"reflect"
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

func TestLegacyCarrierUpdatesPreserveModernDrafts(t *testing.T) {
	s := openTest(t)
	initial := &spec.CarrierProbeConfig{
		Protocol: "icmp", Family: "dual",
		TCPIPv4:  []spec.Carrier{{Name: "old-v4", Addr: "192.0.2.10:80"}},
		TCPIPv6:  []spec.Carrier{{Name: "old-v6", Addr: "[2001:db8::10]:80"}},
		ICMPIPv4: []spec.Carrier{{Name: "icmp-v4", Addr: "198.51.100.20"}},
		ICMPIPv6: []spec.Carrier{{Name: "icmp-v6", Addr: "2001:db8::20"}},
	}
	if err := s.SetProbe(ProbeSettings{Enabled: true, CarrierPing: true, CarrierProbe: initial}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetProbe(ProbeSettings{Enabled: true, CarrierPing: true}); err != nil {
		t.Fatal(err)
	}
	if got := s.ProbeSettings().CarrierProbe; !reflect.DeepEqual(got, initial) {
		t.Fatal("omitted legacy targets changed modern mode", got)
	}
	changed := []spec.Carrier{{Name: "new-v4", Addr: "example.com:443"}}
	if err := s.SetProbe(ProbeSettings{Enabled: true, CarrierPing: true, Carriers: changed}); err != nil {
		t.Fatal(err)
	}
	got := s.ProbeSettings().CarrierProbe
	if got.Protocol != "icmp" || got.Family != "dual" || !reflect.DeepEqual(got.TCPIPv4, changed) || !reflect.DeepEqual(got.TCPIPv6, initial.TCPIPv6) || !reflect.DeepEqual(got.ICMPIPv4, initial.ICMPIPv4) || !reflect.DeepEqual(got.ICMPIPv6, initial.ICMPIPv6) {
		t.Fatal("legacy edit ignored or hidden drafts lost", got)
	}
	if err := s.SetProbe(ProbeSettings{Enabled: true, CarrierPing: true, Carriers: []spec.Carrier{}}); err != nil {
		t.Fatal(err)
	}
	got = s.ProbeSettings().CarrierProbe
	if len(got.TCPIPv4) != 0 || !reflect.DeepEqual(got.TCPIPv6, initial.TCPIPv6) || got.Protocol != "icmp" || got.Family != "dual" {
		t.Fatal("explicit clear changed unrelated settings", got)
	}
	got.Protocol = "tcp"
	got.Family = "ipv4"
	if err := s.SetProbe(ProbeSettings{Enabled: true, CarrierPing: true, CarrierProbe: got}); err != nil {
		t.Fatal(err)
	}
	mixed := []spec.Carrier{{Name: "v4", Addr: "203.0.113.30:80"}, {Name: "v6", Addr: "[2001:db8::30]:80"}}
	if err := s.SetProbe(ProbeSettings{Enabled: true, CarrierPing: true, Carriers: mixed}); err != nil {
		t.Fatal(err)
	}
	got = s.ProbeSettings().CarrierProbe
	if got.Protocol != "tcp" || got.Family != "dual" || len(got.TCPIPv4) != 1 || len(got.TCPIPv6) != 1 || !reflect.DeepEqual(got.ICMPIPv6, initial.ICMPIPv6) {
		t.Fatal("mixed legacy target update failed", got)
	}
	if tasks := s.Probe().CarrierProbe.Tasks(); len(tasks) != 2 || tasks[0].Target != mixed[0].Addr || tasks[1].Target != mixed[1].Addr {
		t.Fatal("updated targets not used by runtime", tasks)
	}
	before := s.ProbeSettings()
	if err := s.SetProbe(ProbeSettings{Enabled: true, CarrierPing: true, Carriers: []spec.Carrier{{Name: "bad", Addr: "example.com:not-a-service"}}}); err == nil {
		t.Fatal("invalid merged legacy draft accepted")
	}
	if !reflect.DeepEqual(s.ProbeSettings(), before) {
		t.Fatal("failed validation modified saved settings")
	}
}

func TestFirstLegacyCarrierUpdateReplacesInferredFamily(t *testing.T) {
	for _, tc := range []struct {
		name     string
		targets  []spec.Carrier
		family   string
		wantAddr string
	}{
		{"omitted", nil, "ipv6", "[2001:db8::10]:80"},
		{"replaced", []spec.Carrier{{Name: "v4", Addr: "192.0.2.10:443"}}, "ipv4", "192.0.2.10:443"},
		{"cleared", []spec.Carrier{}, "ipv4", spec.DefaultCarriers()[0].Addr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := openTest(t)
			// Simulate a persisted configuration written before carrier_probe existed.
			s.st.Probe = ProbeSettings{Enabled: true, CarrierPing: true, Carriers: []spec.Carrier{{Name: "old-v6", Addr: "[2001:db8::10]:80"}}}
			if err := s.SetProbe(ProbeSettings{Enabled: true, CarrierPing: true, Carriers: tc.targets}); err != nil {
				t.Fatal(err)
			}
			got := s.ProbeSettings().CarrierProbe
			if got.Family != tc.family || got.Tasks()[0].Target != tc.wantAddr {
				t.Fatal("legacy family not replaced or preserved correctly", got)
			}
		})
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
