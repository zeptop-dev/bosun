package spec

import "testing"

func TestProbeInterfaceValidation(t *testing.T) {
	for _, task := range []PingTask{
		{Type: "tcp", Target: "198.51.100.20:443", SourceInterface: "pppoe-wan"},
		{Type: "icmp", Target: "2001:db8::20", SourceInterface: "eth0.2", Family: "ipv6"},
	} {
		if err := task.Validate(); err != nil {
			t.Fatal(err)
		}
		task.Series = ProbeTaskSeries(task)
		if !ValidProbeTaskSeries(task.Series) {
			t.Fatal(task.Series)
		}
		if err := task.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, task := range []PingTask{
		{Type: "tcp", Target: "example.com:443", SourceInterface: "eth0"},
		{Type: "tcp", Target: "198.51.100.20", SourceInterface: "eth0"},
		{Type: "tcp", Target: "[2001:db8::20]:https", SourceInterface: "eth0"},
		{Type: "icmp", Target: "example.com", SourceInterface: "eth0"},
		{Type: "http", Target: "https://198.51.100.20", SourceInterface: "eth0"},
		{Type: "icmp", Target: "198.51.100.20", SourceInterface: "eth0;id"},
		{Type: "icmp", Target: "198.51.100.20", SourceInterface: "eth0@eth1"},
		{Type: "icmp", Target: "198.51.100.20", SourceInterface: "interface-name-is-too-long"},
		{Type: "icmp", Target: "198.51.100.20", SourceInterface: ".."},
	} {
		if err := task.Validate(); err == nil {
			t.Fatalf("accepted %+v", task)
		}
	}
}
func TestProbeInterfaceIdentity(t *testing.T) {
	base := PingTask{ID: 7, Name: "CM", Type: "tcp", Target: "198.51.100.20:443", SourceInterface: "eth0"}
	original := ProbeTaskSeries(base)
	changes := []func(*PingTask){func(t *PingTask) { t.ID++ }, func(t *PingTask) { t.Name = "IX" }, func(t *PingTask) { t.Type = "icmp" }, func(t *PingTask) { t.Target = "203.0.113.30:443" }, func(t *PingTask) { t.SourceIP = "192.0.2.10" }, func(t *PingTask) { t.SourceInterface = "eth1" }, func(t *PingTask) { t.Family = "ipv4" }, func(t *PingTask) { t.TCPReachability = true }}
	for _, change := range changes {
		changed := base
		change(&changed)
		if ProbeTaskSeries(changed) == original {
			t.Fatalf("identity unchanged %+v", changed)
		}
		changed.Series = original
		if changed.Validate() == nil {
			t.Fatal("stale series accepted")
		}
	}
	base.IntervalSeconds = 90
	if ProbeTaskSeries(base) != original {
		t.Fatal("cadence changed path identity")
	}
	base.SourceInterface = ""
	if ProbeTaskSeries(base) != "" {
		t.Fatal("legacy identity changed")
	}
	base.Series = original
	if base.Validate() == nil {
		t.Fatal("task series accepted for unbound task")
	}
}
