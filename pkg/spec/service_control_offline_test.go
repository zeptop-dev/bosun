package spec

import "testing"

func TestOfflineServiceControlValidation(t *testing.T) {
	valid := func() *ServiceControl {
		return &ServiceControl{Revision: "command", Mode: "normal", Offline: &OfflineServiceControl{PolicyID: "policy", Cycle: 1, Action: "limit", ThresholdPercent: 80, LimitMbps: 10, QuotaBytes: 1000, Direction: "sum", ManualMode: "normal", PeriodStart: 100, PeriodEnds: []int64{1000}, Anchor: OfflineTrafficAnchor{Epoch: "meter", Sequence: 1, At: 200, Networks: []NetworkResource{{Name: "eth0", ID: "boot:1", Included: true}}}}}
	}
	if err := valid().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*OfflineServiceControl){
		"quota":                 func(p *OfflineServiceControl) { p.QuotaBytes = 0 },
		"direction":             func(p *OfflineServiceControl) { p.Direction = "unknown" },
		"manual pause rate":     func(p *OfflineServiceControl) { p.ManualMode = "pause"; p.ManualLimitMbps = 1 },
		"empty interfaces":      func(p *OfflineServiceControl) { p.Anchor.Networks = nil },
		"duplicate interfaces":  func(p *OfflineServiceControl) { p.Anchor.Networks = append(p.Anchor.Networks, p.Anchor.Networks[0]) },
		"missing boot identity": func(p *OfflineServiceControl) { p.Anchor.Networks[0].ID = "" },
		"anchor outside cycle":  func(p *OfflineServiceControl) { p.Anchor.At = 1000 },
		"unordered boundaries":  func(p *OfflineServiceControl) { p.PeriodEnds = []int64{1000, 999} },
		"missing identity":      func(p *OfflineServiceControl) { p.PolicyID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			c := valid()
			edit(c.Offline)
			if c.Validate() == nil {
				t.Fatal("invalid offline policy accepted")
			}
		})
	}
}
