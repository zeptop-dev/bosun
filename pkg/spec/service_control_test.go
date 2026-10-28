package spec

import "testing"

func TestServiceControlValidation(t *testing.T) {
	for _, s := range []*ServiceControl{nil, {Revision: "v1", Mode: "normal"}, {Revision: "v2", Mode: "pause"}, {Revision: "v3", Mode: "limit", LimitMbps: 1}} {
		if err := s.Validate(); err != nil {
			t.Fatal(s, err)
		}
	}
	for _, s := range []*ServiceControl{{Revision: "v1", Mode: "limit"}, {Revision: "v1", Mode: "limit", LimitMbps: 1000001}, {Revision: "v1", Mode: "normal", LimitMbps: 1}, {Revision: "v1", Mode: "pause", LimitMbps: 1}, {Revision: "v1", Mode: "unknown"}, {Revision: "x\naccept", Mode: "pause"}, {Mode: "normal"}} {
		if err := s.Validate(); err == nil {
			t.Fatal("invalid control accepted", s)
		}
	}
	if ValidateMonitorState(&Node{ServiceControl: &ServiceControl{Revision: "x", Mode: "pause"}}, nil, nil) == nil {
		t.Fatal("monitor-only accepted proxy control")
	}
}
