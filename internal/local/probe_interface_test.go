package local

import (
	"github.com/zeptop-dev/bosun/pkg/spec"
	"testing"
)

func TestLegacyLocalTasksRejectInterfaceBindings(t *testing.T) {
	p := ProbeSettings{Tasks: []spec.PingTask{{Name: "WAN", Type: "tcp", Target: "198.51.100.20:443", SourceInterface: "eth0"}}}
	if err := ValidateProbe(&p); err == nil {
		t.Fatal("local JSON task could lose binding on old version")
	}
}
