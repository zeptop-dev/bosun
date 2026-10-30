package agent

import (
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/servicecontrol"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestPathHealthAgentReportsOriginalSampleAndPauseStopsProbe(t *testing.T) {
	a, p, _ := configRevisionRig(t)
	a.node.Inbounds = nil
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Second))
				var b [3]byte
				if _, e := io.ReadFull(c, b[:]); e == nil && b == [3]byte{5, 1, 2} {
					c.Write([]byte{5, 2})
				}
			}()
		}
	}()
	portListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portListener.Addr().(*net.TCPAddr).Port
	portListener.Close()
	target := ln.Addr().String()
	p.revisionPanel.forwards = []spec.Forward{{Tag: "line-1-entry-health", Listen: "127.0.0.1", Port: port, Protocol: "tcp", Target: target, PathHealth: &spec.PathHealth{RouteID: 1, ScopeID: "scope", Protocol: spec.PathHealthSOCKS5, IntervalSeconds: 15, TimeoutSeconds: 1, FailureThreshold: 1, RecoveryThreshold: 1, Candidates: []spec.PathHealthCandidate{{ID: "candidate", Target: target, Digest: strings.Repeat("a", 64)}}}}}
	defer a.fwd.Stop()
	applyRevision(t, a)
	deadline := time.Now().Add(3 * time.Second)
	for len(a.fwd.PathHealthSnapshot()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	first := a.buildReport(nil, spec.SystemStatus{})
	if first.PathHealth == nil || !first.PathHealth.Supported || len(first.PathHealth.Samples) != 1 || first.PathHealth.Samples[0].Result != "success" {
		t.Fatal("actual agent failed to report relay probe", first.PathHealth)
	}
	second := a.buildReport(nil, spec.SystemStatus{})
	if first.PathHealth.Samples[0].Sequence != second.PathHealth.Samples[0].Sequence || !first.PathHealth.Samples[0].ObservedAt.Equal(second.PathHealth.Samples[0].ObservedAt) {
		t.Fatal("report construction renewed sample")
	}
	if len(first.Traffic) != 0 || len(second.Traffic) != 0 {
		t.Fatal("probe created customer traffic")
	}
	p.offline = true
	if len(a.buildReport(nil, spec.SystemStatus{}).PathHealth.Samples) != 0 {
		t.Fatal("offline cache attested new delivery")
	}
	p.offline = false
	p.leaseError = errors.New("expired")
	if len(a.buildReport(nil, spec.SystemStatus{}).PathHealth.Samples) != 0 {
		t.Fatal("revoked lease attested probe")
	}
	p.leaseError = nil
	var script string
	fail := false
	a.ServiceControl = &servicecontrol.Manager{Dir: t.TempDir(), Run: serviceControlTestRunner(&script, &fail)}
	a.node.ServiceControl = &spec.ServiceControl{Revision: "pause-health", Mode: spec.ServiceControlPause}
	applyRevision(t, a)
	if len(a.fwd.PathHealthSnapshot()) != 0 || len(a.buildReport(nil, spec.SystemStatus{}).PathHealth.Samples) != 0 {
		t.Fatal("pause retained probing evidence")
	}
	if c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("pause kept relay listener")
	}
	if !strings.Contains(script, "counter drop") {
		t.Fatal("pause omitted independent guard")
	}
}
