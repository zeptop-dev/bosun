package probe

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestBoundProbeNeverUsesUnboundHooks(t *testing.T) {
	r := &Runner{
		LookupIP: func(context.Context, string, string) ([]net.IP, error) {
			t.Fatal("bound literal sent to resolver")
			return nil, nil
		},
		Dial: func(context.Context, string) (time.Duration, error) { t.Fatal("unbound dial used"); return 0, nil },
		DialFrom: func(context.Context, string, string) (time.Duration, error) {
			t.Fatal("source-only dial used")
			return 0, nil
		},
		ICMP: func(context.Context, string, string) (time.Duration, error) {
			t.Fatal("unbound ICMP used")
			return 0, nil
		},
	}
	for _, kind := range []string{"tcp", "icmp"} {
		target := "198.51.100.20"
		if kind == "tcp" {
			target += ":443"
		}
		m := r.MeasureOnce(context.Background(), spec.PingTask{Type: kind, Target: target, SourceInterface: "no-such-wan"})
		want := "interface"
		if runtime.GOOS != "linux" {
			want = "unsupported"
		}
		if m.Outcome != want || m.LatencyMs != -1 {
			t.Fatalf("%s: %+v", kind, m)
		}
	}
}
func TestInterfaceTaskConfigurationAndHistory(t *testing.T) {
	task := spec.PingTask{ID: 9, Name: "WAN", Type: "tcp", Target: "198.51.100.20:443", SourceInterface: "no-such-wan", IntervalSeconds: 60}
	cfg := spec.Probe{Enabled: true, InterfaceTasks: []spec.PingTask{task, {ID: 10, Name: "missing-binding", Type: "tcp", Target: "198.51.100.20:443"}}}
	r := &Runner{}
	defer r.Stop()
	r.Configure(context.Background(), &cfg)
	wait := func() spec.PingResult {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			v := r.Batch()
			if len(v) > 0 {
				return v[0]
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("no sample")
		return spec.PingResult{}
	}
	first := wait()
	if len(r.Results()) != 1 || first.Series != spec.ProbeTaskSeries(task) {
		t.Fatalf("bad bound task result %+v", r.Results())
	}
	cfg.InterfaceTasks[0].SourceInterface = "other-missing"
	r.Configure(context.Background(), &cfg)
	second := wait()
	if second.Series == first.Series || second.Quality.Epoch == first.Quality.Epoch || second.Quality.Window.Attempts != 1 {
		t.Fatal("mixed histories", first, second)
	}
	r.Acknowledge([]spec.PingResult{first})
	if len(r.Batch()[0].Quality.Recent) != 1 {
		t.Fatal("stale path acknowledged new sample")
	}
	cfg.InterfaceTasks[0].Target = "203.0.113.30:443"
	if r.cfg.InterfaceTasks[0].Target == cfg.InterfaceTasks[0].Target {
		t.Fatal("configuration slice aliases caller")
	}
}
