package probe

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestRingLoss(t *testing.T) {
	r := &ring{}
	for i := 0; i < ringSize+5; i++ {
		v := float64(i)
		if i%10 == 0 {
			v = -1
		}
		r.add(v)
	}
	if len(r.samples) != ringSize || !r.full {
		t.Fatalf("ring size %d", len(r.samples))
	}
	if r.last() != float64(ringSize+4) {
		t.Fatalf("last %v", r.last())
	}
	if l := r.loss(); l < 5 || l > 15 {
		t.Fatalf("loss %v", l)
	}
}

func TestMeasureRetriesAndLoss(t *testing.T) {
	calls := 0
	r := &Runner{Dial: func(_ context.Context, addr string) (time.Duration, error) {
		calls++
		if addr == "down.test:80" {
			return 0, errors.New("timeout")
		}
		if calls == 1 {
			return 1500 * time.Millisecond, nil // slow first try triggers a retry
		}
		return 20 * time.Millisecond, nil
	}}
	if ms := r.measure(context.Background(), spec.PingTask{Type: "tcp", Target: "ok.test"}); ms != 20 || calls != 2 {
		t.Fatalf("ms %v calls %d", ms, calls)
	}
	calls = 0
	if ms := r.measure(context.Background(), spec.PingTask{Type: "tcp", Target: "down.test:80"}); ms != -1 || calls != 3 {
		t.Fatalf("lost: ms %v calls %d", ms, calls)
	}
}

func TestConfigureResults(t *testing.T) {
	r := &Runner{Dial: func(context.Context, string) (time.Duration, error) { return 30 * time.Millisecond, nil }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Configure(ctx, &spec.Probe{Enabled: true, CarrierPing: true, Tasks: []spec.PingTask{{ID: 7, Name: "gw", Type: "tcp", Target: "gw.test:443", IntervalSeconds: 60}}})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(r.Results()) == 4 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	res := r.Results()
	if len(res) != 4 || res[0].Name != "CT" || res[3].TaskID != 7 || res[3].LatencyMs != 30 {
		t.Fatalf("results %+v", res)
	}
	r.Configure(ctx, &spec.Probe{Enabled: false})
	if len(r.Results()) != 0 {
		t.Fatal("disabled runner still reports")
	}
}
