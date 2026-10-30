package captain

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

func TestDiagnosticsSamplingContinuesDuringStateLongPoll(t *testing.T) {
	samples := make(chan agentproto.DiagnosticsSample, 8)
	waiting, release := make(chan struct{}, 1), make(chan struct{})
	c := diagnosticsClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var sample agentproto.DiagnosticsSample
			if err := json.NewDecoder(r.Body).Decode(&sample); err != nil {
				t.Error(err)
			}
			samples <- sample
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Query().Get("wait") != "" {
			select {
			case waiting <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-r.Context().Done():
			}
			w.WriteHeader(http.StatusNotModified)
			return
		}
		diagnosticStateResponse(w, r, diagnosticControl(r, "epoch", 1, 10000))
	})
	if _, err := c.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() {
		// Stop new polls before releasing the in-flight request. Its final 304
		// may still persist the recovery snapshot, so join the watcher before
		// diagnosticsClient's TempDir cleanup can remove that directory.
		if err := c.Close(); err != nil {
			t.Error(err)
		}
		close(release)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("state watcher did not exit before fixture cleanup")
		}
	})
	// Start only the state watcher, without public-address discovery.
	go func() {
		defer close(done)
		c.watch()
	}()
	select {
	case <-waiting:
	case <-time.After(2 * time.Second):
		t.Fatal("state watcher did not long poll")
	}
	for want := uint64(1); want <= 3; want++ {
		sample := awaitDiagnostic(t, samples)
		if sample.Sequence != want || sample.Epoch != "epoch" {
			t.Fatal("state watcher reset or starved diagnostic sampling", sample)
		}
	}
}
