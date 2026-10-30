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
	// Release the simulated long poll before server/client cleanup; do not
	// start unrelated public-address discovery with Changed().
	t.Cleanup(func() { close(release) })
	if _, err := c.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	go c.watch()
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
