package selfupdate

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRestartSignalsOnceAfterResponse(t *testing.T) {
	if os.Getenv("BOSUN_TEST_RESTART_SIGNAL") == "1" {
		signals := make(chan os.Signal, 10)
		signal.Notify(signals, syscall.SIGTERM)
		defer signal.Stop(signals)
		const delay = 200 * time.Millisecond
		requested := make(chan time.Time, 1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requested <- time.Now()
			Restart(delay)
			_, _ = io.WriteString(w, "accepted")
		}))
		defer srv.Close()
		resp, err := srv.Client().Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil || string(body) != "accepted" {
			t.Fatalf("initiating HTTP response lost: %q, %v", body, err)
		}
		start := <-requested
		Restart(0) // Must not accelerate the first request's response grace.
		select {
		case <-signals:
			if time.Since(start) < delay {
				t.Fatal("restart skipped the response delay")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("no shutdown signal")
		}
		Restart(0) // Nor should another request signal again during cleanup.
		select {
		case <-signals:
			t.Fatal("duplicate restart interrupted cleanup")
		case <-time.After(100 * time.Millisecond):
		}
		_, _ = os.Stdout.WriteString("graceful restart handled\n")
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestRestartSignalsOnceAfterResponse$", "-test.timeout=8s")
	cmd.Env = append(os.Environ(), "BOSUN_TEST_RESTART_SIGNAL=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "graceful restart handled") {
		t.Fatalf("restart bypassed signal handling: %v\n%s", err, out)
	}
}
