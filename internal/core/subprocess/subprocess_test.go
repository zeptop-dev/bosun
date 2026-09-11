package subprocess

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

func TestStartStop(t *testing.T) {
	s := New("sleep", "sleep", []string{"30"}, "", slog.Default())
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if !s.Running() {
		t.Fatal("expected running")
	}
	if err := s.Start(ctx); err != ErrRunning {
		t.Fatalf("expected ErrRunning, got %v", err)
	}
	if err := s.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if s.Running() {
		t.Fatal("expected stopped")
	}
}

func TestRestartOnCrash(t *testing.T) {
	// A process that exits immediately must be relaunched by the supervisor.
	s := New("true", "sh", []string{"-c", "exit 1"}, "", slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	sawRestart := false
	for time.Now().Before(deadline) {
		s.mu.Lock()
		if s.backoff > minBackoff {
			sawRestart = true
		}
		s.mu.Unlock()
		if sawRestart {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !sawRestart {
		t.Fatal("supervisor did not schedule a restart")
	}
	_ = s.Stop(ctx)
}
