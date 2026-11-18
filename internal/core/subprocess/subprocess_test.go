package subprocess

import (
	"context"
	"log/slog"
	"syscall"
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

// Stop racing with fork/exec must wait until it can see and reap the child.
func TestStopDuringLaunch(t *testing.T) {
	s := New("sleep", "sleep", []string{"30"}, "", slog.Default())
	entered, release := make(chan struct{}), make(chan struct{})
	s.creds = func() *syscall.SysProcAttr {
		close(entered)
		<-release
		return nil
	}
	started := make(chan error, 1)
	go func() { started <- s.Start(context.Background()) }()
	<-entered
	stopped := make(chan error, 1)
	go func() { stopped <- s.Stop(context.Background()) }()
	select {
	case err := <-stopped:
		close(release)
		<-started
		_ = s.Stop(context.Background())
		t.Fatalf("Stop returned before an in-flight launch completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	if s.Running() || s.PID() != 0 {
		t.Fatal("child survived a concurrent Stop")
	}
}

func TestCancelledContextDoesNotLaunch(t *testing.T) {
	s := New("sleep", "sleep", []string{"30"}, "", slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	defer s.Stop(context.Background())
	if err := s.Start(ctx); err != context.Canceled {
		t.Fatalf("cancelled launch returned %v", err)
	}
	if s.Running() {
		t.Fatal("started a child after shutdown")
	}
}
