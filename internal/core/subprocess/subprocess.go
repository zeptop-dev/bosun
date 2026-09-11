// Package subprocess supervises a long-running child process: it pipes the
// child's output into structured logs, restarts it with backoff when it dies
// unexpectedly, and stops it gracefully on request.
package subprocess

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// ErrRunning is returned by Start when the process is already running.
var ErrRunning = errors.New("subprocess: already running")

const (
	minBackoff  = time.Second
	maxBackoff  = 30 * time.Second
	stableAfter = time.Minute // a run longer than this resets the backoff
	stopGrace   = 5 * time.Second
)

// Supervisor runs one command and keeps it alive.
type Supervisor struct {
	name string
	path string
	args []string
	dir  string
	log  *slog.Logger

	mu       sync.Mutex
	cmd      *exec.Cmd
	exited   chan struct{}
	stopping bool
	backoff  time.Duration
}

// New prepares a supervisor; nothing runs until Start.
func New(name, path string, args []string, dir string, log *slog.Logger) *Supervisor {
	return &Supervisor{name: name, path: path, args: args, dir: dir, log: log.With("proc", name), backoff: minBackoff}
}

// Start launches the process. It returns once the process has been spawned;
// crashes afterwards are handled by automatic restarts until Stop or ctx ends.
func (s *Supervisor) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.cmd != nil {
		s.mu.Unlock()
		return ErrRunning
	}
	s.stopping = false
	s.mu.Unlock()
	return s.launch(ctx)
}

func (s *Supervisor) launch(ctx context.Context) error {
	cmd := exec.Command(s.path, s.args...)
	cmd.Dir = s.dir
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	exited := make(chan struct{})
	s.mu.Lock()
	s.cmd = cmd
	s.exited = exited
	s.mu.Unlock()
	s.log.Info("started", "pid", cmd.Process.Pid, "path", s.path, "args", s.args)

	started := time.Now()
	// Proxy cores write their own leveled logs to stderr, so both streams are
	// relayed at Info; the child's level is visible in the message text.
	go s.pipe(stdout, slog.LevelInfo)
	go s.pipe(stderr, slog.LevelInfo)
	go func() {
		err := cmd.Wait()
		s.mu.Lock()
		stopping := s.stopping
		s.cmd = nil
		s.mu.Unlock()
		close(exited)
		if stopping {
			s.log.Info("stopped")
			return
		}
		s.log.Error("exited unexpectedly", "err", err, "after", time.Since(started).Round(time.Second))
		s.restartLater(ctx, time.Since(started))
	}()
	return nil
}

func (s *Supervisor) restartLater(ctx context.Context, ran time.Duration) {
	s.mu.Lock()
	if ran > stableAfter {
		s.backoff = minBackoff
	}
	delay := s.backoff
	s.backoff = min(s.backoff*2, maxBackoff)
	s.mu.Unlock()

	s.log.Info("restarting", "in", delay)
	select {
	case <-ctx.Done():
		return
	case <-time.After(delay):
	}
	s.mu.Lock()
	stopping := s.stopping
	s.mu.Unlock()
	if stopping {
		return
	}
	if err := s.launch(ctx); err != nil {
		s.log.Error("restart failed", "err", err)
		s.restartLater(ctx, 0)
	}
}

func (s *Supervisor) pipe(r io.Reader, level slog.Level) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		s.log.Log(context.Background(), level, sc.Text())
	}
}

// Stop terminates the process with SIGTERM, escalating to SIGKILL after a
// grace period. It is a no-op if nothing is running.
func (s *Supervisor) Stop(ctx context.Context) error {
	s.mu.Lock()
	s.stopping = true
	cmd := s.cmd
	exited := s.exited
	s.mu.Unlock()
	if cmd == nil {
		return nil
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-exited:
		return nil
	case <-time.After(stopGrace):
		s.log.Warn("did not exit after SIGTERM, killing")
	case <-ctx.Done():
	}
	_ = cmd.Process.Kill()
	<-exited
	return nil
}

// Restart stops then starts the process.
func (s *Supervisor) Restart(ctx context.Context) error {
	if err := s.Stop(ctx); err != nil {
		return err
	}
	return s.Start(ctx)
}

// Running reports whether a child process is currently alive.
func (s *Supervisor) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cmd != nil
}
