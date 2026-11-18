package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/core/subprocess"
	"github.com/zeptop-dev/bosun/pkg/selfupdate"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// No systemd cgroup or shell trap cleans up the child for us. This reproduces
// native updates under OpenRC: the agent itself must checkpoint, stop and reap.
func TestRestartStopsOwnedChildAndCheckpoints(t *testing.T) {
	for _, mode := range []string{"graceful", "ignore-term"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			// Also clean up after a regression to abrupt os.Exit. The PID belongs
			// to our helper, recorded after it has bound its private test listener.
			t.Cleanup(func() {
				b, _ := os.ReadFile(filepath.Join(dir, "ready.json"))
				var child restartChild
				if json.Unmarshal(b, &child) == nil && child.PID > 0 {
					p, _ := os.FindProcess(child.PID)
					_ = p.Kill()
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestRestartProcessHelper$", "-test.timeout=20s")
			cmd.Env = append(os.Environ(), "BOSUN_RESTART_HELPER=agent", "BOSUN_RESTART_DIR="+dir, "BOSUN_RESTART_CORE_MODE="+mode)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("agent: %v\n%s", err, out)
			}
			if _, err := os.Stat(filepath.Join(dir, "cleaned")); err != nil {
				t.Fatalf("agent exited without completing shutdown/checkpoint: %v\n%s", err, out)
			}
			b, err := os.ReadFile(filepath.Join(dir, "ready.json"))
			if err != nil {
				t.Fatal(err)
			}
			var child restartChild
			if err := json.Unmarshal(b, &child); err != nil {
				t.Fatal(err)
			}
			p, _ := os.FindProcess(child.PID)
			if err := p.Signal(syscall.Signal(0)); err == nil {
				t.Fatal("owned child survived agent exit")
			}
			// Binding, rather than Dial failure, proves the listener was released.
			ln, err := net.Listen("tcp", child.Address)
			if err != nil {
				t.Fatalf("core still owns listener: %v", err)
			}
			_ = ln.Close()
			_, err = os.Stat(filepath.Join(dir, "core-stopped"))
			if mode == "graceful" && err != nil {
				t.Fatal("core did not receive a graceful stop")
			}
			if mode == "ignore-term" && !os.IsNotExist(err) {
				t.Fatal("stubborn child was not killed by the stop deadline")
			}
		})
	}
}

type restartChild struct {
	PID     int
	Address string
}

type restartPanel struct{ lostResponsePanel }

func (p *restartPanel) Node(context.Context) (*spec.Node, bool, error) {
	return &spec.Node{Inbounds: []spec.Inbound{{Tag: "vless", Core: "xray", Protocol: spec.VLESS, Port: 18443}}}, true, nil
}
func (p *restartPanel) Users(context.Context) ([]spec.User, bool, error) {
	return []spec.User{{ID: 1, Name: "customer"}}, true, nil
}
func (p *restartPanel) Intervals() spec.Intervals {
	return spec.Intervals{Pull: time.Hour, Push: time.Hour}
}

type restartCore struct {
	countingCore
	sup     *subprocess.Supervisor
	started chan struct{}
	dir     string
}

func (c *restartCore) Running() bool { return c.sup.Running() }
func (c *restartCore) Start(ctx context.Context, _ *core.Bundle) error {
	if err := c.sup.Start(ctx); err != nil {
		return err
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		b, err := os.ReadFile(filepath.Join(c.dir, "ready.json"))
		var child restartChild
		if err == nil && json.Unmarshal(b, &child) == nil {
			conn, err := net.DialTimeout("tcp", child.Address, time.Second)
			if err != nil {
				return err
			}
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			var reply [2]byte
			_, err = io.ReadFull(conn, reply[:])
			_ = conn.Close()
			if err != nil || string(reply[:]) != "ok" {
				return fmt.Errorf("core handshake: %q, %v", reply, err)
			}
			c.pending = 1000
			close(c.started)
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("core never opened listener")
		case <-time.After(10 * time.Millisecond):
		}
	}
}
func (c *restartCore) Stop(ctx context.Context) error { return c.sup.Stop(ctx) }

func TestRestartProcessHelper(t *testing.T) {
	role := os.Getenv("BOSUN_RESTART_HELPER")
	if role == "" {
		return
	}
	dir := os.Getenv("BOSUN_RESTART_DIR")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if role == "core" {
		if os.Getenv("BOSUN_RESTART_CORE_MODE") == "ignore-term" {
			signal.Ignore(syscall.SIGTERM)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		b, _ := json.Marshal(restartChild{PID: os.Getpid(), Address: ln.Addr().String()})
		if err := os.WriteFile(filepath.Join(dir, "ready.json"), b, 0600); err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_, _ = c.Write([]byte("ok"))
				_ = c.Close()
			}
		}()
		<-ctx.Done()
		if err := os.WriteFile(filepath.Join(dir, "core-stopped"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c := &restartCore{countingCore: countingCore{fakeCore: fakeCore{name: "xray", protos: []spec.Protocol{spec.VLESS}}}, dir: dir, started: make(chan struct{})}
	c.sup = subprocess.New("xray", exe, []string{"-test.run=^TestRestartProcessHelper$", "-test.timeout=20s"}, dir, slog.Default()).WithEnv("BOSUN_RESTART_HELPER=core")
	reg := core.NewRegistry()
	reg.Register(c)
	p := &restartPanel{lostResponsePanel{seen: map[uint64]bool{}}}
	a := New(&config.Config{DataDir: dir}, p, reg, nil, slog.Default())
	go func() {
		<-c.started
		// Use the same process-level restart entry point as upgrades, rollbacks,
		// UI restart and node-mode changes; repeated requests must be harmless.
		selfupdate.Restart(50 * time.Millisecond)
		selfupdate.Restart(100 * time.Millisecond)
	}()
	if err := a.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if c.Running() || len(subprocess.ActiveProcesses()) != 0 {
		t.Fatal("agent returned before reaping its child")
	}
	if p.total != 0 {
		t.Fatal("shutdown unexpectedly relied on network delivery")
	}
	// Reload the durable journal, not the old in-memory counters.
	a.trafficJournal = nil
	a.report(context.Background())
	if p.total != 1000 {
		t.Fatalf("shutdown lost final traffic: %d", p.total)
	}
	if err := os.WriteFile(filepath.Join(dir, "cleaned"), nil, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestShutdownStopsNonRunningPreparation(t *testing.T) {
	entered, cancelled := make(chan struct{}), make(chan struct{})
	pending := core.NewPending("xray", func(ctx context.Context) (core.Core, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pending.Prepare(ctx)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("preparation did not start")
	}
	reg := core.NewRegistry()
	reg.Register(pending)
	a := New(&config.Config{DataDir: t.TempDir()}, nopDriver{}, reg, nil, slog.Default())
	a.stopAll()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("shutdown skipped a non-running adapter's cleanup")
	}
}
