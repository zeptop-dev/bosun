package singbox

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
	"golang.org/x/net/proxy"
)

// Opt-in real upstream check, restricted to loopback. No host firewall changes.
func TestStandaloneRealSOCKSAndSS2022(t *testing.T) {
	binary := os.Getenv("BOSUN_STANDALONE_TEST_BINARY")
	if binary == "" {
		t.Skip("set BOSUN_STANDALONE_TEST_BINARY")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	// Hold all ports until the complete configuration has been allocated.
	var held []net.Listener
	port := func() int {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		held = append(held, l)
		return l.Addr().(*net.TCPAddr).Port
	}
	socksPort, ssPort, statsPort, clientPort := port(), port(), port(), port()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16))
	inbounds := []spec.Inbound{{Tag: "standalone-socks", Protocol: spec.SOCKS, Listen: "127.0.0.1", Port: socksPort, Standalone: &spec.StandaloneAuth{Username: "operator", Password: "secret"}}, {Tag: "standalone-ss", Protocol: spec.Shadowsocks, Listen: "127.0.0.1", Port: ssPort, Cipher: "2022-blake3-aes-128-gcm", ServerKey: key, Standalone: &spec.StandaloneAuth{}}}
	for _, l := range held {
		_ = l.Close()
	}
	core, err := New(Options{Distribution: "singbox-extended", Binary: binary, WorkDir: t.TempDir(), StatsListen: net.JoinHostPort("127.0.0.1", strconv.Itoa(statsPort))}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer core.Stop(context.Background())
	bundle, err := core.Render(&spec.Node{AllowPrivateDest: true}, inbounds, users)
	if err != nil {
		t.Fatal(err)
	}
	if err = core.Start(ctx, bundle); err != nil {
		t.Fatal(err)
	}
	check := func(addr string, auth *proxy.Auth, success bool) {
		t.Helper()
		d, e := proxy.SOCKS5("tcp", addr, auth, &net.Dialer{Timeout: time.Second})
		if e != nil {
			t.Fatal(e)
		}
		var c net.Conn
		deadline := time.Now().Add(4 * time.Second)
		for {
			c, e = d.Dial("tcp", echo.Addr().String())
			if e == nil || !success || time.Now().After(deadline) {
				break
			}
			time.Sleep(40 * time.Millisecond)
		}
		if !success {
			if e == nil {
				c.Close()
				t.Fatal("unauthorized credentials accepted")
			}
			return
		}
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
		payload := bytes.Repeat([]byte("standalone-echo"), 2048)
		if _, e = c.Write(payload); e != nil {
			t.Fatal(e)
		}
		got := make([]byte, len(payload))
		if _, e = io.ReadFull(c, got); e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("echo mismatch")
		}
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))
	check(addr, &proxy.Auth{User: "operator", Password: "secret"}, true)
	check(addr, &proxy.Auth{User: "operator", Password: "wrong"}, false)
	check(addr, &proxy.Auth{User: users[0].Name, Password: users[0].Password}, false)
	check(addr, nil, false)
	// A native SS2022 outbound connects using precisely one key, without a subscriber PSK.
	cfg := map[string]any{"log": map[string]any{"level": "error"}, "inbounds": []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": clientPort}}, "outbounds": []any{map[string]any{"type": "shadowsocks", "server": "127.0.0.1", "server_port": ssPort, "method": "2022-blake3-aes-128-gcm", "password": key}}}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "client.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, binary, "run", "-c", path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	check(net.JoinHostPort("127.0.0.1", strconv.Itoa(clientPort)), nil, true)
	// Standalone traffic has no user statistics identity to charge.
	if stats, err := core.Stats(ctx, true); err != nil {
		t.Fatal(err)
	} else {
		for _, u := range users {
			if x := stats[u.Name]; x.Up != 0 || x.Down != 0 {
				t.Fatal("independent usage billed to subscriber")
			}
		}
	}
}
