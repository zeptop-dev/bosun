//go:build linux

package xray

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/shaper"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"github.com/zeptop-dev/bosun/pkg/wg"
)

// All interfaces, routes and firewall rules live in a disposable namespace.
// The target is in a second namespace so real sockets traverse tc in both
// directions. No host routes or active proxy services are changed.
func TestWireGuardDevicesSharedLimitLinux(t *testing.T) {
	binary := os.Getenv("BOSUN_XRAY_WG_TEST_BINARY")
	if os.Getenv("BOSUN_WG_SHAPING_TEST") != "1" || binary == "" {
		t.Skip("set BOSUN_WG_SHAPING_TEST=1 and BOSUN_XRAY_WG_TEST_BINARY")
	}
	if os.Getenv("BOSUN_WG_SHAPING_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "-n", os.Args[0], "-test.run=^TestWireGuardDevicesSharedLimitLinux$", "-test.v")
		cmd.Env = append(os.Environ(), "BOSUN_WG_SHAPING_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated WG shaping: %v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	run := func(name string, args ...string) {
		t.Helper()
		if out, err := exec.CommandContext(ctx, name, args...).CombinedOutput(); err != nil {
			t.Fatalf("fixture %s: %v %s", name, err, out)
		}
	}
	child := exec.CommandContext(ctx, "unshare", "-n", "sleep", "90")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	pid := strconv.Itoa(child.Process.Pid)
	self, _ := os.Readlink("/proc/self/ns/net")
	readyNS := false
	for range 100 {
		ns, _ := os.Readlink("/proc/" + pid + "/ns/net")
		if ns != "" && ns != self {
			readyNS = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !readyNS {
		t.Fatal("target namespace not ready")
	}
	run("ip", "link", "set", "lo", "up")
	run("ip", "link", "add", "uplink", "type", "veth", "peer", "name", "target")
	run("ip", "link", "set", "target", "netns", pid)
	run("ip", "addr", "add", "192.0.2.1/24", "dev", "uplink")
	run("ip", "link", "set", "uplink", "up")
	run("nsenter", "-t", pid, "-n", "ip", "addr", "add", "192.0.2.2/24", "dev", "target")
	run("nsenter", "-t", pid, "-n", "ip", "link", "set", "target", "up")
	target := exec.CommandContext(ctx, "nsenter", "-t", pid, "-n", "python3", "-c", `
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(b'ok')
 def do_POST(self):
  body=self.rfile.read(int(self.headers['Content-Length']))
  self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
ThreadingHTTPServer(('192.0.2.2',18080),Handler).serve_forever()
`)
	if err := target.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Process.Kill(); _ = target.Wait() })
	shape := &shaper.Shaper{Interface: "uplink"}
	if err := shape.Apply(ctx, []shaper.Limit{{UserID: 1, Mbps: 2}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = shape.Apply(context.Background(), nil) })
	free := func() int {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	server, err := New(Options{Binary: binary, WorkDir: t.TempDir(), APIListen: fmt.Sprintf("127.0.0.1:%d", free())}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Stop(context.Background()) })
	ib := deviceTestInbound(t)
	ib.Listen, ib.Port, ib.NoSniff = "127.0.0.1", 18443, true
	user := spec.User{ID: 1, Name: "subscriber", UUID: "11111111-1111-4111-8111-111111111111", SpeedLimitMbps: 2, WireGuardLegacyDisabled: true, WireGuardPeers: []spec.WireGuardPeer{{UUID: "phone", Address: "10.67.0.1/32"}, {UUID: "laptop", Address: "10.67.0.2/32"}}}
	bundle, err := server.Render(&spec.Node{AllowPrivateDest: true}, []spec.Inbound{ib}, []spec.User{user})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Start(ctx, bundle); err != nil {
		t.Fatal(err)
	}
	clients := []*http.Client{}
	for _, device := range user.WireGuardPeers {
		private, _, err := wg.DeriveDevicePeer(ib.WGPrivateKey, user.UUID, device.UUID)
		if err != nil {
			t.Fatal("device key")
		}
		public, err := wg.PublicKey(ib.WGPrivateKey)
		if err != nil {
			t.Fatal("server key")
		}
		port := free()
		config := m{"log": m{"loglevel": "error"}, "inbounds": []m{{"listen": "127.0.0.1", "port": port, "protocol": "http", "settings": m{}}}, "outbounds": []m{{"protocol": "wireguard", "settings": m{"secretKey": private, "address": []string{device.Address}, "noKernelTun": true, "peers": []m{{"publicKey": public, "endpoint": "127.0.0.1:18443", "allowedIPs": []string{"0.0.0.0/0"}}}}}}}
		data, _ := json.Marshal(config)
		path := filepath.Join(t.TempDir(), "client.json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, binary, "run", "-c", path)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
		tr := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
		t.Cleanup(tr.CloseIdleConnections)
		clients = append(clients, &http.Client{Transport: tr, Timeout: 35 * time.Second})
	}
	for _, client := range clients {
		ready := false
		for range 100 {
			r, e := client.Get("http://192.0.2.2:18080/")
			if e == nil {
				_, _ = io.Copy(io.Discard, r.Body)
				r.Body.Close()
				ready = r.StatusCode == 200
				if ready {
					break
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !ready {
			t.Fatal("WG device failed readiness")
		}
	}
	if _, err := server.Stats(ctx, true); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), 1024*1024)
	var group sync.WaitGroup
	errs := make(chan error, 2)
	started := time.Now()
	for _, client := range clients {
		group.Add(1)
		go func(c *http.Client) {
			defer group.Done()
			r, e := c.Post("http://192.0.2.2:18080/", "application/octet-stream", bytes.NewReader(payload))
			if e != nil {
				errs <- e
				return
			}
			defer r.Body.Close()
			b, e := io.ReadAll(r.Body)
			if e != nil {
				errs <- e
				return
			}
			if !bytes.Equal(b, payload) {
				errs <- fmt.Errorf("payload mismatch")
			}
		}(client)
	}
	group.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	elapsed := time.Since(started)
	// 2 MiB upload followed by 2 MiB download shares one 2 Mbps account.
	// Independent per-device 2 Mbps allowances finish in about half this time.
	if elapsed < 10500*time.Millisecond {
		t.Fatalf("devices bypassed shared cap: %s", elapsed)
	}
	stats, err := server.Stats(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	v := stats[spec.InboundUser(user.Name, ib.Tag)]
	if v.Up < 2*int64(len(payload)) || v.Down < 2*int64(len(payload)) {
		t.Fatalf("parent counters missing data: up=%d down=%d", v.Up, v.Down)
	}
	t.Logf("two WG devices share 2 Mbps and parent counters: elapsed=%s up=%d down=%d", elapsed, v.Up, v.Down)
}
