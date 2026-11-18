package reversewg

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/core/singbox"
	"github.com/zeptop-dev/bosun/internal/core/xray"
	"github.com/zeptop-dev/bosun/internal/egressguard"
	"github.com/zeptop-dev/bosun/internal/shaper"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"github.com/zeptop-dev/bosun/pkg/wg"
)

// Called only inside TestLinuxTransport's disposable network namespace.
func testProxyAccounting(t *testing.T, a, a2 Config, grant *spec.PrivateAccess, applyLimits func([]shaper.Limit) error) {
	t.Helper()
	for _, kind := range []string{"xray", "singbox", "singbox-extended", "xray-wireguard", "singbox-socks", "singbox-http"} {
		t.Run(kind, func(t *testing.T) { testProxyAccountingCore(t, a, a2, grant, applyLimits, kind) })
	}
}
func testProxyAccountingCore(t *testing.T, a, a2 Config, grant *spec.PrivateAccess, applyLimits func([]shaper.Limit) error, kind string) {
	entryProtocol := spec.VLESS
	if kind == "singbox-socks" {
		kind = "singbox"
		entryProtocol = spec.SOCKS
	}
	if kind == "singbox-http" {
		kind = "singbox"
		entryProtocol = spec.HTTP
	}
	env := "BOSUN_XRAY_TEST_BINARY"
	if kind == "singbox" {
		env = "BOSUN_SINGBOX_TEST_BINARY"
	}
	if kind == "singbox-extended" {
		env = "BOSUN_EXTENDED_TEST_BINARY"
	}
	isWG := kind == "xray-wireguard"
	if isWG {
		env = "BOSUN_XRAY_WG_TEST_BINARY"
		kind = "xray"
	}
	binary := os.Getenv(env)
	if binary == "" {
		t.Skip("real proxy accounting not requested; set " + env)
		return
	}
	dir, err := os.MkdirTemp("", "bosun-wg-core-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	// The installed production binary may live below a root-only directory.
	// Copy its public executable, never its configuration, into this fixture.
	source, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.OpenFile(filepath.Join(dir, "xray"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		source.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(target, source)
	source.Close()
	closeErr := target.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatal("copy test binary failed")
	}
	a.PrivateAccess, a2.PrivateAccess = grant, grant
	user := spec.User{ID: 1, Name: "subscriber", UUID: "11111111-1111-4111-8111-111111111111", SpeedLimitMbps: 2, Password: "fixture-password"}
	n := spec.Node{WireGuardLinks: []spec.WireGuardLink{a, a2}, Inbounds: []spec.Inbound{
		{Tag: "wg-one", Core: "xray", Protocol: spec.VLESS, Listen: "127.0.0.1", Port: 18443, WireGuardSlot: a.Slot, PrivateAccess: grant},
		{Tag: "wg-two", Core: "xray", Protocol: spec.VLESS, Listen: "127.0.0.1", Port: 18444, WireGuardSlot: a2.Slot, PrivateAccess: grant},
		{Tag: "ordinary", Core: "xray", Protocol: spec.VLESS, Listen: "127.0.0.1", Port: 18445, PrivateAccess: &spec.PrivateAccess{Mode: "custom", Rules: []spec.PrivateAccessRule{{CIDR: "10.10.0.2/32", Protocol: "tcp", PortStart: 18080}}}},
	}}
	for i := range n.Inbounds {
		n.Inbounds[i].Core = kind
	}
	for i := 0; i < 2; i++ {
		n.Inbounds[i].Protocol = entryProtocol
	}
	if isWG {
		for i := 0; i < 2; i++ {
			n.Inbounds[i].Protocol = spec.WireGuard
			n.Inbounds[i].WGMTU = 1280
			spec.FillInboundSecrets(&n.Inbounds[i])
		}
	}

	var c core.Core
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if kind == "xray" {
		c, err = xray.New(xray.Options{Binary: filepath.Join(dir, "xray"), WorkDir: dir, APIListen: "127.0.0.1:19102", LogLevel: "warning"}, log)
	} else {
		c, err = singbox.New(singbox.Options{Distribution: kind, Binary: filepath.Join(dir, "xray"), WorkDir: dir, StatsListen: "127.0.0.1:19102", LogLevel: "warn"}, log)
	}
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := c.Render(&n, n.Inbounds, []spec.User{user})
	if err != nil {
		t.Fatal(err)
	}
	for name, contents := range bundle.Files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, contents, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	grants, err := n.PrivateGrants([]spec.User{user})
	if err != nil {
		t.Fatal(err)
	}
	limit := shaper.Limit{UserID: user.ID, Mbps: 2}
	for _, g := range grants {
		if g.UserID == user.ID {
			limit.Marks = append(limit.Marks, g.Mark)
		}
	}
	if err := applyLimits([]shaper.Limit{limit}); err != nil {
		t.Fatal(err)
	}
	guard := &egressguard.Guard{}
	if err := guard.Apply(context.Background(), 65534, egressguard.Options{PrivateGrants: grants, LoopbackPorts: []int{53}, ProtectedPorts: []int{19102}}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := guard.Apply(context.Background(), -1, egressguard.Options{Disabled: true}); err != nil {
			t.Error(err)
		}
	}()
	cmd := exec.Command("setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "--inh-caps=+net_admin,+net_bind_service", "--ambient-caps=+net_admin,+net_bind_service", filepath.Join(dir, "xray"), "run", "-c", filepath.Join(dir, bundle.Main))
	logFile, e := os.OpenFile(filepath.Join(dir, "core.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer logFile.Close()
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			raw, _ := os.ReadFile(filepath.Join(dir, "core.log"))
			message := string(raw)
			for _, ib := range n.Inbounds {
				if ib.WGPrivateKey != "" {
					message = strings.ReplaceAll(message, ib.WGPrivateKey, "[fixture key]")
				}
			}
			t.Log(message)
		}
	}()
	if isWG {
		type m = map[string]any
		cfg := m{"log": m{"loglevel": "error"}}
		var inbounds, outbounds, routes []any
		for _, ib := range n.Inbounds[:2] {
			private, _, e := wg.DerivePeer(ib.WGPrivateKey, user.UUID)
			if e != nil {
				t.Fatal(e)
			}
			public, e := wg.PublicKey(ib.WGPrivateKey)
			if e != nil {
				t.Fatal(e)
			}
			inbounds = append(inbounds, m{"tag": ib.Tag, "listen": "127.0.0.1", "port": ib.Port, "protocol": "vless", "settings": m{"decryption": "none", "clients": []any{m{"id": user.UUID}}}})
			outbounds = append(outbounds, m{"tag": ib.Tag, "protocol": "wireguard", "settings": m{"secretKey": private, "address": []string{wg.ClientAddress(user.ID)}, "noKernelTun": true, "mtu": 1280, "peers": []any{m{"publicKey": public, "endpoint": fmt.Sprintf("127.0.0.1:%d", ib.Port), "allowedIPs": []string{"0.0.0.0/0", "::/0"}, "keepAlive": 25}}}})
			routes = append(routes, m{"type": "field", "inboundTag": []string{ib.Tag}, "outboundTag": ib.Tag})
		}
		cfg["inbounds"], cfg["outbounds"], cfg["routing"] = inbounds, outbounds, m{"rules": routes}
		raw, e := json.Marshal(cfg)
		if e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(dir, "client.json")
		if e = os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
		client := exec.Command(filepath.Join(dir, "xray"), "run", "-c", path)
		if e = client.Start(); e != nil {
			t.Fatal(e)
		}
		defer func() { _ = client.Process.Kill(); _ = client.Wait() }()
	}
	ready := false
	for i := 0; i < 100; i++ {
		port := "18443"
		if isWG {
			port = "18445"
		}
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 50*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		t.Fatal("non-root " + kind + " did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	probe := exec.CommandContext(ctx, "python3", "-c", proxyTraffic, string(entryProtocol))
	if out, err := probe.CombinedOutput(); err != nil {
		t.Fatalf("real proxy data path: %v\n%s", err, out)
	}

	// Shared raw-login protocols aggregate in the upstream counter. Keep that
	// identity instead of falsely assigning all bytes to the last listener.
	expected := map[string]int64{}
	for i, ib := range n.Inbounds {
		name := spec.InboundUser(user.Name, ib.Tag)
		if i < 2 && (entryProtocol == spec.SOCKS || entryProtocol == spec.HTTP) {
			name = user.Name
		}
		expected[name] += 512 * 1024
	}
	var counters map[string]spec.Traffic
	for i := 0; i < 30; i++ {
		counters, err = c.Stats(ctx, false)
		if err != nil {
			t.Fatal(err)
		}
		complete := true
		for name, want := range expected {
			v := counters[name]
			complete = complete && v.Up >= want && v.Down >= want
		}
		if complete {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	for name, want := range expected {
		v := counters[name]
		if v.Up != want || v.Down != want {
			t.Fatalf("payload billing mismatch for %s: %+v, want %d", name, v, want)
		}
	}
	for name := range counters {
		if name != user.Name && !strings.HasPrefix(name, user.Name+"|") {
			t.Fatal("transport identity entered user accounting")
		}
	}

	t.Log("non-root pinned " + kind + ": two WG exits plus ordinary egress, private socket marks, shared 2 Mbps limit and exact per-inbound payload billing passed")
}

const proxyTraffic = `
import socket,struct,uuid,threading,time,sys,base64
errors=[]
payload=b'x'*(512*1024)
def exact(s,n):
 data=b''
 while len(data)<n:
  part=s.recv(n-len(data))
  assert part
  data+=part
 return data
def transfer(port):
 try:
  s=socket.create_connection(('127.0.0.1',port),2);s.settimeout(10)
  target=b'\x01'+socket.inet_aton('10.10.0.2' if port==18445 else '10.20.0.2')
  kind=sys.argv[1] if port!=18445 else 'vless'
  if kind=='socks':
   s.sendall(b'\x05\x01\x02');assert exact(s,2)==b'\x05\x02'
   user=b'subscriber';password=b'fixture-password';s.sendall(b'\x01'+bytes([len(user)])+user+bytes([len(password)])+password);assert exact(s,2)==b'\x01\x00'
   s.sendall(b'\x05\x01\x00'+target+struct.pack('!H',18080));h=exact(s,4);assert h[:2]==b'\x05\x00';exact(s,(16 if h[3]==4 else 4)+2)
  elif kind=='http':
   auth=base64.b64encode(b'subscriber:fixture-password').decode();s.sendall(('CONNECT 10.20.0.2:18080 HTTP/1.1\r\nHost: 10.20.0.2:18080\r\nProxy-Authorization: Basic '+auth+'\r\n\r\n').encode())
   header=b''
   while not header.endswith(b'\r\n\r\n'):header+=exact(s,1)
   assert b' 200 ' in header
  else:s.sendall(b'\x00'+uuid.UUID('11111111-1111-4111-8111-111111111111').bytes+b'\x00\x01'+struct.pack('!H',18080)+target)
  sender=threading.Thread(target=s.sendall,args=(payload,));sender.start()
  if kind=='vless':header=exact(s,2);exact(s,header[1])
  result=exact(s,len(payload));sender.join();s.close()
  assert result==(payload.upper() if port==18444 else payload)
 except Exception as e:errors.append(str(port)+":"+repr(e))
start=time.monotonic()
threads=[threading.Thread(target=transfer,args=(p,)) for p in [18443,18444,18445]]
for t in threads:t.start()
for t in threads:t.join()
assert not errors,errors
assert time.monotonic()-start>=5.5,'proxy bypassed aggregate user cap'
`
