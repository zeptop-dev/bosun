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
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
	"github.com/zeptop-dev/bosun/pkg/wg"
)

// This exercises separate real WG clients without installing host interfaces,
// routes or firewall rules. The binary is an explicit opt-in so ordinary unit
// tests remain independent of locally installed proxy cores.
func TestWireGuardDevicesLiveXray(t *testing.T) {
	binary := os.Getenv("BOSUN_XRAY_WG_TEST_BINARY")
	if binary == "" {
		t.Skip("set BOSUN_XRAY_WG_TEST_BINARY to Xray >= 26.6.27")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	free := func(network string) int {
		t.Helper()
		if network == "udp" {
			l, err := net.ListenPacket(network, "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			return l.LocalAddr().(*net.UDPAddr).Port
		}
		l, err := net.Listen(network, "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	server, err := New(Options{Binary: binary, WorkDir: t.TempDir(), APIListen: net.JoinHostPort("127.0.0.1", strconv.Itoa(free("tcp")))}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if !server.Capabilities().WireGuardDevices {
		t.Fatal("test binary does not support WireGuard device accounting")
	}
	t.Cleanup(func() { _ = server.Stop(context.Background()) })
	ibs := []spec.Inbound{deviceTestInbound(t), deviceTestInbound(t)}
	for i := range ibs {
		ibs[i].Tag, ibs[i].Listen, ibs[i].Port, ibs[i].NoSniff = fmt.Sprintf("wg%d", i), "127.0.0.1", free("udp"), true
	}
	alice := spec.User{ID: 1, Name: "alice", UUID: "00000000-0000-4000-8000-000000000001", WireGuardPeers: []spec.WireGuardPeer{
		{UUID: "phone", Address: "10.67.0.1/32"}, {UUID: "laptop", Address: "10.67.0.2/32"},
	}}
	bob := spec.User{ID: 2, Name: "bob", UUID: "00000000-0000-4000-8000-000000000002", WireGuardLegacyDisabled: true, WireGuardPeers: []spec.WireGuardPeer{{UUID: "tablet", Address: "10.67.0.3/32"}}}
	payload := bytes.Repeat([]byte("w"), 64*1024)
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer destination.Close()
	// gVisor rejects external packets destined for loopback. Dial a reserved
	// test address through WG and redirect only on the server to our fixture.
	node := &spec.Node{AllowPrivateDest: true, DefaultOutbound: "fixture", Outbounds: []spec.Outbound{{
		Tag: "fixture", Protocol: "freedom", Settings: map[string]any{
			"redirect": strings.TrimPrefix(destination.URL, "http://"),
		},
	}}}
	bundle, err := server.Render(node, ibs, []spec.User{alice, bob})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(ctx, bundle); err != nil {
		t.Fatal(err)
	}

	client := func(ib spec.Inbound, user spec.User, device *spec.WireGuardPeer) *http.Client {
		t.Helper()
		private, _, err := wg.DerivePeer(ib.WGPrivateKey, user.UUID)
		address := wg.ClientAddress(user.ID)
		if device != nil {
			private, _, err = wg.DeriveDevicePeer(ib.WGPrivateKey, user.UUID, device.UUID)
			address = device.Address
		}
		if err != nil {
			t.Fatal("cannot derive client identity")
		}
		public, err := wg.PublicKey(ib.WGPrivateKey)
		if err != nil {
			t.Fatal("cannot derive server identity")
		}
		port := free("tcp")
		config := m{
			"log":      m{"loglevel": "error"},
			"inbounds": []m{{"listen": "127.0.0.1", "port": port, "protocol": "http", "settings": m{}}},
			"outbounds": []m{{"protocol": "wireguard", "settings": m{
				"secretKey": private, "address": []string{address}, "noKernelTun": true,
				"peers": []m{{"publicKey": public, "endpoint": net.JoinHostPort(ib.Listen, strconv.Itoa(ib.Port)), "allowedIPs": []string{"0.0.0.0/0"}, "keepAlive": 25}},
			}}},
		}
		data, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "client.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, binary, "run", "-c", path)
		// Configs contain ephemeral credentials; do not print config or logs.
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		proxyURL, _ := url.Parse("http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 3 * time.Second}
	}
	phone := client(ibs[0], alice, &alice.WireGuardPeers[0])
	laptop := client(ibs[0], alice, &alice.WireGuardPeers[1])
	legacy := client(ibs[0], alice, nil)
	otherUser := client(ibs[0], bob, &bob.WireGuardPeers[0])
	otherInbound := client(ibs[1], alice, &alice.WireGuardPeers[0])
	request := func(c *http.Client) error {
		res, err := c.Get("http://192.0.2.10/")
		if err != nil {
			return err
		}
		defer res.Body.Close()
		got, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, payload) {
			return fmt.Errorf("response payload mismatch")
		}
		return nil
	}
	ready := func(c *http.Client) {
		t.Helper()
		// A retained client may need WG's retransmission/keepalive timer to
		// establish a fresh handshake after the server intentionally restarts.
		deadline := time.Now().Add(35 * time.Second)
		for {
			if err := request(c); err == nil {
				return
			} else if time.Now().After(deadline) {
				t.Fatalf("client did not become usable: %v", err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	for _, c := range []*http.Client{phone, laptop, legacy, otherUser, otherInbound} {
		ready(c)
	}
	// Reset after readiness so all accounts and inbounds have a known baseline.
	if _, err := server.Stats(ctx, true); err != nil {
		t.Fatal(err)
	}
	var wgClients sync.WaitGroup
	errors := make(chan error, 2)
	for _, c := range []*http.Client{phone, laptop} {
		wgClients.Add(1)
		go func(c *http.Client) {
			defer wgClients.Done()
			for range 3 {
				if err := request(c); err != nil {
					errors <- err
					return
				}
			}
		}(c)
	}
	wgClients.Wait()
	close(errors)
	for err := range errors {
		t.Fatalf("concurrent devices interrupted each other: %v", err)
	}
	for _, c := range []*http.Client{legacy, otherUser, otherInbound} {
		if err := request(c); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := server.Stats(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	for key, count := range map[string]int64{"alice|wg0": 7, "alice|wg1": 1, "bob|wg0": 1} {
		download := stats[key].Down
		minimum := count * int64(len(payload))
		if download < minimum || download > minimum+32*1024 {
			t.Errorf("%s download = %d, want %d payload bytes plus HTTP overhead", key, download, minimum)
		}
	}
	for key, stat := range stats {
		if key != "alice|wg0" && key != "alice|wg1" && key != "bob|wg0" && stat.Up+stat.Down != 0 {
			t.Errorf("traffic escaped parent account/inbound attribution: %s", key)
		}
	}
	// Removing a device must replace the running WG peers, while the retained
	// device and legacy identity remain valid after the intentional restart.
	alice.WireGuardPeers = alice.WireGuardPeers[1:]
	bundle, err = server.Render(node, ibs, []spec.User{alice, bob})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Apply(ctx, bundle); err != nil {
		t.Fatal(err)
	}
	ready(laptop)
	ready(legacy)
	ready(otherUser)
	if err := request(phone); err == nil {
		t.Fatal("revoked device still opens new proxied connections")
	}
	if err := request(otherInbound); err == nil {
		t.Fatal("revocation did not propagate to the other WG inbound")
	}
}
