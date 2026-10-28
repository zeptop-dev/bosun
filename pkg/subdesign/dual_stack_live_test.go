package subdesign

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"github.com/zeptop-dev/bosun/pkg/subscription"
	"gopkg.in/yaml.v3"
)

// An optional real-client smoke test. All DNS, proxy and destination traffic is
// confined to loopback. It proves usable address-family fallback, not real-world
// latency advantages or every protocol's handshake behavior.
func TestMihomoNodeDualStackConnectivityLive(t *testing.T) {
	binary := os.Getenv("BOSUN_MIHOMO_TEST_BINARY")
	if binary == "" {
		t.Skip("set BOSUN_MIHOMO_TEST_BINARY")
	}
	if l, err := net.Listen("tcp6", "[::1]:0"); err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	} else {
		_ = l.Close()
	}
	for _, mode := range []string{"ipv4", "ipv6", "both"} {
		t.Run(mode, func(t *testing.T) {
			var aQueries, aaaaQueries atomic.Int64
			packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			dnsServer := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
				reply := new(dns.Msg)
				reply.SetReply(q)
				for _, question := range q.Question {
					if question.Name != "node.example.com." {
						continue
					}
					header := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: 1}
					switch question.Qtype {
					case dns.TypeA:
						aQueries.Add(1)
						reply.Answer = append(reply.Answer, &dns.A{Hdr: header, A: net.ParseIP("127.0.0.1")})
					case dns.TypeAAAA:
						aaaaQueries.Add(1)
						reply.Answer = append(reply.Answer, &dns.AAAA{Hdr: header, AAAA: net.ParseIP("::1")})
					}
				}
				_ = w.WriteMsg(reply)
			})}
			go func() { _ = dnsServer.ActivateAndServe() }()
			t.Cleanup(func() { _ = dnsServer.Shutdown() })

			port := 0
			startProxy := func(family string) {
				address := "127.0.0.1"
				network := "tcp4"
				if family == "ipv6" {
					address, network = "::1", "tcp6"
				}
				listener, err := net.Listen(network, net.JoinHostPort(address, strconv.Itoa(port)))
				if err != nil {
					t.Fatal(err)
				}
				port = listener.Addr().(*net.TCPAddr).Port
				server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodConnect || r.Host != "service.example.com:80" {
						http.Error(w, "unexpected target", http.StatusBadRequest)
						return
					}
					conn, buf, err := w.(http.Hijacker).Hijack()
					if err != nil {
						return
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
					_, _ = buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
					_ = buf.Flush()
					request, err := http.ReadRequest(bufio.NewReader(buf))
					if err != nil {
						return
					}
					_ = request.Body.Close()
					_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(family), family)
				})}
				go func() { _ = server.Serve(listener) }()
				t.Cleanup(func() { _ = server.Close() })
			}
			if mode != "ipv6" {
				startProxy("ipv4")
			}
			if mode != "ipv4" {
				startProxy("ipv6")
			}
			free, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			mixedPort := free.Addr().(*net.TCPAddr).Port
			_ = free.Close()
			d := Design{Groups: []Group{{Name: "PROXY", Type: "select", Members: []string{"@all"}}}, Final: "PROXY", Enhancements: Enhancements{NodeDualStack: true}}
			tpl, err := d.Render("clash")
			if err != nil {
				t.Fatal(err)
			}
			out, err := subscription.Clash{}.RenderWith([]subscription.Line{{Name: "Node", Host: "node.example.com", Port: port, Inbound: spec.Inbound{Protocol: spec.HTTP}}}, subscription.Account{}, tpl)
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err = yaml.Unmarshal(out, &doc); err != nil {
				t.Fatal(err)
			}
			doc["mixed-port"] = mixedPort
			doc["log-level"] = "debug"
			doc["bind-address"] = "127.0.0.1"
			doc["external-controller"] = ""
			doc["dns"] = map[string]any{"enable": true, "ipv6": false, "use-system-hosts": false, "nameserver": []string{packet.LocalAddr().String()}, "proxy-server-nameserver": []string{packet.LocalAddr().String()}}
			out, err = yaml.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			file := filepath.Join(dir, "config.yaml")
			if err = os.WriteFile(file, out, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "-d", dir, "-f", file)
			log, err := os.Create(filepath.Join(dir, "client.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			cmd.Stdout, cmd.Stderr = log, log
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cancel(); _ = cmd.Wait() }()
			mixedAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(mixedPort))
			ready := false
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
				if conn, err := net.DialTimeout("tcp4", mixedAddress, 100*time.Millisecond); err == nil {
					_ = conn.Close()
					ready = true
					break
				}
				time.Sleep(25 * time.Millisecond)
			}
			if !ready {
				body, _ := os.ReadFile(log.Name())
				t.Fatalf("Mihomo did not listen: %s", body)
			}
			proxyURL, _ := url.Parse("http://" + mixedAddress)
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			// The socket opens before Mihomo completes provider and resolver
			// initialization. Allow that startup work to settle before the probe.
			time.Sleep(100 * time.Millisecond)
			response, err := client.Get("http://service.example.com/")
			if err != nil {
				body, _ := os.ReadFile(log.Name())
				t.Fatalf("request failed: %v\n%s", err, body)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != 200 || (mode != "both" && string(body) != mode) || !strings.HasPrefix(string(body), "ipv") {
				clientLog, _ := os.ReadFile(log.Name())
				t.Fatalf("unexpected response: %d %q, %v A=%d AAAA=%d proxyPort=%d\n%s", response.StatusCode, body, err, aQueries.Load(), aaaaQueries.Load(), port, clientLog)
			}
			if aQueries.Load() == 0 || aaaaQueries.Load() == 0 {
				t.Fatalf("node lookup was not dual stack: A=%d AAAA=%d", aQueries.Load(), aaaaQueries.Load())
			}
		})
	}
}

func TestMihomoDualStackProtocolsLive(t *testing.T) {
	binary := os.Getenv("BOSUN_MIHOMO_TEST_BINARY")
	if binary == "" {
		t.Skip("set BOSUN_MIHOMO_TEST_BINARY")
	}
	d := Design{Groups: []Group{{Name: "PROXY", Type: "select", Members: []string{"@all"}}}, Final: "PROXY", Enhancements: Enhancements{NodeDualStack: true}}
	tpl, err := d.Render("clash")
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []spec.Protocol{spec.VLESS, spec.VMess, spec.Trojan, spec.Shadowsocks, spec.AnyTLS, spec.Snell, spec.SOCKS, spec.HTTP, spec.Hysteria2, spec.TUIC, spec.Mieru, spec.WireGuard} {
		t.Run(string(protocol), func(t *testing.T) {
			line := subscription.Line{Name: "Node", Host: "node.example.com", Port: 443, UUID: "11111111-1111-1111-1111-111111111111", Password: "test-password", UserID: 1,
				Inbound: spec.Inbound{Protocol: protocol, Port: 443, Cipher: "aes-128-gcm", SnellPSK: "test-key", WGPrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}
			out, err := subscription.Clash{}.RenderWith([]subscription.Line{line}, subscription.Account{}, tpl)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			file := filepath.Join(dir, "config.yaml")
			if err = os.WriteFile(file, out, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "-t", "-d", dir, "-f", file)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("Mihomo rejected protocol %s: %v\n%s", protocol, err, output)
			}
		})
	}
}
