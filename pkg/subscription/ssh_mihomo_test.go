package subscription

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
	"golang.org/x/crypto/ssh"
)

// Opt in with BOSUN_TEST_MIHOMO_BIN pointing to an installed mihomo binary.
// Everything uses loopback and a private client directory; no existing client
// configuration, operating-system proxy setting or external service is used.
func TestSSHSubscriptionMihomo(t *testing.T) {
	binary := os.Getenv("BOSUN_TEST_MIHOMO_BIN")
	if binary == "" {
		t.Skip("set BOSUN_TEST_MIHOMO_BIN to exercise a real mihomo client")
	}
	version, err := exec.Command(binary, "-v").CombinedOutput()
	if err != nil {
		t.Fatalf("mihomo version: %v", err)
	}
	t.Log(strings.TrimSpace(string(version)))
	for _, pinned := range []bool{true, false} {
		t.Run(fmt.Sprintf("matching_host_key_%v", pinned), func(t *testing.T) {
			var delivered atomic.Int32
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				delivered.Add(1)
				_, _ = io.WriteString(w, "through SSH")
			}))
			defer origin.Close()
			readiness := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			defer readiness.Close()
			ib := spec.Inbound{Tag: "proxy-ssh", Protocol: spec.SSH}
			if err := ib.EnsureSSHKey(); err != nil {
				t.Fatal(err)
			}
			line := Line{Name: "SSH proxy", UUID: "subscriber", Password: "password:with#characters", Inbound: ib}
			signer, err := ssh.ParsePrivateKey([]byte(ib.SSH.PrivateKey))
			if err != nil {
				t.Fatal(err)
			}
			var authenticated atomic.Int32
			server := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
				if c.User() != "subscriber|proxy-ssh" || string(password) != line.Password {
					return nil, errors.New("unexpected proxy credentials")
				}
				authenticated.Add(1)
				return nil, nil
			}}
			server.AddHostKey(signer)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var connections sync.Map
			var attempted atomic.Int32
			var workers sync.WaitGroup
			workers.Go(func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					connections.Store(conn, true)
					attempted.Add(1)
					workers.Go(func() {
						defer connections.Delete(conn)
						defer conn.Close()
						_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
						sshConn, channels, requests, err := ssh.NewServerConn(conn, server)
						if err != nil {
							return
						}
						defer sshConn.Close()
						workers.Go(func() { ssh.DiscardRequests(requests) })
						for channel := range channels {
							var target struct {
								Host       string
								Port       uint32
								OriginHost string
								OriginPort uint32
							}
							if channel.ChannelType() != "direct-tcpip" || ssh.Unmarshal(channel.ExtraData(), &target) != nil || net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port))) != origin.Listener.Addr().String() {
								_ = channel.Reject(ssh.Prohibited, "only the loopback fixture is allowed")
								continue
							}
							upstream, err := net.DialTimeout("tcp", origin.Listener.Addr().String(), time.Second)
							if err != nil {
								_ = channel.Reject(ssh.ConnectionFailed, "fixture unavailable")
								continue
							}
							ch, reqs, err := channel.Accept()
							if err != nil {
								_ = upstream.Close()
								continue
							}
							workers.Go(func() { ssh.DiscardRequests(reqs) })
							workers.Go(func() {
								_, _ = io.Copy(upstream, ch)
								_ = upstream.Close()
								_ = ch.Close()
							})
							workers.Go(func() {
								_, _ = io.Copy(ch, upstream)
								_ = ch.Close()
								_ = upstream.Close()
							})
						}
					})
				}
			})
			t.Cleanup(func() {
				_ = listener.Close()
				connections.Range(func(key, _ any) bool { _ = key.(net.Conn).Close(); return true })
				workers.Wait()
			})
			line.Host, _, _ = net.SplitHostPort(listener.Addr().String())
			line.Port = listener.Addr().(*net.TCPAddr).Port
			if !pinned {
				other := spec.Inbound{Protocol: spec.SSH}
				if err := other.EnsureSSHKey(); err != nil {
					t.Fatal(err)
				}
				line.Inbound.SSH = other.SSH
			}
			probe, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			mixed := probe.Addr().String()
			port := probe.Addr().(*net.TCPAddr).Port
			_ = probe.Close()
			controllerListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			controller := controllerListener.Addr().String()
			_ = controllerListener.Close()
			tpl := fmt.Sprintf("mixed-port: %d\nexternal-controller: %s\nbind-address: 127.0.0.1\nallow-lan: false\nmode: rule\nlog-level: debug\nproxies: []\nproxy-groups: []\nrules: ['DST-PORT,%d,DIRECT', 'MATCH,SSH proxy']\n", port, controller, readiness.Listener.Addr().(*net.TCPAddr).Port)
			body, err := (Clash{}).RenderWith([]Line{line}, Account{}, tpl)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(binary, "-d", dir, "-f", path)
			logPath := filepath.Join(dir, "mihomo.log")
			log, err := os.Create(logPath)
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			cmd.Stdout, cmd.Stderr = log, log
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			ready := false
			controlTransport := &http.Transport{Proxy: nil}
			defer controlTransport.CloseIdleConnections()
			controlClient := &http.Client{Transport: controlTransport, Timeout: time.Second}
			deadline := time.Now().Add(15 * time.Second)
			for time.Now().Before(deadline) {
				response, err := controlClient.Get("http://" + controller + "/proxies/" + url.PathEscape(line.Name))
				if err == nil {
					var proxy map[string]any
					decodeErr := json.NewDecoder(response.Body).Decode(&proxy)
					_ = response.Body.Close()
					if response.StatusCode == http.StatusOK && decodeErr == nil && proxy["name"] == line.Name && proxy["udp"] == false {
						ready = true
						break
					}
				}
				time.Sleep(25 * time.Millisecond)
			}
			if !ready {
				t.Fatal("mihomo did not listen using the rendered SSH subscription")
			}
			proxyURL, _ := url.Parse("http://" + mixed)
			transport := origin.Client().Transport.(*http.Transport).Clone()
			transport.Proxy = http.ProxyURL(proxyURL)
			transport.DisableKeepAlives = true
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			// The controller and proxy listener open while mihomo's tunnel is
			// still suspended during initialization. Wait for a separate direct
			// loopback route; retrying the actual SSH request would hide failures.
			ready = false
			deadline = time.Now().Add(15 * time.Second)
			for time.Now().Before(deadline) {
				response, err := client.Get(readiness.URL)
				if response != nil {
					_ = response.Body.Close()
					ready = err == nil && response.StatusCode == http.StatusNoContent
				}
				if ready {
					break
				}
				time.Sleep(25 * time.Millisecond)
			}
			if !ready {
				t.Fatal("mihomo's proxy tunnel did not finish initialization")
			}
			response, err := client.Get(origin.URL)
			var content []byte
			if response != nil {
				content, _ = io.ReadAll(response.Body)
				_ = response.Body.Close()
			}
			if pinned {
				if err != nil || response == nil || response.StatusCode != http.StatusOK || string(content) != "through SSH" || delivered.Load() != 1 || authenticated.Load() == 0 {
					data, _ := os.ReadFile(logPath)
					t.Log(string(data))
					if response != nil {
						t.Logf("proxy status %d, body %q", response.StatusCode, content)
					}
					t.Fatalf("SSH proxy request failed: err=%v delivered=%d authenticated=%d", err, delivered.Load(), authenticated.Load())
				}
			} else if attempted.Load() == 0 || delivered.Load() != 0 || authenticated.Load() != 0 || err == nil && response.StatusCode == http.StatusOK {
				t.Fatal("mismatched SSH host key did not stop the proxy request")
			}
		})
	}
}
