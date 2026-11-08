package subscription

import (
	"bufio"
	"context"
	"encoding/json"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// These opt-in tests launch private loopback-only clients and an authoritative
// A/AAAA fixture. They do not change the user's running proxy or system DNS.
func TestIPVersionClientDial(t *testing.T) {
	for _, client := range []string{"mihomo", "singbox"} {
		t.Run(client, func(t *testing.T) {
			binary := os.Getenv("BOSUN_TEST_" + strings.ToUpper(client) + "_BIN")
			if binary == "" {
				t.Skip("set BOSUN_TEST_" + strings.ToUpper(client) + "_BIN")
			}
			for _, mode := range []string{"ipv4", "ipv6", "dual"} {
				t.Run(mode, func(t *testing.T) { ipVersionClientDial(t, client, binary, mode) })
			}
		})
	}
}

func ipVersionClientDial(t *testing.T, client, binary, mode string) {
	v4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer v4.Close()
	port := v4.Addr().(*net.TCPAddr).Port
	v6, err := net.Listen("tcp6", fmt.Sprintf("[::1]:%d", port))
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer v6.Close()
	var hits4, hits6 atomic.Int32
	handler := func(family string, hits *atomic.Int32) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				http.Error(w, "CONNECT required", 400)
				return
			}
			conn, rw, e := w.(http.Hijacker).Hijack()
			if e != nil {
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			fmt.Fprint(rw, "HTTP/1.1 200 Connection Established\r\n\r\n")
			rw.Flush()
			request, e := http.ReadRequest(bufio.NewReader(conn))
			if e != nil {
				return
			}
			request.Body.Close()
			hits.Add(1)
			fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(family), family)
		}
	}
	h4 := &http.Server{Handler: handler("ipv4", &hits4)}
	defer h4.Close()
	go h4.Serve(v4)
	h6 := &http.Server{Handler: handler("ipv6", &hits6)}
	defer h6.Close()
	go h6.Serve(v6)
	dnsConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsServer := &dns.Server{PacketConn: dnsConn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for _, q := range r.Question {
			if q.Name != "proxy.example.com." {
				continue
			}
			if q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}, A: net.ParseIP("127.0.0.1")})
			}
			if q.Qtype == dns.TypeAAAA {
				m.Answer = append(m.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0}, AAAA: net.ParseIP("::1")})
			}
		}
		_ = w.WriteMsg(m)
	})}
	go dnsServer.ActivateAndServe()
	defer dnsServer.Shutdown()
	// Reserve then release only this client's port. The proxy+DNS endpoints above
	// remain open for the whole test and cannot be reused by a following fixture.
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	clientPort := reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	line := ipPolicyLine(mode)
	line.Host = "proxy.example.com"
	line.Port = port
	line.Inbound = spec.Inbound{Protocol: spec.HTTP}
	dir := t.TempDir()
	var body []byte
	var args []string
	if client == "mihomo" {
		tpl := fmt.Sprintf("mixed-port: %d\nbind-address: 127.0.0.1\nallow-lan: false\nmode: rule\nlog-level: debug\ndns:\n  enable: true\n  ipv6: false\n  nameserver: ['udp://%s']\n  proxy-server-nameserver: ['udp://%s']\nrules: ['IP-CIDR,127.0.0.1/32,DIRECT,no-resolve', 'MATCH,family node']\n", clientPort, dnsConn.LocalAddr(), dnsConn.LocalAddr())
		body, err = (Clash{}).RenderWith([]Line{line}, Account{}, tpl)
		args = []string{"-d", dir, "-f", filepath.Join(dir, "config.yaml")}
	} else {
		body, err = (SingBox{}).Render([]Line{line}, Account{})
		if err != nil {
			t.Fatal(err)
		}
		var cfg map[string]any
		if err = json.Unmarshal(body, &cfg); err != nil {
			t.Fatal(err)
		}
		cfg["dns"] = m{"servers": []any{m{"tag": "local", "type": "udp", "server": "127.0.0.1", "server_port": dnsConn.LocalAddr().(*net.UDPAddr).Port}}}
		cfg["route"] = m{"default_domain_resolver": "local", "final": line.Name}
		cfg["inbounds"] = []any{m{"type": "mixed", "tag": "mixed", "listen": "127.0.0.1", "listen_port": clientPort}}
		cfg["outbounds"] = []any{cfg["outbounds"].([]any)[2]}
		body, err = json.Marshal(cfg)
		args = []string{"run", "-c", filepath.Join(dir, "config.json")}
	}
	if err != nil {
		t.Fatal(err)
	}
	config := args[len(args)-1]
	if err = os.WriteFile(config, body, 0600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(filepath.Join(dir, "client.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(clientPort))
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		c, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if e == nil {
			c.Close()
			ready = true
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if !ready {
		log, _ := os.ReadFile(logFile.Name())
		t.Fatalf("client not ready: %s", log)
	}
	proxy, _ := url.Parse("http://" + address)
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 4 * time.Second}
	if client == "mihomo" {
		readiness := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
		defer readiness.Close()
		ready = false
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
			response, e := httpClient.Get(readiness.URL)
			if response != nil {
				response.Body.Close()
				ready = e == nil && response.StatusCode == http.StatusNoContent
			}
			if ready {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		if !ready {
			t.Fatal("Mihomo tunnel did not initialize")
		}
	}
	response, err := httpClient.Get("http://target.example.com/probe")
	if err != nil {
		log, _ := os.ReadFile(logFile.Name())
		t.Fatalf("request: %v; %s", err, log)
	}
	result, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || mode != "dual" && string(result) != mode {
		log, _ := os.ReadFile(logFile.Name())
		t.Fatalf("unexpected %d %s: %s", response.StatusCode, result, log)
	}
	if mode == "dual" && string(result) != "ipv4" && string(result) != "ipv6" {
		t.Fatal("unknown endpoint", string(result))
	}
	if mode == "ipv4" && hits6.Load() != 0 || mode == "ipv6" && hits4.Load() != 0 {
		t.Fatal("wrong family was used")
	}
	// A strict choice must not fall back to the other healthy address family.
	if mode != "dual" {
		if mode == "ipv4" {
			h4.Close()
		} else {
			h6.Close()
		}
		response, err = httpClient.Get("http://target.example.com/probe2")
		if err == nil {
			defer response.Body.Close()
			if response.StatusCode == 200 {
				t.Fatal("only policy fell back")
			}
		}
		if mode == "ipv4" && hits6.Load() != 0 || mode == "ipv6" && hits4.Load() != 0 {
			t.Fatal("fallback reached opposite family")
		}
	}
}
