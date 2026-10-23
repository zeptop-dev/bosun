package subdesign

import (
	"context"
	"encoding/base64"
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
	"gopkg.in/yaml.v3"
)

// Real DNS exchanges through a real Mihomo process, all within loopback. The
// route intentionally proxies the resolver IP, like a BackCN preset can do to
// domestic DNS IPs. Explicit DIRECT must win for domestic/bootstrap lookups,
// while foreign lookups must traverse the chosen proxy. No public DNS or
// production proxy is contacted, and no client configuration is read.
func TestMihomoProtectedDNSRoutingLive(t *testing.T) {
	binary := os.Getenv("BOSUN_MIHOMO_TEST_BINARY")
	if binary == "" {
		t.Skip("set BOSUN_MIHOMO_TEST_BINARY")
	}
	var bootstrapQueries, foreignQueries, proxyConnections atomic.Int64
	serveDNS := func(count *atomic.Int64) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var data []byte
			var err error
			if r.Method == http.MethodGet {
				data, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
			} else {
				data, err = io.ReadAll(io.LimitReader(r.Body, 65536))
			}
			if err != nil {
				http.Error(w, "bad request", 400)
				return
			}
			var q dns.Msg
			if err = q.Unpack(data); err != nil || len(q.Question) != 1 {
				http.Error(w, "bad query", 400)
				return
			}
			count.Add(1)
			reply := new(dns.Msg)
			reply.SetReply(&q)
			if q.Question[0].Qtype == dns.TypeA {
				ip := net.ParseIP("198.51.100.20")
				if q.Question[0].Name == "proxy.example.com." {
					ip = net.ParseIP("127.0.0.1")
				}
				reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: ip}}
			}
			body, err := reply.Pack()
			if err != nil {
				http.Error(w, "bad response", 500)
				return
			}
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(body)
		})
	}
	bootstrap := httptest.NewTLSServer(serveDNS(&bootstrapQueries))
	defer bootstrap.Close()
	foreign := httptest.NewTLSServer(serveDNS(&foreignQueries))
	defer foreign.Close()
	bootstrapURL, _ := url.Parse(bootstrap.URL)
	foreignURL, _ := url.Parse(foreign.URL)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || (r.Host != bootstrapURL.Host && r.Host != foreignURL.Host) {
			http.Error(w, "unsupported target", 400)
			return
		}
		upstream, err := net.DialTimeout("tcp", r.Host, time.Second)
		if err != nil {
			http.Error(w, "connect failed", 502)
			return
		}
		defer upstream.Close()
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		_ = upstream.SetDeadline(time.Now().Add(15 * time.Second))
		proxyConnections.Add(1)
		_, _ = buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buf.Flush()
		go func() { _, _ = io.Copy(upstream, conn) }()
		_, _ = io.Copy(conn, upstream)
	}))
	defer proxy.Close()
	_, proxyPortText, _ := net.SplitHostPort(proxy.Listener.Addr().String())
	proxyPort, _ := strconv.Atoi(proxyPortText)
	d := Design{Groups: []Group{{Name: "PROXY", Type: "select", Members: []string{"@all"}}}, Final: "PROXY", Enhancements: Enhancements{DNSProtection: true, DNSPolicy: "PROXY"}}
	tpl, err := d.Render("clash")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = yaml.Unmarshal([]byte(tpl), &doc); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	controller := listener.Addr().String()
	_ = listener.Close()
	doc["mixed-port"] = 0
	doc["external-controller"] = controller
	doc["log-level"] = "silent"
	doc["proxies"] = []any{map[string]any{"name": "LOCAL", "type": "http", "server": "proxy.example.com", "port": proxyPort}}
	doc["proxy-groups"] = []any{map[string]any{"name": "PROXY", "type": "select", "proxies": []string{"LOCAL"}}}
	doc["rules"] = []string{"IP-CIDR,127.0.0.0/8,PROXY,no-resolve", "MATCH,DIRECT"}
	configDNS := doc["dns"].(map[string]any)
	configDNS["use-system-hosts"] = false
	replace := func(original any, endpoint string) []any {
		items := original.([]any)
		_, fragment, _ := strings.Cut(items[0].(string), "#")
		if fragment != "" {
			fragment += "&"
		}
		return []any{endpoint + "/dns-query#" + fragment + "skip-cert-verify=true"}
	}
	for _, key := range []string{"default-nameserver", "proxy-server-nameserver", "direct-nameserver"} {
		configDNS[key] = replace(configDNS[key], bootstrap.URL)
	}
	configDNS["nameserver"] = replace(configDNS["nameserver"], foreign.URL)
	originalPolicies := configDNS["nameserver-policy"].(map[string]any)
	configDNS["nameserver-policy"] = map[string]any{"cn.example.com": replace(originalPolicies["+.cn"], bootstrap.URL)}
	dir := t.TempDir()
	file := filepath.Join(dir, "config.yaml")
	out, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(file, out, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-d", dir, "-f", file)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second}
	ready := time.Now().Add(5 * time.Second)
	for {
		r, err := client.Get("http://" + controller + "/version")
		if err == nil {
			_ = r.Body.Close()
			break
		}
		if time.Now().After(ready) {
			t.Fatal("Mihomo did not start")
		}
		time.Sleep(25 * time.Millisecond)
	}
	query := func(name string) {
		t.Helper()
		r, err := client.Get("http://" + controller + "/dns/query?name=" + name + "&type=A")
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode != 200 || !strings.Contains(string(b), "198.51.100.20") {
			t.Fatalf("DNS query failed: %s", b)
		}
	}
	query("foreign.example.com")
	if bootstrapQueries.Load() == 0 || foreignQueries.Load() == 0 || proxyConnections.Load() == 0 {
		t.Fatal("node bootstrap and proxied DNS were not both exercised")
	}
	count := proxyConnections.Load()
	query("cn.example.com")
	if proxyConnections.Load() != count {
		t.Fatal("domestic DNS followed BackCN-style proxy routing instead of explicit DIRECT")
	}
}
