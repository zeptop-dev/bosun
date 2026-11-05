package scripts

import (
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func preflightScript(t *testing.T) string {
	t.Helper()
	start := strings.Index(Install, "captain_preflight() {")
	end := strings.Index(Install[start:], "\n# In Captain mode")
	if start < 0 || end < 0 {
		t.Fatal("preflight function missing")
	}
	return "set -eu\n" + Install[start:start+end] + "\ncaptain_preflight\necho preflight-verified\n"
}
func runPreflight(t *testing.T, endpoint, action string, env ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", "-c", preflightScript(t))
	cmd.Env = append(os.Environ(), "CAPTAIN="+endpoint, "ACTION="+action, "PAIR=secret-pair-code", "TOKEN_FILE=/unused-secret-token", "NO_PROXY=*", "no_proxy=*")
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
func TestCaptainPreflightRealTLSCompatibilityAndFailure(t *testing.T) {
	cases := []struct {
		name, agent, main        string
		status                   int
		want                     string
		fallback, chunked, trust bool
	}{
		{name: "dedicated", agent: `{"ok":true,"service":"captain-agent"}`, status: 200, trust: true},
		{name: "legacy-main-404", agent: "not found", main: `{"ok":true,"time":1793836800}`, status: 404, fallback: true, trust: true},
		{name: "legacy-main-405", agent: "method", main: "{ \"time\": 1793836800,\n \"ok\": true }", status: 405, fallback: true, trust: true},
		{name: "main-spa-fallback", agent: "<html>Captain</html>", main: `{"ok":true,"time":1793836800}`, status: 200, fallback: true, trust: true},
		{name: "non-captain", agent: `{"ok":true}`, main: `{"ok":true}`, status: 200, fallback: true, trust: true, want: "neither Agent nor main health"},
		{name: "no-routes", agent: "404", main: "404", status: 404, fallback: true, trust: true, want: "neither Agent nor main health"},
		{name: "redirect", status: 302, trust: true, want: "redirect refused"},
		{name: "origin-refused", status: 521, trust: true, want: "HTTP 521"},
		{name: "origin-timeout", agent: strings.Repeat("large-proxy-error-page", 1000), status: 522, trust: true, want: "HTTP 522"},
		{name: "origin-tls", status: 525, trust: true, want: "HTTP 525"},
		{name: "origin-certificate", status: 526, trust: true, want: "HTTP 526"},
		{name: "untrusted-tls", status: 200, agent: `{"ok":true,"service":"captain-agent"}`, want: "TLS verification"},
		{name: "html-with-marker", agent: `<html>{"ok":true,"service":"captain-agent"}</html>`, status: 200, trust: true, fallback: true, want: "neither Agent nor main health"},
		{name: "duplicate-json", agent: `{"ok":false,"ok":true,"service":"captain-agent"}`, status: 200, trust: true, fallback: true, want: "neither Agent nor main health"},
		{name: "newline-in-string", agent: "{\"ok\":true,\"service\":\"captain-\nagent\"}", status: 200, trust: true, fallback: true, want: "neither Agent nor main health"},
		{name: "whitespace-in-string", agent: `{"ok":true,"service":"cap tain-agent"}`, status: 200, trust: true, fallback: true, want: "neither Agent nor main health"},
		{name: "oversized", agent: `{"ok":true,"service":"captain-agent"}` + strings.Repeat(" ", 20000), status: 200, trust: true, want: "size limit"},
		{name: "chunked-oversized", agent: `{"ok":true,"service":"captain-agent"}` + strings.Repeat(" ", 20000), status: 200, trust: true, chunked: true, want: "size limit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			hits := []string{}
			credentials := false
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits = append(hits, r.URL.Path)
				if r.Header.Get("Authorization") != "" || r.Header.Get("X-Bosun-Pair-Code") != "" || r.URL.RawQuery != "" {
					credentials = true
				}
				if r.URL.Path == "/api/health" {
					fmt.Fprint(w, tc.main)
					return
				}
				if r.URL.Path != "/api/agent/health" {
					t.Errorf("followed unexpected path %s", r.URL.Path)
					return
				}
				w.Header().Set("Location", "/should-not-follow?secret-response-value")
				if !tc.chunked {
					w.Header().Set("Content-Length", fmt.Sprint(len(tc.agent)))
				}
				w.WriteHeader(tc.status)
				if tc.chunked {
					w.(http.Flusher).Flush()
				}
				fmt.Fprint(w, tc.agent)
			}))
			srv.Config.ErrorLog = log.New(io.Discard, "", 0)
			srv.StartTLS()
			defer srv.Close()
			ca := filepath.Join(dir, "ca.pem")
			os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600)
			env := []string{}
			if tc.trust {
				env = append(env, "CURL_CA_BUNDLE="+ca)
			}
			// curlrc would leak credentials or bypass TLS if -q were absent.
			os.WriteFile(filepath.Join(dir, ".curlrc"), []byte("header = \"Authorization: secret-from-curlrc\"\n"), 0600)
			env = append(env, "CURL_HOME="+dir)
			output, err := runPreflight(t, srv.URL, "install", env...)
			if tc.want == "" {
				if err != nil || !strings.Contains(output, "preflight-verified") {
					t.Fatalf("%v %s", err, output)
				}
			} else if err == nil || !strings.Contains(output, tc.want) {
				t.Fatalf("expected %q failure: %v %s", tc.want, err, output)
			}
			if credentials {
				t.Fatal("preflight sent credentials")
			}
			if tc.trust {
				want := []string{"/api/agent/health"}
				if tc.fallback {
					want = append(want, "/api/health")
				}
				if !reflect.DeepEqual(hits, want) {
					t.Fatalf("requests %v want %v", hits, want)
				}
			}
			for _, secret := range []string{srv.URL, "secret-pair-code", "secret-response-value", "secret-from-curlrc", tc.agent} {
				if secret != "" && strings.Contains(output, secret) {
					t.Fatal("response/url/credential leaked")
				}
			}
		})
	}
}

func TestCaptainPreflightHTTPPathAndConnectionFailure(t *testing.T) {
	hits := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		if r.URL.Path == "/panel/api/agent/health" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"ok":true,"time":1793836800}`)
	}))
	out, err := runPreflight(t, srv.URL+"/panel/", "upgrade")
	if err != nil || !reflect.DeepEqual(hits, []string{"/panel/api/agent/health", "/panel/api/health"}) {
		t.Fatalf("HTTP prefix compatibility: %v %v %s", err, hits, out)
	}
	srv.Close()
	out, err = runPreflight(t, srv.URL, "install")
	if err == nil || !strings.Contains(out, "connection failed") {
		t.Fatalf("closed listener: %v %s", err, out)
	}
}

func TestCaptainPreflightClassifiedCurlErrorsAndOfflineSkip(t *testing.T) {
	for _, tc := range []struct {
		code int
		want string
	}{{5, "DNS resolution"}, {6, "DNS resolution"}, {7, "connection failed"}, {28, "timed out"}, {35, "TLS verification"}, {60, "TLS verification"}, {63, "size limit"}, {52, "HTTP transport"}} {
		t.Run(fmt.Sprint(tc.code), func(t *testing.T) {
			dir := t.TempDir()
			stub := filepath.Join(dir, "curl")
			body := fmt.Sprintf("#!/bin/sh\n[ \"$1\" = -q ] || exit 98\nprintf 'private diagnostic with credential-url' >&2\nexit %d\n", tc.code)
			os.WriteFile(stub, []byte(body), 0755)
			out, err := runPreflight(t, "https://example.com:18443", "install", "PATH="+dir+":"+os.Getenv("PATH"))
			if err == nil || !strings.Contains(out, tc.want) || strings.Contains(out, "private diagnostic") || strings.Contains(out, "example.com") {
				t.Fatalf("%v %s", err, out)
			}
		})
	}
	for _, tc := range []struct{ action, url string }{{"uninstall", "https://example.com"}, {"enable-web-upgrade", "https://example.com"}, {"install", ""}, {"upgrade", ""}} {
		out, err := runPreflight(t, tc.url, tc.action, "PATH=/missing-curl")
		if err != nil || strings.Contains(out, "endpoint check passed") {
			t.Fatalf("skip %v: %v %s", tc, err, out)
		}
	}
	for _, endpoint := range []string{"https://user:secret@example.com", "https://example.com?secret=token", "https://example.com/#secret", "https://example.com\nAuthorization: secret"} {
		out, err := runPreflight(t, endpoint, "install")
		if err == nil || !strings.Contains(out, "invalid endpoint") || strings.Contains(out, "secret") {
			t.Fatalf("URL validation %v %s", err, out)
		}
	}
}

// Run the whole installer to its host-mutation boundary. For upgrades the real
// worker download/checksum path executes; only binary execution/mutation stops.
func TestCaptainPreflightRunsBeforeInstallAndUpgradeDownloads(t *testing.T) {
	for _, action := range []string{"install", "upgrade"} {
		for _, fail := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-fail-%t", action, fail), func(t *testing.T) {
				dir := t.TempDir()
				bin := []byte("synthetic binary")
				sum := sha256.Sum256(bin)
				hits := []string{}
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits = append(hits, r.URL.Path)
					if r.URL.Path == "/api/agent/health" {
						if r.Header.Get("Authorization") != "" || r.Header.Get("X-Bosun-Pair-Code") != "" {
							t.Error("preflight credentials leaked")
						}
						if fail {
							w.WriteHeader(522)
							fmt.Fprint(w, "private-error-body")
							return
						}
						fmt.Fprint(w, `{"ok":true,"service":"captain-agent"}`)
						return
					}
					if len(hits) < 2 || hits[0] != "/api/agent/health" {
						t.Error("download preceded preflight")
					}
					if action == "upgrade" {
						if r.Header.Get("Authorization") != "Bearer existing-token" || r.Header.Get("X-Bosun-Pair-Code") != "" {
							t.Error("upgrade identity")
						}
					} else if r.Header.Get("X-Bosun-Pair-Code") != "ABCD-EFGH" || r.Header.Get("Authorization") != "" {
						t.Error("install identity")
					}
					switch {
					case strings.HasSuffix(r.URL.Path, "/releases/latest"):
						fmt.Fprint(w, `{"tag_name":"v0.89.0"}`)
					case strings.HasSuffix(r.URL.Path, "/bosun-linux-amd64"):
						w.Write(bin)
					case strings.HasSuffix(r.URL.Path, "/SHA256SUMS"):
						fmt.Fprintf(w, "%x  bosun-linux-amd64\n", sum)
					default:
						t.Errorf("unexpected download %s", r.URL.Path)
					}
				}))
				defer srv.Close()
				ca := filepath.Join(dir, "ca.pem")
				os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600)
				stub := filepath.Join(dir, "bin")
				os.Mkdir(stub, 0755)
				for name, body := range map[string]string{"uname": "case \"$1\" in -s) echo Linux;; -m) echo x86_64;; esac", "id": "echo 0", "systemctl": "exit 0"} {
					os.WriteFile(filepath.Join(stub, name), []byte("#!/bin/sh\n"+body+"\n"), 0755)
				}
				native := filepath.Join(dir, "bosun")
				cfg := filepath.Join(dir, "config.yaml")
				token := filepath.Join(dir, "token")
				script := Install
				script = strings.ReplaceAll(script, "NATIVE=/usr/local/bin/bosun", "NATIVE="+native)
				script = strings.ReplaceAll(script, "/etc/bosun/config.yaml", cfg)
				script = strings.ReplaceAll(script, "/usr/local/lib/$PRODUCT-updater/worker", filepath.Join(dir, "absent-worker"))
				args := []string{action, "--captain", srv.URL, "--download-source", "captain", "--mode", "binary"}
				if action == "upgrade" {
					os.WriteFile(cfg, []byte("existing config"), 0600)
					os.WriteFile(token, []byte("existing-token"), 0600)
					body := fmt.Sprintf("#!/bin/sh\ncase \"$1\" in installer-download-config) printf 'captain\\n%s\\n%s\\n';; version) echo 'bosun v0.89.0';; esac\n", srv.URL, token)
					os.WriteFile(native, []byte(body), 0755)
					script = strings.Replace(script, "    \"$WORKER\" installer-check-layout", "    echo verified-before-mutation; exit 0\n    \"$WORKER\" installer-check-layout", 1)
				} else {
					args = append(args, "--pair", "ABCD-EFGH")
					end := strings.Index(script, "if [ \"$MODE\" = binary ]; then mkdir -p")
					if end < 0 {
						t.Fatal("mutation boundary missing")
					}
					script = script[:end] + "echo verified-before-mutation\n"
				}
				path := filepath.Join(dir, "install.sh")
				os.WriteFile(path, []byte(script), 0600)
				cmd := exec.Command("sh", append([]string{path}, args...)...)
				cmd.Env = append(os.Environ(), "PATH="+stub+":"+os.Getenv("PATH"), "CURL_CA_BUNDLE="+ca, "NO_PROXY=*", "no_proxy=*")
				out, err := cmd.CombinedOutput()
				if fail {
					if err == nil || !strings.Contains(string(out), "HTTP 522") || !reflect.DeepEqual(hits, []string{"/api/agent/health"}) {
						t.Fatalf("failed preflight continued: %v %v %s", err, hits, out)
					}
				} else {
					if err != nil || !strings.Contains(string(out), "verified-before-mutation") || len(hits) < 4 {
						t.Fatalf("successful flow %v %v %s", err, hits, out)
					}
				}
				if strings.Contains(string(out), "existing-token") || strings.Contains(string(out), "ABCD-EFGH") || strings.Contains(string(out), "private-error-body") {
					t.Fatal("credentials/body in diagnostics")
				}
			})
		}
	}
}

func TestCaptainPreflightRealTimeoutIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer srv.Close()
	start := time.Now()
	output, err := runPreflight(t, srv.URL, "install")
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(output, "timed out") || elapsed > 15*time.Second {
		t.Fatalf("timeout not bounded: %s %v %s", elapsed, err, output)
	}
}
