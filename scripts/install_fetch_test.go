package scripts

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestInstallerFetchIgnoresCurlConfig(t *testing.T) {
	start := strings.Index(Install, "fetch() {")
	if start < 0 {
		t.Fatal("fetch function missing")
	}
	end := strings.Index(Install[start:], "\n# YAML single-quoted")
	if end < 0 {
		t.Fatal("fetch function boundary missing")
	}
	script := "set -eu\n" + Install[start:start+end] + "\nfetch -o \"$TMP/download\" \"$1\"\n"
	for _, mode := range []string{"pair", "token", "github"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			var intendedHits, extraHits atomic.Int32
			extra := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				extraHits.Add(1)
				fmt.Fprint(w, "extra response")
			}))
			defer extra.Close()
			intended := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				intendedHits.Add(1)
				if r.URL.Path != "/release" || r.Header.Get("X-From-Curlrc") != "" {
					t.Error("download used curlrc request settings")
				}
				wantPair, wantAuth := "", ""
				if mode == "pair" {
					wantPair = "synthetic-pair"
				} else if mode == "token" {
					wantAuth = "Bearer synthetic-token"
				}
				if r.Header.Get("X-Bosun-Pair-Code") != wantPair || r.Header.Get("Authorization") != wantAuth {
					t.Error("download sent the wrong identity")
				}
				fmt.Fprint(w, "intended release")
			}))
			defer intended.Close()
			ca := filepath.Join(dir, "ca.pem")
			caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intended.Certificate().Raw})
			caPEM = append(caPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: extra.Certificate().Raw})...)
			if err := os.WriteFile(ca, caPEM, 0600); err != nil {
				t.Fatal(err)
			}
			// A default curl config can add another transfer. Custom credential
			// headers would be sent there even without following a redirect.
			curlrc := fmt.Sprintf("url = %q\nheader = \"X-From-Curlrc: unexpected\"\n", extra.URL+"/extra")
			if err := os.WriteFile(filepath.Join(dir, ".curlrc"), []byte(curlrc), 0600); err != nil {
				t.Fatal(err)
			}
			tokenFile := filepath.Join(dir, "token")
			if err := os.WriteFile(tokenFile, []byte("synthetic-token"), 0600); err != nil {
				t.Fatal(err)
			}
			source, pair := "captain", ""
			if mode == "github" {
				source = "github"
			} else if mode == "pair" {
				pair = "synthetic-pair"
			}
			cmd := exec.Command("sh", "-c", script, "fetch-test", intended.URL+"/release")
			cmd.Env = append(os.Environ(), "TMP="+dir, "DOWNLOAD_SOURCE="+source, "PAIR="+pair, "TOKEN_FILE="+tokenFile, "CURL_HOME="+dir, "CURL_CA_BUNDLE="+ca, "NO_PROXY=*", "no_proxy=*")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("fetch failed: %v %s", err, out)
			}
			if intendedHits.Load() != 1 || extraHits.Load() != 0 {
				t.Fatalf("fetch requested %d intended and %d curlrc URLs", intendedHits.Load(), extraHits.Load())
			}
			body, err := os.ReadFile(filepath.Join(dir, "download"))
			if err != nil || string(body) != "intended release" {
				t.Fatalf("download output changed: %v", err)
			}
			if strings.Contains(string(out), "synthetic-pair") || strings.Contains(string(out), "synthetic-token") {
				t.Fatal("credential printed")
			}
		})
	}
}
