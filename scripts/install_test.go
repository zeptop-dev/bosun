package scripts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Run the real bootstrap through its checksum stage, stopping immediately
// before the first host mutation. Network calls use a local TLS Captain and
// uname/id/init-system discovery are isolated stubs.
func TestCaptainBootstrapDownloadsAndChecksWithoutGitHub(t *testing.T) {
	for _, fail := range []string{"", "old-version", "checksum", "redirect"} {
		t.Run(fail, func(t *testing.T) {
			dir := t.TempDir()
			bin := []byte("fake bosun release")
			digest := sha256.Sum256(bin)
			hits := []string{}
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits = append(hits, r.URL.Path)
				if r.Header.Get("Authorization") != "" {
					t.Error("old permanent token sent during fresh pairing")
				}
				if r.Header.Get("X-Bosun-Pair-Code") != "ABCD-EFGH" {
					t.Error("missing pair header")
				}
				if fail == "redirect" {
					http.Redirect(w, r, "https://example.com/package", 302)
					return
				}
				switch {
				case strings.HasSuffix(r.URL.Path, "/releases/latest"):
					v := "v0.88.0"
					if fail == "old-version" {
						v = "v0.87.0"
					}
					fmt.Fprintf(w, `{"tag_name":%q}`, v)
				case strings.HasSuffix(r.URL.Path, "/bosun-linux-amd64"):
					w.Write(bin)
				case strings.HasSuffix(r.URL.Path, "/SHA256SUMS"):
					sum := hex.EncodeToString(digest[:])
					if fail == "checksum" {
						sum = strings.Repeat("0", 64)
					}
					fmt.Fprintf(w, "%s  bosun-linux-amd64\n", sum)
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
					http.NotFound(w, r)
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
			end := strings.Index(Install, "if [ \"$MODE\" = binary ]; then install -m 0755")
			if end < 0 {
				t.Fatal("installer mutation boundary not found")
			}
			script := filepath.Join(dir, "install.sh")
			os.WriteFile(script, []byte(Install[:end]+"echo verified\n"), 0600)
			oldToken := filepath.Join(dir, "absent-token")
			os.WriteFile(oldToken, []byte("old-node-token"), 0600)
			cmd := exec.Command("sh", script, "--captain", srv.URL, "--pair", "ABCD-EFGH", "--download-source", "captain", "--token-file", filepath.Join(dir, "absent-token"), "--monitor-only")
			cmd.Env = append(os.Environ(), "PATH="+stub+string(os.PathListSeparator)+os.Getenv("PATH"), "CURL_CA_BUNDLE="+ca)
			output, err := cmd.CombinedOutput()
			if fail == "" {
				if err != nil || !strings.Contains(string(output), "verified") {
					t.Fatalf("bootstrap: %v %s", err, output)
				}
				if len(hits) != 3 {
					t.Fatalf("hits %v", hits)
				}
			} else if err == nil {
				t.Fatalf("expected %s failure: %s", fail, output)
			}
		})
	}
}

func TestCaptainBootstrapRefusesCredentialDestinationChangesBeforeNetworking(t *testing.T) {
	for _, scenario := range []string{"different-endpoint", "unreadable-config", "unknown-owner", "orphan-token"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			stub := filepath.Join(dir, "bin")
			os.Mkdir(stub, 0755)
			marker := filepath.Join(dir, "network")
			for name, body := range map[string]string{"uname": "echo Linux", "id": "echo 0", "curl": "touch '" + marker + "'; exit 1"} {
				os.WriteFile(filepath.Join(stub, name), []byte("#!/bin/sh\n"+body+"\n"), 0755)
			}
			cfg := filepath.Join(dir, "config.yaml")
			os.WriteFile(cfg, []byte("existing"), 0600)
			token := filepath.Join(dir, "token")
			os.WriteFile(token, []byte("existing-token"), 0600)
			helper := filepath.Join(dir, "bosun")
			body := "case \"$1\" in installer-download-config) printf 'captain\\nhttps://old.example.com:18443\\n" + token + "\\n';; version) echo 'bosun v0.88.0';; esac"
			if scenario == "unreadable-config" {
				body = "case \"$1\" in installer-download-config) exit 1;; version) echo 'bosun v0.88.0';; esac"
			}
			if scenario == "unknown-owner" {
				body = "case \"$1\" in installer-download-config) exit 1;; version) echo 'bosun v0.87.0';; esac"
			}
			if scenario == "orphan-token" {
				body = "case \"$1\" in installer-download-config) printf 'github\\n\\n\\n';; version) echo 'bosun v0.88.0';; esac"
			}
			os.WriteFile(helper, []byte("#!/bin/sh\n"+body+"\n"), 0755)
			script := strings.ReplaceAll(Install, "NATIVE=/usr/local/bin/bosun", "NATIVE="+helper)
			script = strings.ReplaceAll(script, "/etc/bosun/config.yaml", cfg)
			scriptPath := filepath.Join(dir, "install.sh")
			os.WriteFile(scriptPath, []byte(script), 0600)
			args := []string{scriptPath, "upgrade", "--captain", "https://new.example.com:18443", "--token-file", token}
			if scenario != "unreadable-config" {
				args = append(args, "--download-source", "captain")
			}
			cmd := exec.Command("sh", args...)
			cmd.Env = append(os.Environ(), "PATH="+stub+string(os.PathListSeparator)+os.Getenv("PATH"))
			output, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("expected refusal: %s", output)
			}
			if _, err := os.Stat(marker); err == nil {
				t.Fatalf("network request occurred: %s", output)
			}
			if !strings.Contains(string(output), "endpoint differs") && !strings.Contains(string(output), "Cannot read existing") && !strings.Contains(string(output), "Cannot verify the destination") {
				t.Fatalf("unexpected refusal: %s", output)
			}
		})
	}
}
