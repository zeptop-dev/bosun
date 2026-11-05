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

	"gopkg.in/yaml.v3"
)

func TestGeneratedGitHubConfigurationRemainsCompatibleWithOldReleases(t *testing.T) {
	start := strings.Index(Install, "NODE_MODE_LINE=\"\"")
	if start < 0 {
		t.Fatal("configuration generation start missing")
	}
	end := strings.Index(Install[start:], "\nif [ \"$MODE\" = docker ]; then")
	quoteStart := strings.Index(Install, "yaml_quote()")
	if end < 0 || quoteStart < 0 {
		t.Fatal("configuration generation boundaries missing")
	}
	quoteEnd := strings.IndexByte(Install[quoteStart:], '\n')
	for _, source := range []string{"github", "captain"} {
		t.Run(source, func(t *testing.T) {
			dir := t.TempDir()
			body := Install[quoteStart:quoteStart+quoteEnd] + "\n" + Install[start:start+end]
			body = strings.ReplaceAll(body, "/etc/bosun", filepath.Join(dir, "etc"))
			body = strings.ReplaceAll(body, "/var/lib/bosun", filepath.Join(dir, "data"))
			cmd := exec.Command("sh", "-eu", "-c", body)
			cmd.Env = append(os.Environ(), "NODE_MODE=monitor", "OPENWRT=0", "DATA_DIR="+filepath.Join(dir, "data"), "CAPTAIN=https://example.com:18443", "PAIR=ABCD-EFGH", "DOWNLOAD_SOURCE="+source, "TOKEN_FILE="+filepath.Join(dir, "data", "captain.token"), "WEB_LISTEN=:2053")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("configuration generation: %v %s", err, output)
			}
			raw, err := os.ReadFile(filepath.Join(dir, "etc", "config.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			var cfg struct {
				Panel struct {
					Captain yaml.Node `yaml:"captain"`
				} `yaml:"panel"`
			}
			if err := yaml.Unmarshal(raw, &cfg); err != nil {
				t.Fatal(err)
			}
			captain, err := yaml.Marshal(&cfg.Panel.Captain)
			if err != nil {
				t.Fatal(err)
			}
			if source == "github" {
				// These are the Captain fields accepted by released v0.88.0.
				var legacy struct {
					URL       string `yaml:"url"`
					PairCode  string `yaml:"pair_code"`
					TokenFile string `yaml:"token_file"`
				}
				decoder := yaml.NewDecoder(strings.NewReader(string(captain)))
				decoder.KnownFields(true)
				if err := decoder.Decode(&legacy); err != nil {
					t.Fatalf("GitHub default rejected by released configuration schema: %v", err)
				}
				if legacy.URL != "https://example.com:18443" || legacy.PairCode != "ABCD-EFGH" || legacy.TokenFile != filepath.Join(dir, "data", "captain.token") {
					t.Fatalf("lost connection settings: %+v", legacy)
				}
			} else {
				var fields map[string]string
				if err := yaml.Unmarshal(captain, &fields); err != nil || fields["download_source"] != "captain" {
					t.Fatalf("Captain source not retained: %v %+v", err, fields)
				}
			}
		})
	}
}

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
				if r.URL.Path == "/api/agent/health" {
					if r.Header.Get("Authorization") != "" || r.Header.Get("X-Bosun-Pair-Code") != "" {
						t.Error("preflight sent credentials")
					}
					fmt.Fprint(w, `{"ok":true,"service":"captain-agent"}`)
					return
				}
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
					v := "v0.89.0"
					if fail == "old-version" {
						v = "v0.88.0"
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
			end := strings.Index(Install, "if [ \"$MODE\" = binary ]; then mkdir -p")
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
				if len(hits) != 4 || hits[0] != "/api/agent/health" {
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
			body := "case \"$1\" in installer-download-config) printf 'captain\\nhttps://old.example.com:18443\\n" + token + "\\n';; version) echo 'bosun v0.89.0';; esac"
			if scenario == "unreadable-config" {
				body = "case \"$1\" in installer-download-config) exit 1;; version) echo 'bosun v0.89.0';; esac"
			}
			if scenario == "unknown-owner" {
				body = "case \"$1\" in installer-download-config) exit 1;; version) echo 'bosun v0.88.0';; esac"
			}
			if scenario == "orphan-token" {
				body = "case \"$1\" in installer-download-config) printf 'github\\n\\n\\n';; version) echo 'bosun v0.89.0';; esac"
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

func TestCaptainOfflineUninstallUsesCachedWorkerWithoutToken(t *testing.T) {
	dir := t.TempDir()
	stub := filepath.Join(dir, "bin")
	os.Mkdir(stub, 0755)
	for name, body := range map[string]string{"uname": "echo Linux", "id": "echo 0", "stat": "echo 0", "curl": "echo unexpected-network >&2; exit 99"} {
		os.WriteFile(filepath.Join(stub, name), []byte("#!/bin/sh\n"+body+"\n"), 0755)
	}
	cfg := filepath.Join(dir, "config.yaml")
	os.WriteFile(cfg, []byte("existing"), 0600)
	token := filepath.Join(dir, "deleted-token")
	helper := filepath.Join(dir, "bosun")
	os.WriteFile(helper, []byte("#!/bin/sh\nprintf 'captain\\nhttps://example.com:18443\\n"+token+"\\n'\n"), 0755)
	worker := filepath.Join(dir, "worker")
	marker := filepath.Join(dir, "uninstalled")
	os.WriteFile(worker, []byte("#!/bin/sh\ncase \"$1\" in installer-version) echo 1;; uninstall) touch '"+marker+"';; *) exit 1;; esac\n"), 0755)
	script := strings.ReplaceAll(Install, "NATIVE=/usr/local/bin/bosun", "NATIVE="+helper)
	script = strings.ReplaceAll(script, "/etc/bosun/config.yaml", cfg)
	script = strings.ReplaceAll(script, "/usr/local/lib/$PRODUCT-updater/worker", worker)
	path := filepath.Join(dir, "install.sh")
	os.WriteFile(path, []byte(script), 0600)
	cmd := exec.Command("sh", path, "uninstall", "--yes", "--keep-data")
	cmd.Env = append(os.Environ(), "PATH="+stub+string(os.PathListSeparator)+os.Getenv("PATH"))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("offline uninstall: %v %s", err, output)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("cached worker was not invoked")
	}
}

func TestOfflineUninstallWithBrokenConfigUsesOnlyVerifiedPrivateWorker(t *testing.T) {
	cases := []struct {
		name, config, cache           string
		keep, confirm, removeOriginal bool
	}{
		{"corrupt-config", "corrupt", "valid", false, true, false},
		{"unreadable-config", "unreadable", "valid", true, true, false},
		{"confirmation-required", "corrupt", "valid", false, false, false},
		{"copied-before-original-disappears", "corrupt", "valid", true, true, true},
	}
	for _, fault := range []string{"corrupt", "unreadable"} {
		for _, cache := range []string{"missing", "invalid", "unowned", "writable", "symlink", "not-executable"} {
			cases = append(cases, struct {
				name, config, cache           string
				keep, confirm, removeOriginal bool
			}{fault + "-" + cache, fault, cache, false, true, false})
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			stub := filepath.Join(dir, "bin")
			os.Mkdir(stub, 0755)
			network := filepath.Join(dir, "network")
			configRead := filepath.Join(dir, "config-read")
			owner, mode := "0", "755"
			if tc.cache == "unowned" {
				owner = "1000"
			}
			if tc.cache == "writable" {
				mode = "777"
			}
			commands := map[string]string{
				"uname": "echo Linux", "id": "echo 0",
				"stat": "case \"$2\" in %u) echo " + owner + ";; %a) echo " + mode + ";; *) exit 1;; esac",
				"curl": "touch '" + network + "'; exit 99",
			}
			for name, body := range commands {
				if err := os.WriteFile(filepath.Join(stub, name), []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			cfg := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(cfg, []byte("invalid: ["), 0600); err != nil {
				t.Fatal(err)
			}
			if tc.config == "unreadable" {
				if err := os.Chmod(cfg, 0000); err != nil {
					t.Fatal(err)
				}
			}
			native := filepath.Join(dir, "bosun")
			helper := "#!/bin/sh\ncase \"$1\" in installer-download-config) touch '" + configRead + "'; echo 'config unavailable' >&2; exit 1;; version) echo 'bosun v0.89.0';; *) exit 1;; esac\n"
			if err := os.WriteFile(native, []byte(helper), 0755); err != nil {
				t.Fatal(err)
			}
			worker := filepath.Join(dir, "worker")
			called := filepath.Join(dir, "called")
			versionPath := filepath.Join(dir, "version-path")
			runPath := filepath.Join(dir, "run-path")
			capability := "1"
			if tc.cache == "invalid" {
				capability = "0"
			}
			remove := ""
			if tc.removeOriginal {
				remove = "rm -f '" + worker + "'; "
			}
			workerBody := "#!/bin/sh\ncase \"$1\" in installer-version) printf '%s\\n' \"$0\" > '" + versionPath + "'; " + remove + "echo " + capability + ";; uninstall) printf '%s\\n' \"$@\" > '" + called + "'; printf '%s\\n' \"$0\" > '" + runPath + "';; *) exit 1;; esac\n"
			if tc.cache != "missing" {
				if err := os.WriteFile(worker, []byte(workerBody), 0755); err != nil {
					t.Fatal(err)
				}
			}
			switch tc.cache {
			case "symlink":
				if err := os.Rename(worker, worker+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(worker+".real", worker); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(worker, 0777); err != nil {
					t.Fatal(err)
				}
			case "not-executable":
				if err := os.Chmod(worker, 0600); err != nil {
					t.Fatal(err)
				}
			}
			script := strings.ReplaceAll(Install, "NATIVE=/usr/local/bin/bosun", "NATIVE="+native)
			script = strings.ReplaceAll(script, "/etc/bosun/config.yaml", cfg)
			script = strings.ReplaceAll(script, "/usr/local/lib/$PRODUCT-updater/worker", worker)
			script = strings.ReplaceAll(script, "have_tty() { ( exec 3>/dev/tty ) 2>/dev/null; }", "have_tty() { return 1; }")
			path := filepath.Join(dir, "install.sh")
			if err := os.WriteFile(path, []byte(script), 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{path, "uninstall"}
			if tc.confirm {
				args = append(args, "--yes")
			}
			if tc.keep {
				args = append(args, "--keep-data")
			}
			cmd := exec.Command("sh", args...)
			cmd.Env = append(os.Environ(), "PATH="+stub+string(os.PathListSeparator)+os.Getenv("PATH"))
			output, err := cmd.CombinedOutput()
			if _, e := os.Stat(network); e == nil {
				t.Fatalf("network request with unavailable config: %s", output)
			}
			call, callErr := os.ReadFile(called)
			if tc.cache == "valid" && tc.confirm {
				if err != nil {
					t.Fatalf("offline uninstall: %v %s", err, output)
				}
				want := "uninstall\n--yes\n"
				if tc.keep {
					want += "--keep-data\n"
				}
				if callErr != nil || string(call) != want {
					t.Fatalf("lost uninstall options: %q %v", call, callErr)
				}
				if _, e := os.Stat(configRead); e == nil {
					t.Fatal("fast path read damaged application config")
				}
				verified, _ := os.ReadFile(versionPath)
				executed, _ := os.ReadFile(runPath)
				if len(verified) == 0 || string(verified) != string(executed) || strings.TrimSpace(string(executed)) == worker {
					t.Fatal("uninstall did not execute the same verified private copy")
				}
			} else {
				if err == nil || callErr == nil {
					t.Fatalf("unsafe or unconfirmed worker executed: %v %q %s", err, call, output)
				}
				if tc.cache == "valid" {
					if !strings.Contains(string(output), "pass --yes") {
						t.Fatalf("confirmation skipped: %s", output)
					}
				} else {
					if _, e := os.Stat(configRead); e != nil {
						t.Fatalf("invalid cache bypassed strict config verification: %s", output)
					}
					if !strings.Contains(string(output), "Cannot read existing download configuration") {
						t.Fatalf("unexpected refusal: %s", output)
					}
				}
			}
		})
	}
}
