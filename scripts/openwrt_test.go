package scripts

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/deploy"
	"gopkg.in/yaml.v3"
)

// Run the actual installer and procd service body with every host path mapped
// into a temporary router. The intentionally small PATH has no install, stat,
// systemd, OpenRC, package manager, firewall, or proxy-core commands.
type openWrtFixture struct {
	root, script, trace, payload, source string
	env                                  []string
}

func newOpenWrtFixture(t *testing.T, source string) *openWrtFixture {
	t.Helper()
	root := t.TempDir()
	f := &openWrtFixture{root: root, script: filepath.Join(root, "install.sh"), trace: filepath.Join(root, "trace"), payload: filepath.Join(root, "release"), source: source}
	put := func(path, body string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	rewrite := strings.NewReplacer("/etc/", root+"/etc/", "/usr/local/", root+"/usr/local/", "/var/lib/", root+"/var/lib/", "/sbin/procd", root+"/sbin/procd", "-C / ", "-C '"+root+"' ")
	put(f.script, rewrite.Replace(Install), 0600)
	if err := os.MkdirAll(filepath.Join(root, "etc/init.d"), 0755); err != nil {
		t.Fatal(err)
	}
	put(filepath.Join(root, "etc/openwrt_release"), "DISTRIB_ID='OpenWrt'\n", 0600)
	put(filepath.Join(root, "sbin/procd"), "#!/bin/sh\nexit 0\n", 0755)
	put(filepath.Join(root, "etc/rc.common"), `#!/bin/sh
service=$1; action=$2
. "$service"
printf 'service %s\n' "$action" >> "$TEST_TRACE"
procd_open_instance() { :; }
procd_set_param() { printf 'procd %s\n' "$*" >> "$TEST_TRACE"; }
procd_close_instance() { :; }
case "$action" in
 enable) mkdir -p "$TEST_ROOT/etc/rc.d"; ln -sf "$service" "$TEST_ROOT/etc/rc.d/S95bosun";;
 disable) rm -f "$TEST_ROOT/etc/rc.d/S95bosun";;
 start|restart) start_service;;
 stop|running) :;;
 *) exit 97;;
esac
`, 0755)
	put(filepath.Join(root, "procd.asset"), rewrite.Replace(deploy.Procd), 0600)
	stub := filepath.Join(root, "bin")
	if err := os.Mkdir(stub, 0755); err != nil {
		t.Fatal(err)
	}
	// GNU tar invokes gzip through PATH, while macOS bsdtar compresses internally.
	for _, name := range []string{"awk", "cat", "chmod", "cp", "cut", "date", "grep", "gzip", "head", "ln", "mkdir", "mktemp", "mv", "rm", "sed", "sha256sum", "sleep", "tar", "wc"} {
		real, err := exec.LookPath(name)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.Symlink(real, filepath.Join(stub, name)); err != nil {
			t.Fatal(err)
		}
	}
	realLS, err := exec.LookPath("ls")
	if err != nil {
		t.Fatal(err)
	}
	put(filepath.Join(stub, "ls"), "#!/bin/sh\n'"+realLS+"' \"$@\" | awk '{$3=0; print}'\n", 0755) // simulated root ownership; host tests run unprivileged
	put(filepath.Join(stub, "uname"), "#!/bin/sh\ncase \"$1\" in -s) echo Linux;; -m) echo x86_64;; esac\n", 0755)
	put(filepath.Join(stub, "id"), "#!/bin/sh\necho 0\n", 0755)
	put(filepath.Join(stub, "curl"), `#!/bin/sh
out=
while [ "$#" -gt 0 ]; do
 case "$1" in -o|--output) out=$2; shift 2;; --header|--proto|--proto-redir|--max-redirs|--connect-timeout|--max-time|--max-filesize|--write-out) shift 2;; -*) shift;; *) url=$1; shift;; esac
done
printf 'fetch %s\n' "$url" >> "$TEST_TRACE"
case "$url" in
 */api/agent/health) printf '{"ok":true,"service":"captain-agent"}' > "$out"; printf 200;;
 */releases/latest) echo '{"tag_name":"v0.89.0"}';;
 */bosun-linux-amd64) cp "$TEST_ROOT/release" "$out";;
 */SHA256SUMS) cp "$TEST_ROOT/checksums" "$out";;
 */bosun.procd) cp "$TEST_ROOT/procd.asset" "$out";;
 *) echo 'unexpected download' >&2; exit 98;;
esac
`, 0755)
	f.env = append(os.Environ(), "PATH="+stub, "TEST_ROOT="+root, "TEST_TRACE="+f.trace, "TEST_SOURCE="+source)
	f.release(t, "v0.89.0")
	return f
}
func (f *openWrtFixture) release(t *testing.T, version string) {
	t.Helper()
	body := `#!/bin/sh
printf 'binary %s\n' "$*" >> "$TEST_TRACE"
case "$1" in
 installer-node-mode) sed -n 's/^node_mode: //p' "$2";;
 installer-download-config) printf '%s\nhttps://example.com\n%s/etc/bosun/data/captain.token\n' "$TEST_SOURCE" "$TEST_ROOT";;
 installer-version|installer-openwrt-supported) echo 1;;
 installer-check-layout|installer-check-upgrade|healthcheck|uninstall) :;;
 version) echo 'bosun ` + version + `';;
 *) echo 'unexpected binary command' >&2; exit 99;;
esac
`
	if err := os.WriteFile(f.payload, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	if err := os.WriteFile(filepath.Join(f.root, "checksums"), []byte(fmt.Sprintf("%x  bosun-linux-amd64\n", sum)), 0600); err != nil {
		t.Fatal(err)
	}
}
func (f *openWrtFixture) run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("/bin/sh", append([]string{f.script}, args...)...)
	cmd.Env = f.env
	raw, err := cmd.CombinedOutput()
	return string(raw), err
}
func (f *openWrtFixture) read(t *testing.T, p string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.root, p))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestOpenWrtInstallReinstallUpgradeAndOfflineUninstall(t *testing.T) {
	for _, source := range []string{"github", "captain"} {
		t.Run(source, func(t *testing.T) {
			f := newOpenWrtFixture(t, source)
			args := []string{"--monitor-only", "--captain", "https://example.com", "--pair", "ABCD-EFGH", "--version", "v0.89.0", "--download-source", source}
			if out, err := f.run(t, args...); err != nil {
				t.Fatalf("install: %v %s", err, out)
			}
			cfg := f.read(t, "etc/bosun/config.yaml")
			var parsed struct {
				Data  string `yaml:"data_dir"`
				Mode  string `yaml:"node_mode"`
				Panel struct {
					Driver  string `yaml:"driver"`
					Captain struct {
						Token string `yaml:"token_file"`
					} `yaml:"captain"`
				} `yaml:"panel"`
			}
			if err := yaml.Unmarshal([]byte(cfg), &parsed); err != nil {
				t.Fatal(err)
			}
			if parsed.Data != f.root+"/etc/bosun/data" || parsed.Mode != "monitor" || parsed.Panel.Driver != "captain" || parsed.Panel.Captain.Token != parsed.Data+"/captain.token" {
				t.Fatalf("invalid router configuration: %+v", parsed)
			}
			for path, want := range map[string]os.FileMode{"etc/bosun/config.yaml": 0600, "etc/bosun": 0700, "etc/bosun/data": 0700, "etc/init.d/bosun": 0755} {
				st, err := os.Stat(filepath.Join(f.root, path))
				if err != nil || st.Mode().Perm() != want {
					t.Fatalf("permissions %s: %v %v", path, st, err)
				}
			}
			if _, err := os.Lstat(filepath.Join(f.root, "etc/rc.d/S95bosun")); err != nil {
				t.Fatal("autostart missing", err)
			}
			trace := f.read(t, "trace")
			for _, want := range []string{"service enable", "service restart", "procd command " + f.root + "/usr/local/bin/bosun run -c " + f.root + "/etc/bosun/config.yaml", "procd respawn 3600 5 0", "procd stdout 1", "procd stderr 1"} {
				if !strings.Contains(trace, want) {
					t.Fatalf("missing %q: %s", want, trace)
				}
			}
			if source == "captain" && strings.Contains(trace, "github") {
				t.Fatal("Captain installation escaped distribution", trace)
			}
			if source == "github" && !strings.Contains(trace, "/v0.89.0/deploy/bosun.procd") {
				t.Fatal("unpinned service asset", trace)
			}
			// Simulate successful pairing plus an operator edit, then rerun without a
			// new pairing code. Neither identity nor configuration may be rewritten.
			cfg += "\n# preserved operator edit\n"
			if err := os.WriteFile(filepath.Join(f.root, "etc/bosun/config.yaml"), []byte(cfg), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(parsed.Panel.Captain.Token, []byte("test-node-token"), 0600); err != nil {
				t.Fatal(err)
			}
			if out, err := f.run(t, "--version", "v0.89.0"); err != nil {
				t.Fatalf("reinstall: %v %s", err, out)
			}
			if got := f.read(t, "etc/bosun/config.yaml"); got != cfg {
				t.Fatal("configuration rewritten")
			}
			if got := f.read(t, "etc/bosun/data/captain.token"); got != "test-node-token" {
				t.Fatal("token changed")
			}
			f.release(t, "v0.90.0")
			if out, err := f.run(t, "upgrade", "--version", "v0.90.0"); err != nil {
				t.Fatalf("upgrade: %v %s", err, out)
			}
			trace = f.read(t, "trace")
			if !strings.Contains(trace, "service stop") || !strings.Contains(trace, "service start") || !strings.Contains(trace, "healthcheck --version v0.90.0 --data-dir "+parsed.Data) {
				t.Fatal("upgrade lifecycle incomplete", trace)
			}
			backups, err := filepath.Glob(filepath.Join(f.root, "etc/bosun-updater/backups/*/data.tar.gz"))
			if err != nil || len(backups) != 1 {
				t.Fatal("persistent backup missing", backups, err)
			}
			listing, err := exec.Command("tar", "-tzf", backups[0]).CombinedOutput()
			if err != nil || !strings.Contains(string(listing), "captain.token") {
				t.Fatal("backup omitted token", err, string(listing))
			}
			if f.read(t, "etc/bosun/config.yaml") != cfg {
				t.Fatal("upgrade rewrote configuration")
			}
			// Offline uninstall must still use the installed capable worker when its
			// permanent token is gone; it may not fall back to external networking.
			if err := os.Remove(parsed.Panel.Captain.Token); err != nil {
				t.Fatal(err)
			}
			before := strings.Count(trace, "fetch ")
			if out, err := f.run(t, "uninstall", "--yes", "--keep-data"); err != nil {
				t.Fatalf("offline uninstall: %v %s", err, out)
			}
			trace = f.read(t, "trace")
			if strings.Count(trace, "fetch ") != before || !strings.Contains(trace, "binary uninstall --yes --keep-data") {
				t.Fatal("offline uninstall did not use local worker", trace)
			}
		})
	}
}

func TestOpenWrtRefusesUnsafeInstallBeforeMutation(t *testing.T) {
	for _, scenario := range []string{"full", "existing-full", "old-release", "docker", "unsupported-cpu", "missing-procd", "symlink-binary"} {
		t.Run(scenario, func(t *testing.T) {
			f := newOpenWrtFixture(t, "github")
			args := []string{"--monitor-only", "--captain", "https://example.com", "--pair", "ABCD-EFGH", "--version", "v0.89.0"}
			switch scenario {
			case "full":
				args = args[1:]
			case "existing-full":
				os.MkdirAll(filepath.Join(f.root, "etc/bosun"), 0700)
				os.MkdirAll(filepath.Join(f.root, "usr/local/bin"), 0755)
				raw, err := os.ReadFile(f.payload)
				if err != nil {
					t.Fatal(err)
				}
				os.WriteFile(filepath.Join(f.root, "usr/local/bin/bosun"), raw, 0755)
				os.WriteFile(filepath.Join(f.root, "etc/bosun/config.yaml"), []byte("node_mode: full\n# do not change\n"), 0600)
			case "old-release":
				args[len(args)-1] = "v0.88.0"
			case "docker":
				args = append(args, "--mode", "docker")
			case "unsupported-cpu":
				os.WriteFile(filepath.Join(f.root, "bin/uname"), []byte("#!/bin/sh\ncase \"$1\" in -s) echo Linux;; -m) echo mips;; esac\n"), 0755)
			case "missing-procd":
				os.Remove(filepath.Join(f.root, "sbin/procd"))
			case "symlink-binary":
				os.MkdirAll(filepath.Join(f.root, "usr/local/bin"), 0755)
				os.WriteFile(filepath.Join(f.root, "unrelated"), []byte("preserved"), 0600)
				os.Symlink(filepath.Join(f.root, "unrelated"), filepath.Join(f.root, "usr/local/bin/bosun"))
			}
			if out, err := f.run(t, args...); err == nil {
				t.Fatalf("unsafe installation accepted: %s", out)
			}
			if scenario == "existing-full" {
				if f.read(t, "etc/bosun/config.yaml") != "node_mode: full\n# do not change\n" {
					t.Fatal("existing config changed")
				}
			} else if _, err := os.Stat(filepath.Join(f.root, "etc/bosun/config.yaml")); !os.IsNotExist(err) {
				t.Fatal("created config after refusal", err)
			}
			if scenario == "symlink-binary" && f.read(t, "unrelated") != "preserved" {
				t.Fatal("overwrote symlink destination")
			}
			if raw, _ := os.ReadFile(f.trace); strings.Contains(string(raw), "service ") {
				t.Fatal("service mutation after refusal", string(raw))
			}
		})
	}
}

func TestOpenWrtWorkerTrustWithoutStat(t *testing.T) {
	start := strings.Index(Install, "trusted_worker_file() {")
	end := strings.Index(Install[start:], "\ncopy_cached_worker() {")
	if start < 0 || end < 0 {
		t.Fatal("missing worker validator")
	}
	body := Install[start : start+end]
	for _, tc := range []struct {
		name, mode, owner string
		want              bool
	}{
		{"root-private", "-rwx------", "0", true}, {"root-readable", "-rwxr-xr-x", "0", true},
		{"group-write", "-rwxrwxr-x", "0", false}, {"other-write", "-rwxr-xrwx", "0", false}, {"non-root", "-rwxr-xr-x", "1000", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			file := filepath.Join(dir, "worker")
			os.WriteFile(file, []byte("#!/bin/sh\nexit 98\n"), 0755)
			// Functions isolate the metadata read; if the validator executes the file or
			// tries stat, this test fails. The test file itself has host-user ownership.
			script := body + "\nOPENWRT=1\nstat() { exit 99; }\nls() { printf '%s\\n' '" + tc.mode + " 1 " + tc.owner + " 0 5 Jan 1 00:00 worker'; }\ntrusted_worker_file '" + file + "'\n"
			out, err := exec.Command("/bin/sh", "-eu", "-c", script).CombinedOutput()
			if (err == nil) != tc.want {
				t.Fatalf("trust decision: want %v got %v %s", tc.want, err, out)
			}
		})
	}
}
