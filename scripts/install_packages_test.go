package scripts

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Execute the real package phase with an isolated PATH. Fake package managers
// install fake tools; no host software, firewall or service can be changed.
type packageFixture struct {
	t                *testing.T
	root, bin, trace string
}

func newPackageFixture(t *testing.T, manager string) *packageFixture {
	t.Helper()
	f := &packageFixture{t: t, root: t.TempDir()}
	f.bin, f.trace = filepath.Join(f.root, "bin"), filepath.Join(f.root, "trace")
	if err := os.Mkdir(f.bin, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"awk", "cat", "chmod", "rm"} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(path, filepath.Join(f.bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	f.write("timeout", `printf 'timeout %s\n' "$*" >> "$TEST_TRACE"
shift
exec "$@"`)
	if manager != "" {
		f.write(manager, packageManagerStub)
	}
	return f
}

func (f *packageFixture) write(name, body string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
		f.t.Fatal(err)
	}
}

const packageManagerStub = `
printf 'package %s\n' "$*" >> "$TEST_TRACE"
case " $* " in
  *' update '*)
    if [ "${TEST_UPDATE_FAIL:-0}" = 1 ]; then echo 'Temporary failure resolving https://user:private-password@example.com/?token=private-token'; exit 100; fi
    printf 'updated' > "$TEST_ROOT/updated"
    exit 0;;
  *' wireguard-tools '*)
    if [ "${TEST_WG_FAIL:-0}" = 1 ]; then echo 'Unable to locate package wireguard-tools'; exit 100; fi
    printf '#!/bin/sh\nexit 0\n' > "$TEST_BIN/wg"; chmod 0755 "$TEST_BIN/wg"; exit 0;;
esac
if [ "${TEST_PACKAGE_FAIL:-0}" = 1 ]; then
  echo "${TEST_PACKAGE_ERROR:-Unable to locate package from https://user:private-password@example.com/?token=private-token}"
  exit 100
fi
if [ "${TEST_NEED_UPDATE:-0}" = 1 ] && [ ! -f "$TEST_ROOT/updated" ]; then
  echo '404 Not Found https://user:private-password@example.com/?token=private-token'
  exit 100
fi
for tool in nft tc ip; do
  [ "${TEST_OMIT_TC:-0}" != 1 ] || [ "$tool" != tc ] || continue
  if [ "$tool" = nft ]; then
    printf '#!/bin/sh\nprintf "nft %%s\\n" "$*" >> "$TEST_TRACE"\nexit "${TEST_NFT_FAIL:-0}"\n' > "$TEST_BIN/$tool"
  else
    printf '#!/bin/sh\nexit 0\n' > "$TEST_BIN/$tool"
  fi
  chmod 0755 "$TEST_BIN/$tool"
done
`

func (f *packageFixture) run(source, selection, mode, node string, extra ...string) string {
	f.t.Helper()
	start := strings.Index(Install, "missing_network_tools() {")
	end := strings.Index(Install[start:], "\n# ask prints a prompt")
	if start < 0 || end < 0 {
		f.t.Fatal("package phase boundaries missing")
	}
	cmd := exec.Command("/bin/sh", "-eu", "-c", Install[start:start+end]+"\necho reached-service-start\n")
	cmd.Env = append(os.Environ(), "PATH="+f.bin, "TMP="+f.root, "TEST_ROOT="+f.root, "TEST_BIN="+f.bin, "TEST_TRACE="+f.trace,
		"DOWNLOAD_SOURCE="+source, "SYSTEM_PACKAGES="+selection, "MODE="+mode, "NODE_MODE="+node, "OPENWRT=0")
	cmd.Env = append(cmd.Env, extra...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		f.t.Fatalf("package phase aborted: %v %s", err, out)
	}
	for _, secret := range []string{"private-password", "private-token", "https://user:"} {
		if strings.Contains(string(out), secret) {
			f.t.Fatalf("package credentials leaked: %s", out)
		}
	}
	for _, suffix := range []string{"log", "reason", "rc"} {
		if _, err := os.Stat(filepath.Join(f.root, "system-packages."+suffix)); !os.IsNotExist(err) {
			f.t.Fatalf("temporary diagnostics retained: %s %v", suffix, err)
		}
	}
	return string(out)
}

func (f *packageFixture) calls() string {
	f.t.Helper()
	raw, err := os.ReadFile(f.trace)
	if err != nil && !os.IsNotExist(err) {
		f.t.Fatal(err)
	}
	return string(raw)
}

func TestInstallSystemPackageSelection(t *testing.T) {
	for _, c := range []struct {
		source, selection string
		installs          bool
	}{
		{"github", "auto", true}, {"captain", "auto", false},
		{"github", "install", true}, {"captain", "install", true},
		{"github", "skip", false}, {"captain", "skip", false},
	} {
		t.Run(c.source+"/"+c.selection, func(t *testing.T) {
			f := newPackageFixture(t, "apt-get")
			out := f.run(c.source, c.selection, "binary", "full")
			if strings.Contains(f.calls(), "package ") != c.installs {
				t.Fatalf("unexpected packages: %s", f.calls())
			}
			if c.installs {
				if !strings.Contains(out, "Network tools found") || !strings.Contains(f.calls(), "nft list tables") || !strings.Contains(out, "does not prove rule-write permission") {
					t.Fatalf("missing readiness distinction: %s / %s", out, f.calls())
				}
			} else if !strings.Contains(out, "OS package installation skipped") || !strings.Contains(out, "still missing: nft tc ip") {
				t.Fatalf("missing actionable skip: %s", out)
			}
		})
	}
}

// Debian 11/12/13 use the same apt package names. This verifies that shared
// command contract, not package downloads against three real distributions.
func TestInstallDebianIndexRetryAndOptionalWG(t *testing.T) {
	f := newPackageFixture(t, "apt-get")
	out := f.run("github", "auto", "binary", "full", "TEST_NEED_UPDATE=1", "TEST_WG_FAIL=1")
	calls := f.calls()
	if strings.Count(calls, "install -y -qq nftables iproute2\n") != 2 || strings.Count(calls, " update\n") != 1 {
		t.Fatalf("no bounded refresh/retry: %s", calls)
	}
	if strings.Contains(calls, "iproute2 wireguard-tools") || !strings.Contains(out, "Optional wg utility missing") || !strings.Contains(out, "Network tools found") {
		t.Fatalf("optional WG blocks basic dependencies: %s %s", calls, out)
	}
	if !strings.Contains(out, "package or package index unavailable") {
		t.Fatalf("missing package diagnosis: %s", out)
	}
}

func TestInstallAlpineTCAndPackageFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			f := newPackageFixture(t, "apk")
			extra := []string{"TEST_WG_FAIL=1"}
			if fail {
				extra = append(extra, "TEST_PACKAGE_FAIL=1", "TEST_PACKAGE_ERROR=unable to select packages https://user:private-password@example.com/?token=private-token")
			}
			out := f.run("captain", "install", "binary", "full", extra...)
			if !strings.Contains(f.calls(), "add --update-cache -q nftables iproute2 iproute2-tc\n") {
				t.Fatalf("Alpine tc package omitted: %s", f.calls())
			}
			if fail && (!strings.Contains(out, "apk add --update-cache nftables iproute2 iproute2-tc") || !strings.Contains(out, "still missing: nft tc ip")) {
				t.Fatalf("missing manual repair: %s", out)
			}
		})
	}
}

func TestInstallNetworkDiagnosticsDoNotPretendShapingWorks(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		want string
	}{
		{"missing-tc", []string{"TEST_OMIT_TC=1"}, "Network dependencies still missing: tc"},
		{"kernel-permission", []string{"TEST_NFT_FAIL=1"}, "nft is installed but the kernel read check failed"},
		{"index-refresh-fails", []string{"TEST_PACKAGE_FAIL=1", "TEST_UPDATE_FAIL=1"}, "OS repository DNS or network access failed"},
		{"package-lock", []string{"TEST_PACKAGE_FAIL=1", "TEST_PACKAGE_ERROR=Could not get lock /var/lib/dpkg/lock-frontend https://user:private-password@example.com"}, "another package manager holds the lock"},
		{"package-signature", []string{"TEST_PACKAGE_FAIL=1", "TEST_PACKAGE_ERROR=NO_PUBKEY from https://user:private-password@example.com"}, "repository TLS or signature verification failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newPackageFixture(t, "apt-get")
			out := f.run("github", "auto", "binary", "full", c.env...)
			if !strings.Contains(out, c.want) {
				t.Fatalf("want %q: %s", c.want, out)
			}
			calls := f.calls()
			for _, forbidden := range []string{"nft add", "nft delete", "nft flush", "tc qdisc", "modprobe", "setcap"} {
				if strings.Contains(calls, forbidden) {
					t.Fatalf("mutating readiness check: %s", calls)
				}
			}
			if c.name == "index-refresh-fails" && strings.Count(calls, "install -y -qq nftables iproute2\n") != 1 {
				t.Fatalf("retried after failed refresh: %s", calls)
			}
		})
	}
}

func TestInstallSystemPackagesSkipNonFullNative(t *testing.T) {
	for _, c := range []struct {
		name, mode, node string
		extra            []string
	}{
		{"monitor", "binary", "monitor", nil}, {"docker", "docker", "full", nil}, {"openwrt", "binary", "full", []string{"OPENWRT=1"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newPackageFixture(t, "apt-get")
			out := f.run("github", "install", c.mode, c.node, c.extra...)
			if f.calls() != "" || strings.Contains(out, "Network") {
				t.Fatalf("non-full native host touched: %s %s", out, f.calls())
			}
		})
	}
}

func TestInstallSystemPackagesArgumentValidation(t *testing.T) {
	end := strings.Index(Install, "\n[ \"$(uname -s)\"")
	if end < 0 {
		t.Fatal("argument boundary missing")
	}
	for _, args := range [][]string{{"--system-packages"}, {"--system-packages", "unknown"}, {"--system-packages", "install"}, {"--system-packages", "skip"}, {"--system-packages", "auto"}} {
		cmd := exec.Command("/bin/sh", append([]string{"-c", Install[:end] + "\nprintf '%s' \"$SYSTEM_PACKAGES\"\n", "installer"}, args...)...)
		out, err := cmd.CombinedOutput()
		valid := len(args) == 2 && args[1] != "unknown"
		if valid && (err != nil || string(out) != args[1]) {
			t.Fatalf("valid option rejected: %v %s", err, out)
		}
		if !valid && (err == nil || !strings.Contains(string(out), "--system-packages")) {
			t.Fatalf("invalid option accepted: %v %s", err, out)
		}
	}
}

// This full installer fixture exercises the original startup ordering, rather
// than proving only an extracted package function. Its release, OS tools and
// filesystem are simulated; it is not a claim of a real LXC kernel test.
func TestInstallPackagesBeforeNativeServiceStartup(t *testing.T) {
	for _, manager := range []string{"apt-get", "apk"} {
		t.Run(manager, func(t *testing.T) {
			f := newOpenWrtFixture(t, "captain")
			if err := os.Remove(filepath.Join(f.root, "etc/openwrt_release")); err != nil {
				t.Fatal(err)
			}
			bin := filepath.Join(f.root, "bin")
			put := func(name, body string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			put(manager, packageManagerStub)
			put("timeout", "shift; exec \"$@\"")
			if manager == "apt-get" {
				if err := os.MkdirAll(filepath.Join(f.root, "etc/systemd/system"), 0755); err != nil {
					t.Fatal(err)
				}
				put("systemctl", `printf 'service %s\n' "$*" >> "$TEST_TRACE"`)
			} else {
				put("rc-service", `printf 'service %s\n' "$*" >> "$TEST_TRACE"`)
				put("rc-update", "exit 0")
			}
			// Replace the copied symlink rather than overwriting the host's sleep.
			if err := os.Remove(filepath.Join(bin, "sleep")); err != nil {
				t.Fatal(err)
			}
			put("sleep", "exit 0")
			curl, err := os.ReadFile(filepath.Join(bin, "curl"))
			if err != nil {
				t.Fatal(err)
			}
			curl = []byte(strings.Replace(string(curl), " */bosun.procd)", " */bosun.service|*/bosun.initd|*/bosun.procd)", 1))
			if err := os.WriteFile(filepath.Join(bin, "curl"), curl, 0755); err != nil {
				t.Fatal(err)
			}
			f.env = append(f.env, "TEST_BIN="+bin, "TEST_NEED_UPDATE=1", "TEST_WG_FAIL=1")
			if manager == "apk" {
				f.env = append(f.env, "TEST_NEED_UPDATE=0")
			}
			out, err := f.run(t, "--captain", "https://example.com", "--pair", "ABCD-EFGH", "--version", "v0.89.0", "--download-source", "captain", "--system-packages", "install")
			if err != nil {
				t.Fatalf("native installation: %v %s", err, out)
			}
			trace := f.read(t, "trace")
			packages := strings.LastIndex(trace, "package ")
			start := strings.Index(trace, "service ")
			if packages < 0 || start < packages || !strings.Contains(trace[:start], "nft list tables") {
				t.Fatalf("service started before dependencies and check: %s", trace)
			}
			if !strings.Contains(out, "Network tools found") || !strings.Contains(out, "Optional wg utility missing") {
				t.Fatalf("incorrect installation diagnosis: %s", out)
			}
		})
	}
}

func TestInstallExistingDependenciesAndUnboundedProbeAvoidance(t *testing.T) {
	for _, haveTimeout := range []bool{false, true} {
		t.Run(fmt.Sprint(haveTimeout), func(t *testing.T) {
			f := newPackageFixture(t, "apt-get")
			for _, tool := range []string{"tc", "ip", "wg"} {
				f.write(tool, "exit 0")
			}
			f.write("nft", `printf 'nft %s\n' "$*" >> "$TEST_TRACE"`)
			if !haveTimeout {
				if err := os.Remove(filepath.Join(f.bin, "timeout")); err != nil {
					t.Fatal(err)
				}
			}
			out := f.run("github", "auto", "binary", "full")
			if strings.Contains(f.calls(), "package ") {
				t.Fatalf("unnecessary OS downloads: %s", f.calls())
			}
			if !haveTimeout && (strings.Contains(f.calls(), "nft ") || !strings.Contains(out, "nft kernel access not checked")) {
				t.Fatalf("unbounded kernel probe: %s %s", out, f.calls())
			}
			if haveTimeout && !strings.Contains(f.calls(), "timeout 5 nft list tables") {
				t.Fatalf("missing bounded kernel probe: %s", f.calls())
			}
		})
	}
}

func TestInstallSystemPackagesRejectIgnoredLifecycleOptions(t *testing.T) {
	end := strings.Index(Install, "\n[ \"$(uname -s)\"")
	if end < 0 {
		t.Fatal("argument boundary missing")
	}
	for _, action := range []string{"upgrade", "uninstall", "enable-web-upgrade"} {
		for _, selection := range []string{"install", "skip", "auto"} {
			cmd := exec.Command("/bin/sh", "-c", Install[:end]+"\necho accepted\n", "installer", action, "--system-packages", selection)
			out, err := cmd.CombinedOutput()
			if selection == "auto" {
				if err != nil || !strings.Contains(string(out), "accepted") {
					t.Fatalf("legacy lifecycle broken: %s %s %v %s", action, selection, err, out)
				}
			} else if err == nil || !strings.Contains(string(out), "only supported for install/reinstall") {
				t.Fatalf("silently ignored option: %s %s %v %s", action, selection, err, out)
			}
		}
	}
}
