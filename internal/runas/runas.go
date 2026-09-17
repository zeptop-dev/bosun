// Package runas holds the unprivileged account the proxy cores run under
// (config cores.user). bosun itself stays root for nftables, tc and port
// binding; the cores get only CAP_NET_BIND_SERVICE. Files the cores must
// read (their configs, work dirs, certificates) are handed to that account
// through Chown. With no account configured every call is a no-op and the
// cores inherit bosun's identity as before.
package runas

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

var (
	mu       sync.RWMutex
	name     string
	uid      = -1
	gid      = -1
	netAdmin bool
	setupErr string
)

// SetNetAdmin says whether cores need CAP_NET_ADMIN on top of the bind
// capability: the per-user speed limits mark sockets (SO_MARK), which an
// unprivileged process may not do. It returns whether the answer changed,
// so running cores can be restarted with the new capability set.
func SetNetAdmin(on bool) (changed bool) {
	mu.Lock()
	defer mu.Unlock()
	changed = netAdmin != on
	netAdmin = on
	return changed
}

// NetAdmin reports whether cores get CAP_NET_ADMIN.
func NetAdmin() bool {
	mu.RLock()
	defer mu.RUnlock()
	return netAdmin
}

// Set resolves the account and makes it the default for cores. A missing
// account is created as a system user when running as root on Linux.
func Set(account string) error {
	if account == "" {
		Clear()
		return nil
	}
	u, err := user.Lookup(account)
	if err != nil {
		if runtime.GOOS == "linux" && os.Geteuid() == 0 {
			// A system account with no home and no login shell. Alpine and
			// other busybox systems have adduser instead of useradd.
			cmds := [][]string{
				{"useradd", "-r", "-M", "-s", "/usr/sbin/nologin", "-d", "/nonexistent", account},
				{"adduser", "-S", "-D", "-H", "-h", "/nonexistent", "-s", "/sbin/nologin", account},
			}
			var last error
			for _, c := range cmds {
				if _, lerr := exec.LookPath(c[0]); lerr != nil {
					continue
				}
				if out, cerr := exec.Command(c[0], c[1:]...).CombinedOutput(); cerr != nil {
					last = fmt.Errorf("%s: %v: %s", c[0], cerr, strings.TrimSpace(string(out)))
					continue
				}
				last = nil
				break
			}
			if last != nil {
				return fmt.Errorf("runas: account %q could not be created: %w", account, last)
			}
			u, err = user.Lookup(account)
		}
		if err != nil {
			return fmt.Errorf("runas: account %q: %w", account, err)
		}
	}
	id, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("runas: uid %q: %w", u.Uid, err)
	}
	g, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("runas: gid %q: %w", u.Gid, err)
	}
	if id == 0 {
		return fmt.Errorf("runas: %q is root; cores.user must be an unprivileged account", account)
	}
	mu.Lock()
	name, uid, gid = account, id, g
	mu.Unlock()
	return nil
}

// SetError records why the configured account could not be used, for the
// doctor; the cores then run as bosun itself.
func SetError(msg string) {
	mu.Lock()
	setupErr = msg
	mu.Unlock()
}

// Error returns that message ("" when the account is fine).
func Error() string {
	mu.RLock()
	defer mu.RUnlock()
	return setupErr
}

// Clear returns to running cores as bosun itself (tests).
func Clear() {
	mu.Lock()
	name, uid, gid, setupErr = "", -1, -1, ""
	mu.Unlock()
}

// Active reports whether a core account is configured.
func Active() bool {
	mu.RLock()
	defer mu.RUnlock()
	return uid >= 0
}

// IDs returns the account's uid and gid, or -1, -1 when none is set.
func IDs() (int, int) {
	mu.RLock()
	defer mu.RUnlock()
	return uid, gid
}

// Name returns the configured account name ("" = none).
func Name() string {
	mu.RLock()
	defer mu.RUnlock()
	return name
}

// Chown gives one path to the core account; no-op without one.
func Chown(path string) error {
	u, g := IDs()
	if u < 0 {
		return nil
	}
	if err := os.Lchown(path, u, g); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("runas: chown %s: %w", path, err)
	}
	return nil
}

// ChownTree gives a directory and everything under it to the core account
// (work dirs that existed before the account was configured).
func ChownTree(dir string) error {
	if !Active() {
		return nil
	}
	return filepath.WalkDir(dir, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return nil // skip what cannot be read; the core will report its own errors
		}
		return Chown(path)
	})
}

// WriteFile writes data through a temporary file and renames it into
// place, never following a symlink at either path. A core owns some of
// these directories, so a plain os.WriteFile could be redirected at a
// root-owned file by a planted link.
func WriteFile(path string, data []byte, perm os.FileMode, chown bool) error {
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if chown {
		if err := Chown(tmp); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	return os.Rename(tmp, path)
}

// MkdirRoot creates a directory that stays owned by bosun and is only
// traversable by the cores, so a core cannot plant entries in it.
func MkdirRoot(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.Chmod(dir, 0o755)
}
