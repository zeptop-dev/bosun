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
	"sync"
)

var (
	mu   sync.RWMutex
	name string
	uid  = -1
	gid  = -1
)

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
			// -r system account, no home, no login shell.
			if out, cerr := exec.Command("useradd", "-r", "-M", "-s", "/usr/sbin/nologin", "-d", "/nonexistent", account).CombinedOutput(); cerr != nil {
				return fmt.Errorf("runas: account %q does not exist and could not be created: %v: %s", account, cerr, out)
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

// Clear returns to running cores as bosun itself (tests).
func Clear() {
	mu.Lock()
	name, uid, gid = "", -1, -1
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
