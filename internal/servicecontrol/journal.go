package servicecontrol

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func readScope(dir string) (Scope, error) {
	if dir == "" {
		return Scope{}, nil
	}
	f, err := os.OpenFile(filepath.Join(dir, "service-control-owned.json"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return Scope{}, nil
	}
	if err != nil {
		return Scope{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return Scope{}, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || !ownedByProcess(st) {
		return Scope{}, errors.New("invalid service control ownership file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		return Scope{}, err
	}
	if len(raw) > 1<<20 {
		return Scope{}, errors.New("service control ownership file too large")
	}
	var out Scope
	if err = json.Unmarshal(raw, &out); err != nil {
		return Scope{}, err
	}
	return out, validateScope(out)
}
func saveScope(dir string, s Scope) error {
	if err := validateScope(s); err != nil {
		return err
	}
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm()&0022 != 0 || !ownedByProcess(st) {
		return errors.New("service control directory must not be writable by other accounts")
	}
	p := filepath.Join(dir, "service-control-owned.json")
	if st, err := os.Lstat(p); err == nil && !st.Mode().IsRegular() {
		return fmt.Errorf("invalid service control ownership path")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(dir, ".service-control-owned-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	raw, err := json.Marshal(s)
	if err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil {
		return err
	}
	if ce != nil {
		return ce
	}
	return os.Rename(f.Name(), p)
}

func ownedByProcess(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}
