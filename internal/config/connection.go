package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

// ConnectionSelection leaves config.yaml (including read-only Docker mounts)
// intact. The override is bound to the installation origin and current token.
type ConnectionSelection struct {
	OriginalURL string `json:"original_url"`
	URL         string `json:"url"`
	MigrationID string `json:"migration_id"`
	MAC         string `json:"mac"`
}

func connectionMAC(v ConnectionSelection, token string) string {
	h := hmac.New(sha256.New, []byte(token))
	h.Write([]byte("connection-selection-v1\x00" + v.OriginalURL + "\x00" + v.URL + "\x00" + v.MigrationID))
	return hex.EncodeToString(h.Sum(nil))
}
func ReadConnection(dir, original, token string) (ConnectionSelection, error) {
	v := ConnectionSelection{OriginalURL: original, URL: original}
	if dir == "" || token == "" {
		return v, nil
	}
	f, err := os.OpenFile(filepath.Join(dir, "captain-connection.json"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return v, nil
	}
	if err != nil {
		return v, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return v, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 8192 {
		return v, errors.New("invalid connection selection permissions")
	}
	if stat, ok := st.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Geteuid() {
		return v, errors.New("invalid connection selection owner")
	}
	data, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil {
		return v, err
	}
	var saved ConnectionSelection
	if json.Unmarshal(data, &saved) != nil {
		return v, errors.New("invalid connection selection")
	}
	// A manual reconfiguration or re-pair does not inherit an old authority.
	if saved.OriginalURL != original || !hmac.Equal([]byte(saved.MAC), []byte(connectionMAC(saved, token))) {
		return v, nil
	}
	if _, ok := agentproto.ConnectionOrigin(saved.URL); !ok {
		return v, errors.New("invalid selected connection URL")
	}
	return saved, nil
}
func SaveConnection(dir, original, source, target, id, token string) error {
	if dir == "" || token == "" || id == "" {
		return errors.New("connection persistence unavailable")
	}
	if _, ok := agentproto.ConnectionOrigin(target); !ok {
		return errors.New("invalid target origin")
	}
	current, err := ReadConnection(dir, original, token)
	if err != nil {
		return err
	}
	if current.URL != source && current.URL != target {
		return errors.New("connection selection changed")
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 {
		return errors.New("connection data directory is not a directory")
	}
	v := ConnectionSelection{OriginalURL: original, URL: target, MigrationID: id}
	v.MAC = connectionMAC(v, token)
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".captain-connection-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, "captain-connection.json")); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err = d.Sync(); err != nil {
		return fmt.Errorf("persist connection selection: %w", err)
	}
	return nil
}
