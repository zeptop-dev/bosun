package captain

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

const snapshotLimit = 32 << 20

type stateFetchError struct{ status int }

func (e *stateFetchError) Error() string { return fmt.Sprintf("captain: GET state: HTTP %d", e.status) }
func transientStateError(err error) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	var cert *tls.CertificateVerificationError
	if errors.As(err, &cert) {
		return false
	}
	var response *stateFetchError
	if errors.As(err, &response) {
		switch response.status {
		case 408, 429, 500, 502, 503, 504:
			return true
		}
		return false
	}
	var network net.Error
	return errors.As(err, &network)
}

type offlineSnapshot struct {
	Version     int              `json:"version"`
	Identity    string           `json:"identity"`
	ValidatedAt time.Time        `json:"validated_at"`
	State       agentproto.State `json:"state"`
}
type signedSnapshot struct {
	Payload json.RawMessage `json:"payload"`
	MAC     string          `json:"mac"`
}

func snapshotMAC(token string, body []byte) string {
	h := hmac.New(sha256.New, []byte(token))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}
func (c *Client) snapshotDir() string { return c.cfg.TokenFile + ".recovery" }
func privateDir(dir string) error {
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm() != 0700 {
		return errors.New("recovery directory is not private")
	}
	if stat, ok := st.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("recovery directory owner mismatch")
	}
	return nil
}
func (c *Client) validateLease() {
	c.mu.Lock()
	if c.state != nil && !c.revoked {
		c.verifiedAt = time.Now()
		c.offline = false
	}
	c.mu.Unlock()
	c.saveSnapshot()
}
func (c *Client) revokeLease() {
	if c.cfg.OfflineMaxAge == 0 {
		return
	}
	c.snapshotMu.Lock()
	defer c.snapshotMu.Unlock()
	c.mu.Lock()
	c.revoked = true
	c.etag = ""
	c.mu.Unlock()
	// Persist a tombstone using the same atomic replacement and directory fsync.
	// Even a restart must not resurrect the last valid authorization snapshot.
	c.mu.Lock()
	token := c.token
	c.mu.Unlock()
	if err := c.writeSnapshot(token, []byte(`{"version":0}`)); err != nil {
		c.log.Error("cannot persist recovery revocation", "err", err)
		if err := c.invalidateSnapshot(); err != nil {
			c.log.Error("cannot invalidate rejected recovery snapshot", "err", err)
		}
	}
}

// ServiceLeaseError is intentionally independent of successful polling. Once enabled,
// an expired or explicitly rejected lease must also block local retry/activation paths.
func (c *Client) ServiceLeaseError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cfg.OfflineMaxAge == 0 {
		return nil
	}
	if c.revoked {
		return errors.New("captain: state authorization rejected")
	}
	if c.state != nil && (c.verifiedAt.IsZero() || time.Now().Before(c.verifiedAt) || !time.Now().Before(c.verifiedAt.Add(c.cfg.OfflineMaxAge))) {
		return errors.New("captain: offline state lease expired; waiting for authenticated state")
	}
	return nil
}
func (c *Client) saveSnapshot() {
	if c.cfg.OfflineMaxAge == 0 {
		return
	}
	c.snapshotMu.Lock()
	defer c.snapshotMu.Unlock()
	c.mu.Lock()
	if c.state == nil || c.revoked || c.token == "" {
		c.mu.Unlock()
		return
	}
	state := *c.state
	state.Jobs = nil
	token := c.token
	identity := fmt.Sprintf("%x", sha256.Sum256([]byte(c.cfg.URL+"\x00"+token)))
	body, err := json.Marshal(offlineSnapshot{Version: 1, Identity: identity, ValidatedAt: c.verifiedAt, State: state})
	c.mu.Unlock()
	if err == nil {
		err = c.writeSnapshot(token, body)
	}
	if err != nil {
		c.log.Warn("offline recovery snapshot not saved; live state remains valid", "err", err)
		// A previous snapshot may authorize users or traffic that the new state
		// removed. Do not let a later restart roll that change back silently.
		if err := c.invalidateSnapshot(); err != nil {
			c.log.Error("cannot invalidate stale recovery snapshot after save failure", "err", err)
		}
	}
}

// The caller serializes snapshots. Never unlink through a foreign directory;
// directory fsync makes successful invalidation survive a restart as well.
func (c *Client) invalidateSnapshot() error {
	dir := c.snapshotDir()
	if err := privateDir(dir); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, "state.json")); err != nil && !os.IsNotExist(err) {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func (c *Client) writeSnapshot(token string, body []byte) error {
	raw, err := json.Marshal(signedSnapshot{Payload: body, MAC: snapshotMAC(token, body)})
	if err != nil {
		return err
	}
	if len(raw) > snapshotLimit {
		return errors.New("recovery snapshot exceeds size limit")
	}
	dir := c.snapshotDir()
	if err = privateDir(dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".snapshot-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, "state.json")); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func (c *Client) recoverSnapshot(cause error) error {
	if c.cfg.OfflineMaxAge == 0 || !transientStateError(cause) {
		return cause
	}
	c.snapshotMu.Lock()
	defer c.snapshotMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.revoked {
		return errors.New("captain: rejected state cannot be recovered")
	}
	if c.state != nil {
		if c.verifiedAt.IsZero() || time.Now().Before(c.verifiedAt) || !time.Now().Before(c.verifiedAt.Add(c.cfg.OfflineMaxAge)) {
			return errors.New("captain: offline recovery lease expired")
		}
		c.offline = true
		return nil
	}
	if err := privateDir(c.snapshotDir()); err != nil {
		return fmt.Errorf("captain: recovery unavailable: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(c.snapshotDir(), "state.json"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("captain: recovery unavailable: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > snapshotLimit || !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return errors.New("captain: unsafe recovery snapshot")
	}
	raw, err := io.ReadAll(io.LimitReader(f, snapshotLimit+1))
	if err != nil {
		return err
	}
	var signed signedSnapshot
	if json.Unmarshal(raw, &signed) != nil || !hmac.Equal([]byte(signed.MAC), []byte(snapshotMAC(c.token, signed.Payload))) {
		return errors.New("captain: corrupt or foreign recovery snapshot")
	}
	var saved offlineSnapshot
	identity := fmt.Sprintf("%x", sha256.Sum256([]byte(c.cfg.URL+"\x00"+c.token)))
	if json.Unmarshal(signed.Payload, &saved) != nil || saved.Version != 1 || saved.Identity != identity || saved.State.Revision == "" || saved.State.Node.ID == "" {
		return errors.New("captain: invalid recovery identity or state")
	}
	now := time.Now()
	if saved.ValidatedAt.IsZero() || now.Before(saved.ValidatedAt) || !now.Before(saved.ValidatedAt.Add(c.cfg.OfflineMaxAge)) {
		return errors.New("captain: offline recovery lease expired")
	}
	saved.State.Jobs = nil
	c.state = &saved.State
	c.verifiedAt = saved.ValidatedAt
	c.offline = true
	c.etag = ""
	c.log.Warn("using bounded offline state recovery", "expires_at", saved.ValidatedAt.Add(c.cfg.OfflineMaxAge))
	return nil
}

// Hand callers independent objects: certificate resolution and render preparation
// may mutate nested fields while the watcher persists the authenticated state.
func cloneState(in *agentproto.State) *agentproto.State {
	raw, _ := json.Marshal(in)
	var out agentproto.State
	_ = json.Unmarshal(raw, &out)
	return &out
}
func (c *Client) OfflineRecoveryActive() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg.OfflineMaxAge > 0 && c.offline
}
