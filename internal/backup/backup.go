// Package backup archives and restores a standalone node's configuration:
// the local state file, its traffic history, the Komari registration and
// operator-supplied certificates. ACME storage and panel TLS material are
// left out on purpose; they are re-obtained.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// members are the files an archive may carry, relative to the data dir.
var members = []string{"local.json", "local.history.json", "komari.json"}

const customCerts = "certs/custom"

// Name is the download file name for an archive taken now.
func Name(at time.Time) string { return "bosun-backup-" + at.Format("20060102-1504") + ".tar.gz" }

// Write streams a tar.gz of the data dir's standalone files to w.
func Write(dataDir string, w io.Writer) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	add := func(rel string) error {
		p := filepath.Join(dataDir, rel)
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		hdr := &tar.Header{Name: filepath.ToSlash(rel), Mode: 0o600, Size: st.Size(), ModTime: st.ModTime(), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err = io.Copy(tw, f)
		return err
	}
	if _, err := os.Stat(filepath.Join(dataDir, "local.json")); err != nil {
		return errors.New("backup: no local.json in " + dataDir)
	}
	for _, m := range members {
		if err := add(m); err != nil {
			return err
		}
	}
	root := filepath.Join(dataDir, customCerts)
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dataDir, p)
		return add(rel)
	})
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// Summary is what a restore found in the archive.
type Summary struct {
	Inbounds  int `json:"inbounds"`
	Users     int `json:"users"`
	Forwards  int `json:"forwards"`
	Ingresses int `json:"ingresses"`
	// AdminChanged is set when the archive's login differs from the current one.
	AdminChanged bool `json:"admin_changed"`
}

// stateShape is the part of local.json a restore inspects.
type stateShape struct {
	Mode  string `json:"mode"`
	Admin struct {
		Username     string `json:"username"`
		PasswordHash string `json:"password_hash"`
	} `json:"admin"`
	Inbounds  []json.RawMessage `json:"inbounds"`
	Users     []json.RawMessage `json:"users"`
	Forwards  []json.RawMessage `json:"forwards"`
	Ingresses []json.RawMessage `json:"ingresses"`
}

// Restore reads a tar.gz produced by Write, validates it and writes the
// files into dataDir atomically (each file via a temp name + rename).
// currentAdmin is the running login "username:hash" for AdminChanged.
func Restore(dataDir string, r io.Reader, currentAdmin string) (Summary, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return Summary{}, errors.New("backup: not a gzip archive")
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Summary{}, errors.New("backup: not a tar archive")
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := filepath.ToSlash(filepath.Clean(hdr.Name))
		if strings.HasPrefix(name, "../") || strings.HasPrefix(name, "/") || strings.Contains(name, "/../") {
			return Summary{}, errors.New("backup: refusing path " + hdr.Name)
		}
		if !allowed(name) {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, 64<<20))
		if err != nil {
			return Summary{}, err
		}
		files[name] = b
	}
	raw, ok := files["local.json"]
	if !ok {
		return Summary{}, errors.New("backup: archive has no local.json")
	}
	var st stateShape
	if err := json.Unmarshal(raw, &st); err != nil {
		return Summary{}, fmt.Errorf("backup: local.json: %w", err)
	}
	if st.Mode == "managed" {
		return Summary{}, errors.New("backup: archive was taken while managed by a panel; detach it first")
	}
	if st.Admin.Username == "" || st.Admin.PasswordHash == "" {
		return Summary{}, errors.New("backup: local.json has no admin login")
	}
	sum := Summary{Inbounds: len(st.Inbounds), Users: len(st.Users), Forwards: len(st.Forwards), Ingresses: len(st.Ingresses),
		AdminChanged: currentAdmin != "" && currentAdmin != st.Admin.Username+":"+st.Admin.PasswordHash}
	for name, b := range files {
		p := filepath.Join(dataDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return Summary{}, err
		}
		tmp := p + ".restore"
		if err := os.WriteFile(tmp, b, 0o600); err != nil {
			return Summary{}, err
		}
		if err := os.Rename(tmp, p); err != nil {
			return Summary{}, err
		}
	}
	return sum, nil
}

func allowed(name string) bool {
	for _, m := range members {
		if name == m {
			return true
		}
	}
	return strings.HasPrefix(name, customCerts+"/")
}
