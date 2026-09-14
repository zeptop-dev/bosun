package ui

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/internal/local"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestDoctorAndBackupAPI(t *testing.T) {
	dir := t.TempDir()
	store, _, err := local.Open(filepath.Join(dir, "local.json"), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	_ = store.SetAdmin("boss", "correct-horse")
	_ = store.PutInbound(local.Inbound{Inbound: spec.Inbound{Tag: "ss", Protocol: spec.Shadowsocks, Port: 8388, Cipher: "aes-128-gcm", ServerKey: "x"}, Enabled: true}, "")
	s := New(Deps{Store: store, Version: "test", Log: slog.Default()})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, srv: srv, http: &http.Client{Jar: jar}}
	if code, _ := c.do("POST", "/api/login", map[string]string{"Username": "boss", "Password": "correct-horse"}); code != 200 {
		t.Fatal("login")
	}

	// Doctor without an agent still produces a report (everything skipped).
	code, b := c.do("GET", "/api/doctor", nil)
	var rep struct {
		Checks  []map[string]any `json:"checks"`
		Summary map[string]int   `json:"summary"`
	}
	_ = json.Unmarshal(b, &rep)
	if code != 200 || len(rep.Checks) == 0 || rep.Summary["skip"] == 0 {
		t.Fatalf("doctor: %d %s", code, b)
	}

	// Backup streams a tar.gz; restoring it into the same node round-trips.
	resp, err := c.http.Get(srv.URL + "/api/backup")
	if err != nil {
		t.Fatal(err)
	}
	archive, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/gzip" || !strings.Contains(resp.Header.Get("Content-Disposition"), "bosun-backup-") || len(archive) < 100 {
		t.Fatalf("backup: %d %s %d bytes", resp.StatusCode, resp.Header.Get("Content-Disposition"), len(archive))
	}
	_ = store.DeleteInbound("ss")
	if len(store.Inbounds()) != 0 {
		t.Fatal("setup")
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "backup.tar.gz")
	_, _ = fw.Write(archive)
	mw.Close()
	req, _ := http.NewRequest("POST", srv.URL+"/api/backup/restore", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err = c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	rb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(rb), `"inbounds":1`) || !strings.Contains(string(rb), `"admin_changed":false`) {
		t.Fatalf("restore: %d %s", resp.StatusCode, rb)
	}
	if len(store.Inbounds()) != 1 || !store.Login("boss", "correct-horse") {
		t.Fatal("store not reloaded from the archive")
	}
	// Garbage is refused.
	body.Reset()
	mw = multipart.NewWriter(&body)
	fw, _ = mw.CreateFormFile("file", "x.tar.gz")
	_, _ = fw.Write([]byte("garbage"))
	mw.Close()
	req, _ = http.NewRequest("POST", srv.URL+"/api/backup/restore", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, _ = c.http.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("garbage restore: %d", resp.StatusCode)
	}
}
