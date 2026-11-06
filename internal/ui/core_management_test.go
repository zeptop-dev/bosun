package ui

import (
	"github.com/zeptop-dev/bosun/internal/local"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestCoreManagementAccess(t *testing.T) {
	store, pw, err := local.Open(filepath.Join(t.TempDir(), "local.json"), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	s := New(Deps{Store: store, Log: slog.Default()})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, srv: srv, http: &http.Client{Jar: jar}}
	body := map[string]any{"action": "activate", "distribution": "singbox", "version": "1.14.1-r3", "revision": 1}
	if code, _ := c.do("POST", "/api/core-management", body); code != 401 {
		t.Fatal(code)
	}
	c.do("POST", "/api/login", map[string]string{"Username": "admin", "Password": pw})
	if code, _ := c.do("POST", "/api/core-management", body); code != 409 {
		t.Fatal(code)
	}
	s.d.Fixed = "captain"
	if code, _ := c.do("POST", "/api/core-management", body); code != 409 {
		t.Fatal("managed local write", code)
	}
}
