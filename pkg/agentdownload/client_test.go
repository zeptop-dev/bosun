package agentdownload

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestAuthenticationChangesAfterPairingAndNeverLeavesEndpoint(t *testing.T) {
	var auth, pair string
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		auth = r.Header.Get("Authorization")
		pair = r.Header.Get("X-Bosun-Pair-Code")
		if r.URL.Path == Prefix+"redirect" {
			http.Redirect(w, r, "/api/admin", 302)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	token := filepath.Join(t.TempDir(), "token")
	c, err := New(srv.URL, token, "ABCD-EFGH", true)
	if err != nil {
		t.Fatal(err)
	}
	get := func(path string) error {
		resp, err := c.HTTP.Get(path)
		if resp != nil {
			resp.Body.Close()
		}
		return err
	}
	if err := get(srv.URL + Prefix + "bosun/v0.89.0/SHA256SUMS"); err != nil {
		t.Fatal(err)
	}
	if auth != "" || pair != "ABCD-EFGH" {
		t.Fatalf("bootstrap authentication: %q %q", auth, pair)
	}
	if err := os.WriteFile(token, []byte("node-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := get(srv.URL + Prefix + "bosun/v0.89.0/SHA256SUMS"); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer node-token" || pair != "" {
		t.Fatalf("node authentication: %q %q", auth, pair)
	}
	before := calls
	for _, bad := range []string{srv.URL + "/api/admin", srv.URL + Prefix + "../pair", srv.URL + Prefix + "bosun?token=secret", "https://example.com" + Prefix + "asset", srv.URL + Prefix + "%2e%2e/pair", srv.URL + Prefix + "bosun%2fasset"} {
		if err := get(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if calls != before {
		t.Fatalf("rejected URL reached network: %d -> %d", before, calls)
	}
	if err := get(srv.URL + Prefix + "redirect"); err == nil {
		t.Fatal("redirect followed")
	}
	if calls != before+1 {
		t.Fatal("redirect target reached network")
	}
}

func TestEndpointValidationAndMissingCredentials(t *testing.T) {
	for _, base := range []string{"http://example.com", "https://user:secret@example.com", "https://example.com?x=1", "https://example.com/#f", "https://example.com/a/../b", "https://example.com/a%2fb", "https://example.com//x", "https://example.com/panel", "https://:18443"} {
		if _, err := New(base, "", "", false); err == nil {
			t.Errorf("accepted endpoint %s", base)
		}
	}
	c, err := New("https://example.com", filepath.Join(t.TempDir(), "missing"), "", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.HTTP.Get(c.APIBase() + "/asset"); err == nil {
		t.Fatal("unauthenticated download allowed")
	}
	for _, p := range []string{"/panel" + Prefix + "asset", "//evil.example" + Prefix + "asset", "?token=x"} {
		if _, err := c.URL(p); err == nil {
			t.Errorf("accepted out-of-prefix %s", p)
		}
	}
	if got, err := c.URL(Prefix + "asset"); err != nil || got != "https://example.com"+Prefix+"asset" {
		t.Fatalf("relative url %s %v", got, err)
	}
}
