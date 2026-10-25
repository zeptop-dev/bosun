package ui

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/zeptop-dev/bosun/internal/local"
	"github.com/zeptop-dev/bosun/pkg/subdesign"
)

func TestSubDesignInspectAndSelectiveApply(t *testing.T) {
	store, pw, err := local.Open(filepath.Join(t.TempDir(), "local.json"), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Deps{Store: store, Version: "test", Log: slog.Default()}).Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, srv: srv, http: &http.Client{Jar: jar}}
	design := subdesign.Design{
		Groups: []subdesign.Group{{Name: "Proxy", Type: "select", Members: []string{"@all"}}},
		Rules:  []subdesign.Rule{{Set: "media", Policy: "Proxy"}},
		Final:  "Proxy",
	}
	request := map[string]any{"design": design}
	if code, _ := c.do("POST", "/api/sub-design/inspect", request); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated inspection: %d", code)
	}
	if code, b := c.do("POST", "/api/login", map[string]string{"Username": "admin", "Password": pw}); code != http.StatusOK {
		t.Fatalf("login: %d %s", code, b)
	}
	old := subdesign.Design{Final: "DIRECT"}
	if err := store.SetSubDesign(old); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSubTemplates(map[string]string{"clash": "manual-clash", "stash": "manual-stash", "qx": "manual-qx"}); err != nil {
		t.Fatal(err)
	}
	oldTemplates := store.SubTemplates()
	oldBytes, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	assertUnchanged := func() {
		t.Helper()
		current, err := os.ReadFile(store.Path())
		if err != nil || string(current) != string(oldBytes) || !reflect.DeepEqual(store.SubDesign(), old) || !reflect.DeepEqual(store.SubTemplates(), oldTemplates) {
			t.Fatal("rejected request changed the saved draft or any template", err)
		}
	}
	code, body := c.do("POST", "/api/sub-design/inspect", request)
	var result struct {
		Formats []subdesign.FormatSupport `json:"formats"`
	}
	if err := json.Unmarshal(body, &result); err != nil || code != http.StatusOK || len(result.Formats) != len(subdesign.Formats) {
		t.Fatalf("inspect: %d %s (%v)", code, body, err)
	}
	for _, item := range result.Formats {
		if item.Format == "qx" && (item.Supported || !slices.Contains(item.ReasonCodes, "remote_rules_unsupported")) {
			t.Fatalf("ProxyMedia incompatibility not reported: %+v", item)
		}
		if item.Format == "loon" && (!item.Supported || !slices.Contains(item.WarningCodes, "native_rule_priority")) {
			t.Fatalf("Loon requirements not reported: %+v", item)
		}
	}
	assertUnchanged()

	for _, tc := range []struct {
		name    string
		formats any
		omitted bool
	}{
		{name: "omitted", omitted: true},
		{name: "null", formats: nil},
		{name: "empty", formats: []string{}},
		{name: "unsupported", formats: []string{"clash", "qx"}},
		{name: "unknown", formats: []string{"clash", "invalid"}},
		{name: "duplicate", formats: []string{"clash", "clash"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := map[string]any{"design": design}
			if !tc.omitted {
				in["formats"] = tc.formats
			}
			if code, b := c.do("POST", "/api/sub-design/apply", in); code != http.StatusBadRequest {
				t.Fatalf("apply should reject: %d %s", code, b)
			}
			assertUnchanged()
		})
	}
	// A failed state-file replacement must not leave the new draft applied
	// alongside old templates, or expose new templates only in memory.
	func() {
		path := store.Path()
		backup := path + ".previous"
		if err := os.Rename(path, backup); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Remove(path); err != nil {
				t.Error(err)
			}
			if err := os.Rename(backup, path); err != nil {
				t.Error(err)
			}
		}()
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if code, b := c.do("POST", "/api/sub-design/apply", map[string]any{"design": design, "formats": []string{"clash"}}); code != http.StatusInternalServerError {
			t.Fatalf("failed file replacement should fail apply: %d %s", code, b)
		}
	}()
	assertUnchanged()
	if code, b := c.do("POST", "/api/sub-design/apply", map[string]any{"design": design, "formats": []string{"clash", "loon"}}); code != http.StatusOK {
		t.Fatalf("explicit supported selection: %d %s", code, b)
	}
	if store.SubTemplate("clash") == "manual-clash" || store.SubTemplate("loon") == "" || store.SubTemplate("qx") != "manual-qx" || store.SubTemplate("stash") != "manual-stash" || !reflect.DeepEqual(store.SubDesign(), design) {
		t.Fatal("selected templates or draft not updated; or unselected template overwritten")
	}

	// Existing callers which omit formats still apply all formats when the
	// complete design can be represented by every client.
	design.Rules = nil
	if code, b := c.do("POST", "/api/sub-design/apply", map[string]any{"design": design}); code != http.StatusOK {
		t.Fatalf("legacy all-format apply: %d %s", code, b)
	}
	for _, format := range subdesign.Formats {
		text, err := design.Render(format)
		if err != nil || store.SubTemplate(format) != text {
			t.Fatalf("legacy apply missing %s: %v", format, err)
		}
	}
	if err := store.Adopt("https://example.com"); err != nil {
		t.Fatal(err)
	}
	if code, _ := c.do("POST", "/api/sub-design/apply", map[string]any{"design": design, "formats": []string{"clash"}}); code != http.StatusForbidden && code != http.StatusConflict {
		t.Fatalf("managed mode allowed local apply: %d", code)
	}
}
