package subdesign

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestManagedResourceURLsAndPublicHandlers(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte("GEOIP,CN"))
	template := "resource_parser_url={{resource_parser_url}}\n{{inline_rule_url:qx:" + encoded + "}}"
	out, err := BindResourceURLs(template, "https://panel.example.com")
	if err != nil || strings.Contains(out, "{{") {
		t.Fatalf("bind resources: %q, %v", out, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+QuantumultXRuleParserPath, ServeQuantumultXRuleParser)
	mux.HandleFunc("GET "+InlineRuleResourcePath+"{format}/{rule}", ServeInlineRuleResource)
	for _, raw := range strings.Split(strings.TrimPrefix(out, "resource_parser_url="), "\n") {
		u, err := url.Parse(raw)
		if err != nil || u.Host != "panel.example.com" || u.Query().Get("v") == "" {
			t.Fatalf("resource origin/version: %q", raw)
		}
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest("GET", u.RequestURI(), nil))
		if recorder.Code != 200 || recorder.Body.Len() == 0 || recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("public resource: %d %s", recorder.Code, recorder.Body.String())
		}
		req := httptest.NewRequest("GET", u.RequestURI(), nil)
		req.Header.Set("If-None-Match", recorder.Header().Get("ETag"))
		cached := httptest.NewRecorder()
		mux.ServeHTTP(cached, req)
		if cached.Code != 304 || cached.Body.Len() != 0 {
			t.Fatal("matching resource cache should return no body")
		}
		head := httptest.NewRecorder()
		mux.ServeHTTP(head, httptest.NewRequest("HEAD", u.RequestURI(), nil))
		if head.Code != 200 || head.Body.Len() != 0 {
			t.Fatal("HEAD must not return the resource body")
		}
	}
}

func TestManagedResourceURLsRejectUnsafeInputs(t *testing.T) {
	for _, base := range []string{"", "//example.com", "https://user:secret@example.com", "https://example.com/?token=secret", "https://example.com/#fragment", "https://example.com,enabled=false", "https://example.com/\n[Rule]", "file:///tmp/file"} {
		if _, err := BindResourceURLs("{{resource_parser_url}}", base); err == nil {
			t.Errorf("accepted unsafe origin %q", base)
		}
	}
	if got, err := BindResourceURLs("unmodified template", ""); err != nil || got != "unmodified template" {
		t.Fatal("ordinary templates must not require a configured resource origin")
	}
	for _, expression := range []string{"", "DOMAIN,example.com\nFINAL,DIRECT", "DOMAIN,example.com,policy", "RULE-SET,https://example.com/remote", strings.Repeat("x", 4097)} {
		encoded := base64.RawURLEncoding.EncodeToString([]byte(expression))
		if _, err := inlineResourceBody("loon", encoded); err == nil {
			t.Errorf("accepted invalid expression %q", expression)
		}
	}
	for _, template := range []string{"{{inline_rule_url:other:QQ}}", "{{inline_rule_url:qx:!}}", "{{inline_rule_url:loon:QQ}}"} {
		if _, err := BindResourceURLs(template, "https://example.com"); err == nil {
			t.Errorf("accepted malformed resource %q", template)
		}
	}
}
