package subdesign

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// QuantumultXRuleParserPath is a public, credential-free script resource.
const QuantumultXRuleParserPath = "/sub-resources/qx-rule-parser.js"

// InlineRuleResourcePath contains only validated, policy-free rule expressions.
const InlineRuleResourcePath = "/sub-resources/inline/"

var inlineResourcePlaceholder = regexp.MustCompile(`\{\{inline_rule_url:(loon|qx):([A-Za-z0-9_-]+)\}\}`)

// BindResourceURLs resolves managed resources at delivery time, after selecting
// the effective template. No account token or request query belongs in a script
// URL: Quantumult X fetches the parser independently of the subscription.
func BindResourceURLs(template, baseURL string) (string, error) {
	const placeholder = "{{resource_parser_url}}"
	if !strings.Contains(template, placeholder) && !strings.Contains(template, "{{inline_rule_url:") {
		return template, nil
	}
	u, err := url.Parse(baseURL)
	if err != nil || u == nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(baseURL, " \t\r\n,{}") {
		return "", fmt.Errorf("invalid subscription resource base URL")
	}
	basePath := strings.TrimRight(u.Path, "/")
	u.Path = basePath + QuantumultXRuleParserPath
	u.RawPath = ""
	digest := sha256.Sum256([]byte(QuantumultXRuleParser()))
	u.RawQuery = fmt.Sprintf("v=%x", digest[:12])
	template = strings.ReplaceAll(template, placeholder, u.String())
	var resourceErr error
	template = inlineResourcePlaceholder.ReplaceAllStringFunc(template, func(match string) string {
		parts := inlineResourcePlaceholder.FindStringSubmatch(match)
		if _, err := inlineResourceBody(parts[1], parts[2]); err != nil {
			resourceErr = err
			return match
		}
		resourceURL := *u
		resourceURL.Path = basePath + InlineRuleResourcePath + parts[1] + "/" + parts[2]
		return resourceURL.String()
	})
	if resourceErr != nil || strings.Contains(template, "{{inline_rule_url:") {
		return "", fmt.Errorf("invalid inline rule resource")
	}
	return template, nil
}

func inlineResourceBody(format, encoded string) (string, error) {
	if len(encoded) > 5500 {
		return "", fmt.Errorf("inline rule resource too large")
	}
	expression, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(expression) == 0 || len(expression) > 4096 {
		return "", fmt.Errorf("invalid inline rule resource")
	}
	return InlineRuleResource(format, string(expression))
}

// ServeInlineRuleResource preserves the position of inline rules among remote
// rules on clients with separate local/remote sections. Only validated rule
// expressions are rendered; the endpoint has no network or storage access.
func ServeInlineRuleResource(w http.ResponseWriter, r *http.Request) {
	body, err := inlineResourceBody(r.PathValue("format"), r.PathValue("rule"))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err != nil {
		http.Error(w, "invalid inline rule resource", http.StatusBadRequest)
		return
	}
	digest := sha256.Sum256([]byte(body))
	etag := fmt.Sprintf("\"%x\"", digest[:])
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(body))
	}
}

// ServeQuantumultXRuleParser serves only the embedded converter, never a file or
// an upstream URL. Its hash changes when the converter changes so subscriptions
// do not keep referring to an obsolete cached script after an upgrade.
func ServeQuantumultXRuleParser(w http.ResponseWriter, r *http.Request) {
	script := QuantumultXRuleParser()
	digest := sha256.Sum256([]byte(script))
	etag := fmt.Sprintf("\"%x\"", digest[:])
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(script))
	}
}
