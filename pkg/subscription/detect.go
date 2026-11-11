package subscription

import (
	"regexp"
	"strconv"
	"strings"
)

// Renderers by client name; "uri" is the fallback.
var renderers = map[string]Renderer{
	"clash":     Clash{},
	"stash":     Stash{},
	"singbox":   SingBox{},
	"surge":     Surge{},
	"surfboard": Surfboard{},
	"loon":      Loon{},
	"qx":        QuantumultX{},
	"uri":       URIList{},
	"wireguard": WireGuardConf{},
	"egern":     Egern{},
}

// Aliases users may pass in ?client=.
var aliases = map[string]string{
	"mihomo": "clash", "clashmeta": "clash", "clash-meta": "clash",
	"sing-box": "singbox", "sfa": "singbox", "sfi": "singbox",
	"nb4a": "singbox", "nekobox-android": "singbox",
	"quantumultx": "qx", "quantumult-x": "qx", "quantumult": "qx",
	"shadowrocket": "uri", "v2rayn": "uri", "v2rayng": "uri", "base64": "uri",
	"wg": "wireguard", "wireguard-conf": "wireguard",
}

// Pick chooses a renderer from an explicit client name or the User-Agent.
// Order matters: Stash and Surfboard identify themselves alongside the
// family they descend from, so they are matched before Clash and Surge.
func Pick(client, userAgent string) Renderer {
	if strings.EqualFold(client, "surge-vless") {
		return Surge{VLESS: true}
	}
	if strings.EqualFold(client, "surge-legacy") {
		return Surge{}
	}
	if client != "" {
		c := strings.ToLower(client)
		if a, ok := aliases[c]; ok {
			c = a
		}
		if r, ok := renderers[c]; ok {
			if c == "surge" {
				return Surge{VLESS: surgeSupportsVLESS(userAgent)}
			}
			return r
		}
	}
	ua := strings.ToLower(userAgent)
	switch {
	case strings.Contains(ua, "egern"):
		return renderers["egern"]
	case strings.Contains(ua, "stash"):
		return renderers["stash"]
	case strings.Contains(ua, "clash"), strings.Contains(ua, "mihomo"):
		return renderers["clash"]
	case strings.Contains(ua, "sing-box"), strings.Contains(ua, "sfa"), strings.Contains(ua, "sfi"):
		return renderers["singbox"]
	case strings.Contains(ua, "surfboard"):
		return renderers["surfboard"]
	case strings.Contains(ua, "surge"):
		return Surge{VLESS: surgeSupportsVLESS(userAgent)}
	case strings.Contains(ua, "loon"):
		return renderers["loon"]
	case strings.Contains(ua, "quantumult"):
		return renderers["qx"]
	}
	return renderers["uri"]
}

// Only recognizable app-version UAs opt in automatically. Bare Surge/6 is
// ambiguous between iOS and Mac; keep legacy behavior rather than guess.
var surgeAppVersion = regexp.MustCompile(`(?i)surge(?:[ /-](?:mac|ios))?/([0-9]+)\.([0-9]+)(?:\.[0-9]+)?(?:[^0-9.]|$)`)

func surgeSupportsVLESS(ua string) bool {
	m := surgeAppVersion.FindStringSubmatch(ua)
	if m == nil {
		return false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	lower := strings.ToLower(ua)
	ios := strings.Contains(lower, "iphone") || strings.Contains(lower, "ipad") || strings.Contains(lower, "surge ios/") || strings.Contains(lower, "surge-ios/")
	mac := strings.Contains(lower, "mac")
	if ios && !mac {
		return major >= 6
	}
	return major > 6 || major == 6 && minor >= 12
}
