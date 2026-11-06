package spec

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
)

// ConfigPreset contains only typed configuration. It never contains core
// overrides, accounting identities, control listeners or guard policies.
type ConfigPreset struct {
	ID      int64           `json:"id"`
	Name    string          `json:"name"`
	Kind    string          `json:"kind"`
	Payload json.RawMessage `json:"payload"`
}

type PresetRouting struct {
	Outbounds       []Outbound  `json:"outbounds"`
	Routes          []RouteRule `json:"routes"`
	DefaultOutbound string      `json:"default_outbound"`
	DNS             []string    `json:"dns"`
}

// InboundTemplate makes a detached copy, discarding credentials and placement.
// Certificate paths are deliberately not portable across machines.
func InboundTemplate(ib Inbound) Inbound {
	ib.PrivateAccess = nil // permissions are local decisions, never template defaults
	raw, _ := json.Marshal(ib)
	var v Inbound
	_ = json.Unmarshal(raw, &v)
	v.Tag, v.Listen, v.Port = "", "", 0
	v.Users, v.ScopedUsers = nil, false
	v.ServerKey, v.ObfsPassword, v.SnellPSK = "", "", ""
	v.WGPrivateKey, v.WGPublicKey = "", ""
	v.SSH = nil
	if v.TLS != nil {
		v.TLS.CertPath, v.TLS.KeyPath = "", ""
		if v.TLS.Mode == TLSStandard {
			v.TLS.AutoCert = true
		}
		if v.TLS.Reality != nil {
			v.TLS.Reality.PrivateKey, v.TLS.Reality.PublicKey = "", ""
			v.TLS.Reality.ShortIDs = nil
		}
	}
	return v
}

func (p *ConfigPreset) Normalize() error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > 100 || !Plain(p.Name) || len(p.Payload) > 128<<10 {
		return fmt.Errorf("invalid preset name or size")
	}
	var value any
	switch p.Kind {
	case "inbound":
		var ib Inbound
		if err := json.Unmarshal(p.Payload, &ib); err != nil {
			return fmt.Errorf("invalid inbound preset")
		}
		ib = InboundTemplate(ib)
		check := ib
		check.Tag = "preset"
		check.Port = 443
		// Deep-copy before generating credentials, so no generated key enters storage.
		raw, _ := json.Marshal(check)
		check = Inbound{}
		_ = json.Unmarshal(raw, &check)
		FillInboundSecrets(&check)
		if err := check.Validate(); err != nil {
			return err
		}
		if _, err := SelectCore(check, CoreCatalog()); err != nil {
			return err
		}
		value = ib
	case "outbounds":
		var outs []Outbound
		if err := json.Unmarshal(p.Payload, &outs); err != nil || len(outs) == 0 || len(outs) > 100 {
			return fmt.Errorf("expected 1-100 typed outbounds")
		}
		tags := map[string]bool{}
		for _, o := range outs {
			if tags[o.Tag] {
				return fmt.Errorf("duplicate outbound tag")
			}
			tags[o.Tag] = true
			if err := validatePresetOutbound(o); err != nil {
				return err
			}
		}
		value = outs
	case "routes":
		var rules []RouteRule
		if err := json.Unmarshal(p.Payload, &rules); err != nil || len(rules) == 0 || len(rules) > 200 {
			return fmt.Errorf("expected 1-200 route rules")
		}
		for _, r := range rules {
			for _, m := range r.Match {
				if !Plain(m) {
					return fmt.Errorf("route matches may not contain control characters")
				}
			}
			if err := ValidateRouteRule(r); err != nil {
				return err
			}
			if r.Action == "outbound" && !ValidTag(r.Value) {
				return fmt.Errorf("invalid outbound tag")
			}
		}
		value = rules
	default:
		return fmt.Errorf("preset kind must be inbound, outbounds or routes")
	}
	p.Payload, _ = json.Marshal(value)
	return nil
}

func validatePresetOutbound(o Outbound) error {
	if !ValidTag(o.Tag) || o.Tag == "direct" || o.Tag == "block" {
		return fmt.Errorf("invalid outbound tag")
	}
	if o.Protocol != "" || len(o.Settings) != 0 {
		return fmt.Errorf("raw core outbounds cannot be saved as presets; use a share link, WARP or a balancer")
	}
	n := 0
	if o.Remote != nil {
		n++
	}
	if o.WARP != nil {
		n++
	}
	if o.Balancer != nil {
		n++
	}
	if n != 1 {
		return fmt.Errorf("one outbound type is required")
	}
	if o.ProxyTag != "" && (!ValidTag(o.ProxyTag) || o.ProxyTag == o.Tag) {
		return fmt.Errorf("invalid outbound chain")
	}
	if o.Remote != nil {
		r := o.Remote
		if r.Port < 1 || r.Port > 65535 || r.Host == "" || !Plain(r.Host) || strings.ContainsAny(r.Host, " /\\\"'") {
			return fmt.Errorf("invalid remote host or port")
		}
		if r.Settings.ScopedUsers || len(r.Settings.Users) > 0 || r.Settings.SSH != nil || r.Settings.WGPrivateKey != "" || r.Settings.SnellPSK != "" || r.Settings.ServerKey != "" {
			return fmt.Errorf("remote contains server-only credentials")
		}

		if tls := r.Settings.TLS; tls != nil && (tls.CertPath != "" || tls.KeyPath != "" || tls.Reality != nil && tls.Reality.PrivateKey != "") {
			return fmt.Errorf("remote contains server-only TLS material")
		}
		if r.Settings.Protocol == SSH {
			if err := r.validateSSH(); err != nil {
				return err
			}
		} else if r.SSH != nil {
			return fmt.Errorf("SSH client options require an SSH remote")
		}
		check := InboundTemplate(r.Settings)
		check.Tag = "remote"
		check.Port = r.Port
		FillInboundSecrets(&check)
		if err := check.Validate(); err != nil {
			return err
		}
		supported := false
		for _, c := range CoreCatalog() {
			if c.Capabilities.UnsupportedReason(r.Settings) == "" {
				supported = true
			}
		}
		if !supported {
			return fmt.Errorf("unsupported remote protocol")
		}
		for _, s := range []string{r.UUID, r.Username, r.Password, r.Fingerprint} {
			if !Plain(s) {
				return fmt.Errorf("remote fields may not contain control characters")
			}
		}
	}
	if o.WARP != nil {
		w := o.WARP
		// A reusable WARP preset uses each node's own account, not a copied key.
		if !w.FromNode || w.PrivateKey != "" || w.License != "" || len(w.Addresses) > 0 {
			return fmt.Errorf("WARP presets must use the node's own account")
		}
		if w.Endpoint != "" {
			if _, _, err := net.SplitHostPort(w.Endpoint); err != nil {
				return fmt.Errorf("invalid WARP endpoint")
			}
		}
	}
	if o.Balancer != nil {
		if len(o.Balancer.Members) == 0 || len(o.Balancer.Members) > 100 {
			return fmt.Errorf("balancer needs members")
		}
		if v := o.Balancer.Strategy; v != "" && v != "urltest" && v != "random" {
			return fmt.Errorf("invalid balancer strategy")
		}
		for _, v := range o.Balancer.Members {
			if !ValidTag(v) || v == o.Tag {
				return fmt.Errorf("invalid balancer member")
			}
		}
	}
	return nil
}

// ValidateRoutingReferences is also used by normal saves. It checks all graph
// edges, including balancer membership, so mixed chain/balancer cycles fail.
func ValidateRoutingReferences(outs []Outbound, rules []RouteRule, def string) error {
	tags := map[string]bool{"direct": true, "block": true}
	edges := map[string][]string{}
	for _, o := range outs {
		if !ValidTag(o.Tag) || tags[o.Tag] {
			return fmt.Errorf("outbound tags must be unique and not direct/block")
		}
		tags[o.Tag] = true
		if o.ProxyTag != "" {
			edges[o.Tag] = append(edges[o.Tag], o.ProxyTag)
		}
		if o.Balancer != nil {
			edges[o.Tag] = append(edges[o.Tag], o.Balancer.Members...)
		}
	}
	colors := map[string]int{}
	var visit func(string) error
	visit = func(tag string) error {
		if !tags[tag] {
			return fmt.Errorf("unknown outbound %s", tag)
		}
		if colors[tag] == 1 {
			return fmt.Errorf("outbound chain or balancer loop")
		}
		if colors[tag] == 2 {
			return nil
		}
		colors[tag] = 1
		for _, e := range edges[tag] {
			if err := visit(e); err != nil {
				return err
			}
		}
		colors[tag] = 2
		return nil
	}
	for tag := range edges {
		if err := visit(tag); err != nil {
			return err
		}
	}
	for _, r := range rules {
		if err := ValidateRouteRule(r); err != nil {
			return err
		}
		if r.Action == "outbound" && (!tags[r.Value] || r.Value == "direct" || r.Value == "block") {
			return fmt.Errorf("rule points at unknown outbound")
		}
	}
	if def != "" && (!tags[def] || def == "direct" || def == "block") {
		return fmt.Errorf("default outbound is not defined")
	}
	return nil
}

type PresetChange struct {
	Field  string `json:"field"`
	Before any    `json:"before"`
	After  any    `json:"after"`
}
type PresetPreview struct {
	Draft   json.RawMessage `json:"draft"`
	Changes []PresetChange  `json:"changes"`
	Cores   *CoreOptions    `json:"cores,omitempty"`
}

// Preview never writes live configuration. Inbound previews keep placement and
// user scope from the caller's draft, generate fresh server secrets and replace
// protocol settings. Routing fragments append without touching DNS/default.
func (p ConfigPreset) Preview(current json.RawMessage) (PresetPreview, error) {
	out := PresetPreview{Changes: []PresetChange{}}
	if err := p.Normalize(); err != nil {
		return out, err
	}
	var before, after any
	switch p.Kind {
	case "inbound":
		var cur, next Inbound
		if json.Unmarshal(current, &cur) != nil {
			return out, fmt.Errorf("invalid current inbound")
		}
		_ = json.Unmarshal(p.Payload, &next)
		next.Tag, next.Listen, next.Port = cur.Tag, cur.Listen, cur.Port
		next.Users, next.ScopedUsers = cur.Users, cur.ScopedUsers
		next.PrivateAccess = cur.PrivateAccess
		if next.Tag == "" {
			next.Tag = string(next.Protocol)
		}
		FillInboundSecrets(&next)
		if err := next.Validate(); err != nil {
			return out, err
		}
		if _, err := SelectCore(next, CoreCatalog()); err != nil {
			return out, err
		}
		cores := PreviewCores(next, nil)
		out.Cores = &cores
		out.Draft, _ = json.Marshal(next)
		before, after = InboundTemplate(cur), InboundTemplate(next)
	case "outbounds", "routes":
		var cur PresetRouting
		if json.Unmarshal(current, &cur) != nil {
			return out, fmt.Errorf("invalid current routing")
		}
		before = cur
		if p.Kind == "outbounds" {
			var v []Outbound
			_ = json.Unmarshal(p.Payload, &v)
			cur.Outbounds = append(append([]Outbound{}, cur.Outbounds...), v...)
		} else {
			var v []RouteRule
			_ = json.Unmarshal(p.Payload, &v)
			cur.Routes = append(append([]RouteRule{}, cur.Routes...), v...)
		}
		if len(cur.Outbounds) > 300 || len(cur.Routes) > 1000 {
			return out, fmt.Errorf("too many routes or outbounds")
		}
		if err := ValidateRoutingReferences(cur.Outbounds, cur.Routes, cur.DefaultOutbound); err != nil {
			return out, err
		}
		after = cur
		out.Draft, _ = json.Marshal(cur)
	}
	// Redact credentials in the displayed diff; the draft is returned only to
	// the authenticated editor that already owns the source configuration.
	a, b := presetView(before), presetView(after)
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	sorted := []string{}
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
		if !reflect.DeepEqual(a[k], b[k]) {
			out.Changes = append(out.Changes, PresetChange{k, a[k], b[k]})
		}
	}
	return out, nil
}
func presetView(v any) map[string]any {
	raw, _ := json.Marshal(v)
	m := map[string]any{}
	_ = json.Unmarshal(raw, &m)
	var clean func(any)
	clean = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, v := range x {
				if strings.Contains(k, "password") || strings.Contains(k, "key") || k == "uuid" || k == "username" {
					x[k] = "[redacted]"
				} else {
					clean(v)
				}
			}
		case []any:
			for _, v := range x {
				clean(v)
			}
		}
	}
	clean(m)
	return m
}
