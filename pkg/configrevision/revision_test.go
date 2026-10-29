package configrevision

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func digest(t *testing.T, n spec.Node, f []spec.Forward) string {
	t.Helper()
	value, err := Digest(n, f)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestVersionedEmptyProjection(t *testing.T) {
	// Altering the DTO envelope or its defaults changes this public contract;
	// review Prefix rather than silently changing an already released version.
	const want = "cfg1-f8ea6711ce01e6dd3f886af482e74a7f64e8294cc936627fe61cb350b32d3d90"
	if got := digest(t, spec.Node{}, nil); got != want {
		t.Fatal("versioned projection changed", got)
	}
}
func fixture() (spec.Node, []spec.Forward) {
	n := spec.Node{ID: "node", Inbounds: []spec.Inbound{
		{Tag: "b", Protocol: spec.VLESS, Port: 443, TLS: &spec.TLS{Mode: spec.TLSReality, ServerName: "cover.example", Reality: &spec.Reality{PrivateKey: "secret", PublicKey: "public", ShortIDs: []string{"short"}, HandshakeServer: "cover.example", HandshakePort: 443}}},
		{Tag: "a", Protocol: spec.Trojan, Port: 8443},
	}, Outbounds: []spec.Outbound{{Tag: "z", Protocol: "vless", Remote: &spec.Remote{Host: "exit.example", Port: 443, UUID: "remote-secret", Settings: spec.Inbound{Protocol: spec.VLESS}}}, {Tag: "a", Protocol: "direct"}}, Routes: []spec.RouteRule{{Match: []string{"domain:example.com"}, Action: "outbound", Value: "z"}, {Match: []string{"ip:10.0.0.0/8"}, Action: "block"}}, DNS: []string{"1.1.1.1", "8.8.8.8"}, PrivateDestAllow: []string{"192.168.0.0/16", "10.0.0.0/8"}, ReverseClients: []spec.ReverseClient{{ID: "b", Host: "b.example", Port: 443}, {ID: "a", Host: "a.example", Port: 443}}, WireGuardLinks: []spec.WireGuardLink{{Slot: 2, Endpoint: "198.51.100.2:51820"}, {Slot: 1, Endpoint: "192.0.2.1:51820"}}, EgressUpstreams: []spec.EgressUpstream{{CIDR: "192.0.2.2", Port: 443, Protocol: "tcp"}, {CIDR: "192.0.2.1", Port: 53, Protocol: "udp"}}}
	f := []spec.Forward{{Tag: "b", Port: 18443, Protocol: "tcp", Target: "192.0.2.1:443", Targets: []spec.ForwardTarget{{Target: "192.0.2.2:443", Weight: 2}, {Target: "192.0.2.3:443", Weight: 3}}}, {Tag: "a", Port: 19443, Protocol: "udp", Target: "192.0.2.4:443"}}
	return n, f
}

func TestStableResourceOrderWithoutLosingOrderedSemantics(t *testing.T) {
	n, f := fixture()
	before, _ := json.Marshal(testInput{n, f})
	want := digest(t, n, f)
	if !strings.HasPrefix(want, Prefix) || len(want) != len(Prefix)+64 {
		t.Fatal("invalid digest format", want)
	}
	for range 3 {
		if got := digest(t, n, f); got != want {
			t.Fatal("non-deterministic digest", got, want)
		}
	}
	after, _ := json.Marshal(testInput{n, f})
	if string(before) != string(after) {
		t.Fatal("digest mutated caller input")
	}
	slices.Reverse(n.Inbounds)
	slices.Reverse(n.Outbounds)
	slices.Reverse(n.ReverseClients)
	slices.Reverse(n.WireGuardLinks)
	slices.Reverse(n.EgressUpstreams)
	slices.Reverse(n.PrivateDestAllow)
	slices.Reverse(f)
	if got := digest(t, n, f); got != want {
		t.Fatal("keyed resource order affected identity")
	}
	for name, mutate := range map[string]func(*spec.Node, []spec.Forward){
		"routes":              func(n *spec.Node, _ []spec.Forward) { slices.Reverse(n.Routes) },
		"DNS preference":      func(n *spec.Node, _ []spec.Forward) { slices.Reverse(n.DNS) },
		"failover candidates": func(_ *spec.Node, f []spec.Forward) { slices.Reverse(f[0].Targets) },
		"primary next hop": func(_ *spec.Node, f []spec.Forward) {
			f[0].Target, f[0].Targets[0].Target = f[0].Targets[0].Target, f[0].Target
		},
	} {
		t.Run(name, func(t *testing.T) {
			n, f := fixture()
			baseline := digest(t, n, f)
			mutate(&n, f)
			if digest(t, n, f) == baseline {
				t.Fatal("meaningful order change was lost")
			}
		})
	}
}

func TestOnlyDocumentedDefaultsAreNormalized(t *testing.T) {
	n := spec.Node{Inbounds: []spec.Inbound{{Tag: "in", Port: 443}}}
	f := []spec.Forward{{Tag: "f", Port: 80, Target: "example.com:443", Targets: []spec.ForwardTarget{{Target: "backup.example:443"}}}}
	want := digest(t, n, f)
	n.Mode = spec.NodeFull
	n.Inbounds[0].Transport = &spec.Transport{Type: "tcp"}
	n.Inbounds[0].Fallbacks = []spec.Fallback{}
	n.Routes = []spec.RouteRule{}
	n.DNS = []string{}
	n.Outbounds = []spec.Outbound{}
	n.Overrides = map[string]json.RawMessage{"xray": json.RawMessage(" { } "), "singbox": json.RawMessage("null"), "hysteria": nil}
	f[0].Backend = "relay"
	f[0].Balance = "failover"
	f[0].Weight = 1
	f[0].Targets[0].Weight = 1
	if got := digest(t, n, f); got != want {
		t.Fatal("equivalent defaults diverged", got, want)
	}
	n.Forwards = []spec.Forward{{Tag: "ignored redundant slot", Port: 9999}}
	if got := digest(t, n, f); got != want {
		t.Fatal("authoritative forwards argument did not replace Node.Forwards")
	}
}

func TestAuthorizationAndCredentialRotationDoNotChangeStructure(t *testing.T) {
	n, f := fixture()
	n.Inbounds[0].SSH = &spec.SSHServer{PrivateKey: "before", PublicKey: "before"}
	n.Inbounds[0].TLS.CertPath = "/old/cert"
	n.Inbounds[0].TLS.KeyPath = "/old/key"
	n.Outbounds[0].Remote.SSH = &spec.SSHClient{PrivateKey: "before", HostKey: "before"}
	n.Outbounds = append(n.Outbounds, spec.Outbound{Tag: "warp", WARP: &spec.WARP{PrivateKey: "before", PeerPublicKey: "before", Reserved: []int{1, 2, 3}, License: "before", Endpoint: "warp.example:2408"}})
	st := agentproto.State{Node: n, Forwards: f}
	want := digest(t, st.Node, st.Forwards)
	st.Revision = "new complete state"
	st.ConfigRevision = "other"
	st.ConfigDelivery = &agentproto.ConfigDelivery{ID: "new", Session: "new"}
	st.Users = []spec.User{{UUID: "new-user", Password: "new-secret", SpeedLimitMbps: 10, QuotaBytes: 1234}}
	st.Jobs = []agentproto.Job{{ID: "new-job", Kind: "diagnostic"}}
	st.Probe = &spec.Probe{Enabled: true, BeatSeconds: 20}
	st.PullSeconds = 12
	st.PushSeconds = 25
	st.Node.ID = "other-node"
	st.Node.ModeRevision = 44
	st.Node.UserSpeedLimitMbps = 88
	st.Node.ServiceControl = &spec.ServiceControl{Revision: "new-control", Mode: "pause", Offline: &spec.OfflineServiceControl{PolicyID: "new-policy", QuotaBytes: 12345}}
	st.Node.ACME = &spec.ACME{Email: "new@example.com", CloudflareToken: "new-token"}
	st.Node.Certificates = []spec.Certificate{{Domain: "new.example", CertPEM: "new-cert", KeyPEM: "new-key"}}
	i := &st.Node.Inbounds[0]
	i.ScopedUsers = true
	i.Users = []spec.User{{ID: 42, UUID: "new-UUID", WireGuardPeers: []spec.WireGuardPeer{{UUID: "device", Address: "10.67.0.1/32"}}, WireGuardLegacyDisabled: true}}
	i.ServerKey = "new-server"
	i.ObfsPassword = "new-obfs"
	i.WGPrivateKey = "new-WG"
	i.WGPublicKey = "new-WG-public"
	i.SnellPSK = "new-snell"
	i.SSH.PrivateKey = "new-SSH"
	i.SSH.PublicKey = "new-SSH-public"
	i.TLS.CertPath = "/new/cert"
	i.TLS.KeyPath = "/new/key"
	i.TLS.Reality.PrivateKey = "new-Reality"
	i.TLS.Reality.PublicKey = "new-Reality-public"
	i.TLS.Reality.ShortIDs = []string{"new-short"}
	r := st.Node.Outbounds[0].Remote
	r.UUID = "new-remote"
	r.Password = "new-password"
	r.Username = "new-name"
	r.SSH.HostKey = "new-host"
	r.SSH.PrivateKey = "new-private"
	w := st.Node.Outbounds[2].WARP
	w.PrivateKey = "new-WARP"
	w.PeerPublicKey = "new-peer"
	w.Reserved = []int{4, 5, 6}
	w.License = "new-license"
	st.Node.WireGuardLinks[0].PrivateKey = "new-link"
	st.Node.WireGuardLinks[0].PeerKey = "new-peer"
	st.Node.ReverseClients[0].UUID = "new-reverse"
	if got := digest(t, st.Node, st.Forwards); got != want {
		t.Fatal("dynamic material changed structural identity", got, want)
	}
	p, err := project(st.Node, st.Forwards)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(p)
	for _, secret := range []string{"new-secret", "new-user", "new-token", "new-key", "new-server", "new-obfs", "new-WG", "new-snell", "new-SSH", "new-Reality", "new-remote", "new-password", "new-name", "new-host", "new-private", "new-WARP", "new-peer", "new-license", "new-link", "new-reverse", "10.67.0.1"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("material in projection: %s", secret)
		}
	}
}

func TestOpaqueAndAmbiguousSettingsCannotClaimStructuralIdentity(t *testing.T) {
	const secret = "secret-do-not-return"
	for _, n := range []spec.Node{
		{Overrides: map[string]json.RawMessage{"xray": json.RawMessage(`{"password":"` + secret + `"}`)}},
		{Overrides: map[string]json.RawMessage{"singbox": json.RawMessage(secret)}},
		{Overrides: map[string]json.RawMessage{"unknown": json.RawMessage(`[]`)}},
		{Outbounds: []spec.Outbound{{Tag: secret, Settings: map[string]any{"password": secret}}}},
		{Outbounds: []spec.Outbound{{Remote: &spec.Remote{}, WARP: &spec.WARP{}}}},
		{Outbounds: []spec.Outbound{{WARP: &spec.WARP{}, Balancer: &spec.Balancer{}}}},
		{Outbounds: []spec.Outbound{{Remote: &spec.Remote{}, Balancer: &spec.Balancer{}}}},
	} {
		got, err := Digest(n, nil)
		if got != "" || !errors.Is(err, ErrUnsupported) || strings.Contains(err.Error(), secret) {
			t.Fatalf("unsafe unsupported result: %s %v", got, err)
		}
	}
	n := spec.Node{Outbounds: []spec.Outbound{{Tag: "direct", Protocol: "direct"}}}
	want := digest(t, n, nil)
	n.Outbounds[0].Settings = map[string]any{}
	if digest(t, n, nil) != want {
		t.Fatal("empty native settings changed identity")
	}
}

func TestProjectionIsIndependentOfInputAfterCreation(t *testing.T) {
	n, f := fixture()
	p, err := project(n, f)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(p)
	n.Inbounds[0].TLS.Reality.HandshakeServer = "changed"
	n.Routes[0].Match[0] = "changed"
	n.Outbounds[0].Remote.Host = "changed"
	f[0].Targets[0].Target = "changed"
	n.DNS[0] = "changed"
	after, _ := json.Marshal(p)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("projection retains mutable caller fields")
	}
}

func TestCredentialBearingEndpointURLsAreUnsupported(t *testing.T) {
	const secret = "do-not-echo-this"
	for _, endpoint := range []string{
		"https://user:" + secret + "@example.com/",
		"https://example.com/?key=" + secret,
		"https://example.com/#" + secret,
		"https://example.com/" + secret,
		"https://example.com/%64ns-query",
		"https://example.com/?",
	} {
		for _, n := range []spec.Node{{DNS: []string{endpoint}}, {Decoy: &spec.Decoy{Upstream: endpoint}}} {
			got, err := Digest(n, nil)
			if got != "" || !errors.Is(err, ErrUnsupported) || strings.Contains(err.Error(), secret) {
				t.Fatalf("URL material not safely classified: %s %v", got, err)
			}
		}
	}
	for _, n := range []spec.Node{
		{DNS: []string{"1.1.1.1", "tls://one.one.one.one", "https://dns.example/dns-query", "https://dns.example/"}},
		{Decoy: &spec.Decoy{Upstream: "http://127.0.0.1:8080/"}},
	} {
		digest(t, n, nil)
	}
}
