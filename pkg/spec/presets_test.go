package spec

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPresetStripsSecretsAndPreservesScope(t *testing.T) {
	ib := Inbound{Tag: "source", Protocol: VLESS, Port: 443, TLS: &TLS{Mode: TLSReality, Reality: &Reality{HandshakeServer: "example.com", HandshakePort: 443}}, ScopedUsers: true, Users: []User{{ID: 99, Password: "secret"}}}
	FillInboundSecrets(&ib)
	key := ib.TLS.Reality.PrivateKey
	raw, _ := json.Marshal(ib)
	p := ConfigPreset{Name: "reality", Kind: "inbound", Payload: raw}
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{key, "secret", "private_key", "users", "source"} {
		if strings.Contains(string(p.Payload), s) {
			t.Fatalf("preset retained %s", s)
		}
	}
	if ib.TLS.Reality.PrivateKey != key {
		t.Fatal("capture mutated source")
	}
	cur := Inbound{Tag: "target", Protocol: VLESS, Port: 8443, Listen: "127.0.0.1", ScopedUsers: true, Users: []User{{ID: 7}}}
	current, _ := json.Marshal(cur)
	v, err := p.Preview(current)
	if err != nil {
		t.Fatal(err)
	}
	var next Inbound
	_ = json.Unmarshal(v.Draft, &next)
	if next.Tag != "target" || next.Port != 8443 || next.Listen != "127.0.0.1" || !next.ScopedUsers || len(next.Users) != 1 || next.Users[0].ID != 7 {
		t.Fatalf("identity or scope changed: %+v", next)
	}
	if next.TLS.Reality.PrivateKey == "" || next.TLS.Reality.PrivateKey == key {
		t.Fatal("keys were copied")
	}
	if err := next.Validate(); err != nil {
		t.Fatal(err)
	}
	again, err := p.Preview(current)
	if err != nil {
		t.Fatal(err)
	}
	if string(again.Draft) == string(v.Draft) {
		t.Fatal("keys reused")
	}
}

func TestPresetRoutingBoundaries(t *testing.T) {
	cases := []ConfigPreset{
		{Name: "raw", Kind: "outbounds", Payload: json.RawMessage(`[{"tag":"exit","protocol":"freedom","settings":{"redirect":"127.0.0.1:22"}}]`)},
		{Name: "bad", Kind: "routes", Payload: json.RawMessage(`[{"match":["domain:example.com\n"],"action":"direct"}]`)},
		{Name: "key", Kind: "outbounds", Payload: json.RawMessage(`[{"tag":"warp","warp":{"from_node":true,"private_key":"secret"}}]`)},
	}
	for _, p := range cases {
		if p.Normalize() == nil {
			t.Fatalf("accepted %s", p.Name)
		}
	}
	p := ConfigPreset{Name: "route", Kind: "routes", Payload: json.RawMessage(`[{"match":["domain:example.com"],"action":"outbound","value":"warp"}]`)}
	if _, e := p.Preview(json.RawMessage(`{"outbounds":[],"routes":[]}`)); e == nil {
		t.Fatal("unknown target accepted")
	}
	current := json.RawMessage(`{"outbounds":[{"tag":"warp","warp":{"from_node":true}}],"routes":[{"match":["domain:old.example.com"],"action":"block"}],"dns":["192.0.2.1"],"default_outbound":"warp"}`)
	v, e := p.Preview(current)
	if e != nil {
		t.Fatal(e)
	}
	var nr PresetRouting
	_ = json.Unmarshal(v.Draft, &nr)
	if len(nr.Routes) != 2 || nr.Routes[0].Action != "block" || nr.DefaultOutbound != "warp" || len(nr.DNS) != 1 {
		t.Fatal("routing replaced")
	}
	if e := ValidateRoutingReferences([]Outbound{{Tag: "a", Balancer: &Balancer{Members: []string{"b"}}}, {Tag: "b", ProxyTag: "a"}}, nil, ""); e == nil {
		t.Fatal("mixed graph cycle allowed")
	}
}

func TestPresetEveryCore(t *testing.T) {
	cases := []Inbound{
		{Protocol: VLESS, Core: "xray"},
		{Protocol: Shadowsocks, Core: "singbox", Cipher: "2022-blake3-aes-128-gcm"},
		{Protocol: Hysteria2, Core: "hysteria", TLS: &TLS{Mode: TLSStandard, ServerName: "example.com", AutoCert: true}, Obfs: "salamander"},
		{Protocol: Mieru, Core: "mita"},
		{Protocol: Snell, Core: "snell"},
	}
	for _, ib := range cases {
		t.Run(ib.Core, func(t *testing.T) {
			raw, _ := json.Marshal(ib)
			p := ConfigPreset{Name: ib.Core, Kind: "inbound", Payload: raw}
			if e := p.Normalize(); e != nil {
				t.Fatal(e)
			}
			if _, e := p.Preview(json.RawMessage(`{"tag":"test","port":9443}`)); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestRoutingRejectsDuplicateBalancerMembers(t *testing.T) {
	for _, members := range [][]string{{"direct", "direct"}, {"direct", "exit", "direct"}} {
		outs := []Outbound{{Tag: "exit", Protocol: "direct"}, {Tag: "pool", Balancer: &Balancer{Members: members}}}
		if err := ValidateRoutingReferences(outs, nil, "pool"); err == nil || !strings.Contains(err.Error(), "duplicate balancer member") {
			t.Fatalf("duplicate accepted: %v", err)
		}
		if err := validatePresetOutbound(outs[1]); err == nil {
			t.Fatal("preset accepted duplicate")
		}
	}
	if err := ValidateRoutingReferences([]Outbound{{Tag: "pool", Balancer: &Balancer{Members: []string{"direct"}}}}, nil, "pool"); err != nil {
		t.Fatal(err)
	}
}
