package mita

import (
	"encoding/json"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestRender(t *testing.T) {
	inbounds := []spec.Inbound{
		{Tag: "a", Protocol: spec.Mieru, Port: 2012, MieruTransport: "tcp"},
		{Tag: "b", Protocol: spec.Mieru, Port: 2013, MieruTransport: "UDP", TrafficPattern: `{"unlockAll":true}`},
	}
	users := []spec.User{{Name: "u1", Password: "p1"}}
	b, err := render(inbounds, users, "info")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	pb := cfg["portBindings"].([]any)
	if len(pb) != 2 || pb[0].(map[string]any)["protocol"] != "TCP" || pb[1].(map[string]any)["protocol"] != "UDP" {
		t.Fatalf("portBindings: %v", pb)
	}
	if cfg["loggingLevel"] != "INFO" {
		t.Fatalf("loggingLevel: %v", cfg["loggingLevel"])
	}
	if cfg["trafficPattern"].(map[string]any)["unlockAll"] != true {
		t.Fatalf("trafficPattern: %v", cfg["trafficPattern"])
	}
	if cfg["users"].([]any)[0].(map[string]any)["password"] != "p1" {
		t.Fatalf("users: %v", cfg["users"])
	}

	// BOTH: TCP at the port, UDP at port+1; mtu lands at the top level.
	b, err = render([]spec.Inbound{{Tag: "c", Protocol: spec.Mieru, Port: 17701, MieruTransport: "BOTH", MieruMTU: 1400}}, users, "info")
	if err != nil {
		t.Fatal(err)
	}
	cfg = map[string]any{}
	_ = json.Unmarshal(b, &cfg)
	pb = cfg["portBindings"].([]any)
	if len(pb) != 2 || pb[0].(map[string]any)["port"] != float64(17701) || pb[0].(map[string]any)["protocol"] != "TCP" || pb[1].(map[string]any)["port"] != float64(17702) || pb[1].(map[string]any)["protocol"] != "UDP" || cfg["mtu"] != float64(1400) {
		t.Fatalf("BOTH/mtu: %v", cfg)
	}
	if _, err := render([]spec.Inbound{{Tag: "c", Protocol: spec.Mieru, Port: 65535, MieruTransport: "BOTH"}}, users, ""); err == nil {
		t.Fatal("BOTH at 65535 accepted")
	}
	if _, err := render([]spec.Inbound{{Tag: "c", Protocol: spec.Mieru, Port: 1, MieruMTU: 900}}, users, ""); err == nil {
		t.Fatal("bad mtu accepted")
	}
	if bindingsKey([]spec.Inbound{{Port: 1, MieruTransport: "TCP", MieruMTU: 1400}}) == bindingsKey([]spec.Inbound{{Port: 1, MieruTransport: "TCP"}}) {
		t.Fatal("mtu change must cycle the proxy")
	}

	if _, err := render([]spec.Inbound{{Tag: "x", Protocol: spec.VLESS, Port: 1}}, nil, ""); err == nil {
		t.Fatal("expected error for non-mieru inbound")
	}
	if _, err := render([]spec.Inbound{{Tag: "x", Protocol: spec.Mieru, Port: 1, MieruTransport: "QUIC"}}, nil, ""); err == nil {
		t.Fatal("expected error for bad transport")
	}
	if bindingsKey(inbounds) == bindingsKey(inbounds[:1]) {
		t.Fatal("bindings key must change with bindings")
	}
}

func msg(fields ...[]byte) []byte {
	var out []byte
	for _, f := range fields {
		out = append(out, f...)
	}
	return out
}

func strField(num protowire.Number, s string) []byte {
	b := protowire.AppendTag(nil, num, protowire.BytesType)
	return protowire.AppendString(b, s)
}

func varField(num protowire.Number, v uint64) []byte {
	b := protowire.AppendTag(nil, num, protowire.VarintType)
	return protowire.AppendVarint(b, v)
}

func bytesField(num protowire.Number, inner []byte) []byte {
	b := protowire.AppendTag(nil, num, protowire.BytesType)
	return protowire.AppendBytes(b, inner)
}

func TestDecodeUserCounters(t *testing.T) {
	item := func(name string, up, down int64) []byte {
		return bytesField(1, msg(
			bytesField(1, strField(1, name)), // User{name}
			bytesField(2, msg(strField(1, "UploadBytes"), varField(2, 2), varField(3, uint64(up)))),
			bytesField(2, msg(strField(1, "DownloadBytes"), varField(2, 2), varField(3, uint64(down)))),
			bytesField(2, msg(strField(1, "Other"), varField(3, 12345))),
		))
	}
	resp := msg(item("alice", 100, 200), item("bob", 0, 7))
	got, err := decodeUserCounters(resp)
	if err != nil {
		t.Fatal(err)
	}
	if got["alice"] != (spec.Traffic{Up: 100, Down: 200}) || got["bob"] != (spec.Traffic{Down: 7}) {
		t.Fatalf("got %+v", got)
	}
}

func TestRenderPerInbound(t *testing.T) {
	c := &Core{opt: Options{LogLevel: "INFO"}}
	users := []spec.User{{Name: "a", Password: "a"}, {Name: "b", Password: "b"}}
	b, err := c.Render(nil, []spec.Inbound{
		{Tag: "shared", Protocol: spec.Mieru, Port: 1000},
		{Tag: "vip", Protocol: spec.Mieru, Port: 1001, ScopedUsers: true, Users: users[:1]},
	}, users)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Files) != 2 || b.Meta["shared"] == "" || b.Meta["vip"] == "" {
		t.Fatalf("bundle: %+v", b)
	}
	var shared, vip map[string]any
	_ = json.Unmarshal(b.Files["shared/server_config.json"], &shared)
	_ = json.Unmarshal(b.Files["vip/server_config.json"], &vip)
	if len(shared["users"].([]any)) != 2 || len(vip["users"].([]any)) != 1 {
		t.Fatalf("users: shared=%v vip=%v", shared["users"], vip["users"])
	}
}

func TestSocketPath(t *testing.T) {
	if p := socketPath("/var/lib/bosun/mita"); p != "/var/lib/bosun/mita/mita.sock" {
		t.Fatalf("short: %s", p)
	}
	long := "/" + string(make([]byte, 120))
	if p := socketPath(long); len(p) > maxSocketPath {
		t.Fatalf("fallback too long: %s", p)
	}
}
