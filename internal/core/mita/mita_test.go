package mita

import (
	"encoding/json"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	"gitlab.com/boyang-hu/bosun/pkg/spec"
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

func TestStatsDeltas(t *testing.T) {
	c := &Core{last: map[string]spec.Traffic{"u": {Up: 100, Down: 100}}}
	// Simulate the delta logic used by Stats without a live RPC.
	cur := map[string]spec.Traffic{"u": {Up: 150, Down: 90}} // Down went backwards: restart
	out := map[string]spec.Traffic{}
	for name, now := range cur {
		prev := c.last[name]
		d := spec.Traffic{Up: now.Up - prev.Up, Down: now.Down - prev.Down}
		if d.Down < 0 {
			d.Down = now.Down
		}
		out[name] = d
	}
	if out["u"] != (spec.Traffic{Up: 50, Down: 90}) {
		t.Fatalf("delta: %+v", out)
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
