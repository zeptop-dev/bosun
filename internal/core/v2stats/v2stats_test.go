package v2stats

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	"gitlab.com/boyang-hu/bosun/pkg/spec"
)

func encodeStat(name string, value int64) []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendString(b, name)
	b = protowire.AppendTag(b, 2, protowire.VarintType)
	b = protowire.AppendVarint(b, uint64(value))
	return b
}

func TestDecodeUsers(t *testing.T) {
	var resp []byte
	for _, s := range []struct {
		n string
		v int64
	}{
		{"user>>>u1>>>traffic>>>uplink", 10},
		{"user>>>u1>>>traffic>>>downlink", 20},
		{"user>>>u2>>>traffic>>>uplink", 5},
		{"inbound>>>in>>>traffic>>>uplink", 999},
	} {
		resp = protowire.AppendTag(resp, 1, protowire.BytesType)
		resp = protowire.AppendBytes(resp, encodeStat(s.n, s.v))
	}
	got, err := DecodeUsers(resp)
	if err != nil {
		t.Fatal(err)
	}
	if got["u1"] != (spec.Traffic{Up: 10, Down: 20}) || got["u2"] != (spec.Traffic{Up: 5}) {
		t.Fatalf("got %+v", got)
	}
	if _, has := got["in"]; has {
		t.Fatal("inbound counters must be filtered out")
	}
}
