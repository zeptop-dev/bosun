// Package v2stats queries the V2Ray-lineage StatsService that both sing-box
// (experimental.v2ray_api) and Xray expose, and folds the counters into
// per-user traffic.
package v2stats

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/zeptop-dev/bosun/internal/core/grpcraw"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// QueryUsers calls QueryStats(pattern, reset) on method and returns traffic
// keyed by user name. Counter names look like "user>>>NAME>>>traffic>>>uplink".
func QueryUsers(ctx context.Context, conn *grpc.ClientConn, method, pattern string, reset bool) (map[string]spec.Traffic, error) {
	// QueryStatsRequest { pattern = 1; reset = 2 }
	var req []byte
	if pattern != "" {
		req = protowire.AppendTag(req, 1, protowire.BytesType)
		req = protowire.AppendString(req, pattern)
	}
	if reset {
		req = protowire.AppendTag(req, 2, protowire.VarintType)
		req = protowire.AppendVarint(req, 1)
	}
	resp, err := grpcraw.Invoke(ctx, conn, method, req)
	if err != nil {
		return nil, err
	}
	return DecodeUsers(resp)
}

// QueryInbounds is QueryUsers for per-inbound counters
// ("inbound>>>TAG>>>traffic>>>uplink"), keyed by inbound tag.
func QueryInbounds(ctx context.Context, conn *grpc.ClientConn, method, pattern string, reset bool) (map[string]spec.Traffic, error) {
	var req []byte
	if pattern != "" {
		req = protowire.AppendTag(req, 1, protowire.BytesType)
		req = protowire.AppendString(req, pattern)
	}
	if reset {
		req = protowire.AppendTag(req, 2, protowire.VarintType)
		req = protowire.AppendVarint(req, 1)
	}
	resp, err := grpcraw.Invoke(ctx, conn, method, req)
	if err != nil {
		return nil, err
	}
	return decodeKind(resp, "inbound")
}

// DecodeUsers parses QueryStatsResponse { repeated Stat stat = 1 } where
// Stat { name = 1; value = 2 } and keeps only user traffic counters.
func DecodeUsers(b []byte) (map[string]spec.Traffic, error) { return decodeKind(b, "user") }

func decodeKind(b []byte, kind string) (map[string]spec.Traffic, error) {
	out := map[string]spec.Traffic{}
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		b = b[n:]
		if num != 1 || typ != protowire.BytesType {
			n = protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			b = b[n:]
			continue
		}
		stat, n := protowire.ConsumeBytes(b)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		b = b[n:]
		name, value, err := decodeStat(stat)
		if err != nil {
			return nil, err
		}
		parts := strings.Split(name, ">>>")
		if len(parts) != 4 || parts[0] != kind || parts[2] != "traffic" {
			continue
		}
		t := out[parts[1]]
		switch parts[3] {
		case "uplink":
			t.Up += value
		case "downlink":
			t.Down += value
		}
		out[parts[1]] = t
	}
	return out, nil
}

func decodeStat(b []byte) (name string, value int64, err error) {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return "", 0, protowire.ParseError(n)
		}
		b = b[n:]
		switch {
		case num == 1 && typ == protowire.BytesType:
			s, n := protowire.ConsumeString(b)
			if n < 0 {
				return "", 0, protowire.ParseError(n)
			}
			name, b = s, b[n:]
		case num == 2 && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(b)
			if n < 0 {
				return "", 0, protowire.ParseError(n)
			}
			value, b = int64(v), b[n:]
		default:
			n = protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return "", 0, protowire.ParseError(n)
			}
			b = b[n:]
		}
	}
	return name, value, nil
}
