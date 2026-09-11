package singbox

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"

	"gitlab.com/zeptop-group/bosun/internal/core/grpcraw"
	"gitlab.com/zeptop-group/bosun/internal/spec"
)

// The stats service is sing-box's experimental.v2rayapi.StatsService. At init
// sing-box renames it to the original V2Ray service name for compatibility, so
// that is the name on the wire. Its messages are tiny, so they are encoded by
// hand with protowire rather than pulling in generated stubs.
const queryStatsMethod = "/v2ray.core.app.stats.command.StatsService/QueryStats"

// queryUserStats returns per-user traffic keyed by user name. With reset the
// counters are zeroed server-side after being read.
func queryUserStats(ctx context.Context, conn *grpc.ClientConn, reset bool) (map[string]spec.Traffic, error) {
	// QueryStatsRequest { pattern=1; reset=2; patterns=3; regexp=4 }
	// Empty patterns returns every counter; we filter client-side.
	var req []byte
	if reset {
		req = protowire.AppendTag(req, 2, protowire.VarintType)
		req = protowire.AppendVarint(req, 1)
	}
	resp, err := grpcraw.Invoke(ctx, conn, queryStatsMethod, req)
	if err != nil {
		return nil, err
	}
	return decodeUserStats(resp)
}

// decodeUserStats parses QueryStatsResponse { repeated Stat stat = 1 } where
// Stat { name = 1; value = 2 } and keeps only "user>>>NAME>>>traffic>>>DIR".
func decodeUserStats(b []byte) (map[string]spec.Traffic, error) {
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
		if len(parts) != 4 || parts[0] != "user" || parts[2] != "traffic" {
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
