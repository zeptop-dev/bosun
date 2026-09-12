package xray

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/zeptop-dev/bosun/internal/core/grpcraw"
)

const (
	methodAllOnlineUsers  = "/xray.app.stats.command.StatsService/GetAllOnlineUsers"
	methodOnlineIPList    = "/xray.app.stats.command.StatsService/GetStatsOnlineIpList"
	onlineCounterSuffix   = ">>>online"
	onlineCounterPrefixFn = "user>>>"
)

// onlineUsers returns names of users with live connections.
// GetAllOnlineUsersResponse { repeated string users = 1 }
func onlineUsers(ctx context.Context, conn *grpc.ClientConn) ([]string, error) {
	resp, err := grpcraw.Invoke(ctx, conn, methodAllOnlineUsers, nil)
	if err != nil {
		return nil, err
	}
	var out []string
	b := resp
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		b = b[n:]
		if num == 1 && typ == protowire.BytesType {
			s, n := protowire.ConsumeString(b)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			out = append(out, s)
			b = b[n:]
			continue
		}
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		b = b[n:]
	}
	return out, nil
}

// onlineIPs returns the IPs a user is connected from.
// GetStatsRequest { name = 1 } -> GetStatsOnlineIpListResponse { name = 1; map<string,int64> ips = 2 }
func onlineIPs(ctx context.Context, conn *grpc.ClientConn, user string) ([]string, error) {
	req := strField(1, onlineCounterPrefixFn+user+onlineCounterSuffix)
	resp, err := grpcraw.Invoke(ctx, conn, methodOnlineIPList, req)
	if err != nil {
		return nil, err
	}
	return decodeIPMap(resp)
}

func decodeIPMap(b []byte) ([]string, error) {
	var ips []string
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		b = b[n:]
		if num != 2 || typ != protowire.BytesType {
			n = protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			b = b[n:]
			continue
		}
		entry, n := protowire.ConsumeBytes(b)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		b = b[n:]
		// map entry: key = 1 (string), value = 2 (int64)
		for len(entry) > 0 {
			knum, ktyp, kn := protowire.ConsumeTag(entry)
			if kn < 0 {
				return nil, protowire.ParseError(kn)
			}
			entry = entry[kn:]
			if knum == 1 && ktyp == protowire.BytesType {
				ip, kn := protowire.ConsumeString(entry)
				if kn < 0 {
					return nil, protowire.ParseError(kn)
				}
				ips = append(ips, ip)
				entry = entry[kn:]
				continue
			}
			kn = protowire.ConsumeFieldValue(knum, ktyp, entry)
			if kn < 0 {
				return nil, protowire.ParseError(kn)
			}
			entry = entry[kn:]
		}
	}
	return ips, nil
}

// Online implements core.OnlineTracker.
func (c *Core) Online(ctx context.Context) (map[string][]string, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	rctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	users, err := onlineUsers(rctx, conn)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(users))
	for _, u := range users {
		ips, err := onlineIPs(rctx, conn, u)
		if err != nil {
			return nil, err
		}
		if len(ips) > 0 {
			out[u] = ips
		}
	}
	return out, nil
}
