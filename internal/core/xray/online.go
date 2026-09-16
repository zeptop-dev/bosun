package xray

import (
	"context"
	"strings"
	"sync"
	"time"

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

// sample asks xray which users are connected right now and from where.
func (c *Core) sample(ctx context.Context) (map[string][]string, error) {
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
		u = onlineEmail(u)
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

// xray forgets a client address about 20 s after its last connection, so
// a report every minute would miss most short sessions. The core samples
// every pollInterval and remembers each address for onlineWindow, which is
// what the panel's device limit needs (same window as sing-box's tracker).
const (
	pollInterval = 10 * time.Second
	onlineWindow = 3 * time.Minute
)

type onlineWindowMap struct {
	mu   sync.Mutex
	seen map[string]map[string]time.Time // user -> ip -> last seen
	now  func() time.Time
}

func newOnlineWindow() *onlineWindowMap {
	return &onlineWindowMap{seen: map[string]map[string]time.Time{}, now: time.Now}
}

func (w *onlineWindowMap) add(sample map[string][]string) {
	now := w.now()
	w.mu.Lock()
	defer w.mu.Unlock()
	for user, ips := range sample {
		m := w.seen[user]
		if m == nil {
			m = map[string]time.Time{}
			w.seen[user] = m
		}
		for _, ip := range ips {
			m[ip] = now
		}
	}
}

// online returns user -> IPs seen within onlineWindow and forgets older ones.
func (w *onlineWindowMap) online() map[string][]string {
	now := w.now()
	w.mu.Lock()
	defer w.mu.Unlock()
	out := map[string][]string{}
	for user, ips := range w.seen {
		for ip, at := range ips {
			if now.Sub(at) > onlineWindow {
				delete(ips, ip)
				continue
			}
			out[user] = append(out[user], ip)
		}
		if len(ips) == 0 {
			delete(w.seen, user)
		}
	}
	return out
}

// pollOnline runs while the process is up (started by Start, ended by Stop).
func (c *Core) pollOnline(ctx context.Context) {
	t := time.NewTicker(pollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !c.Running() {
			continue
		}
		if s, err := c.sample(ctx); err == nil {
			c.online.add(s)
		}
	}
}

// Online implements core.OnlineTracker: the sampled window plus a live
// sample, so a report never misses a connection made seconds ago.
func (c *Core) Online(ctx context.Context) (map[string][]string, error) {
	s, err := c.sample(ctx)
	if err != nil {
		return nil, err
	}
	c.online.add(s)
	return c.online.online(), nil
}

// onlineEmail turns what GetAllOnlineUsers returns into the email the
// per-user counters are keyed by. Xray hands back the full counter name
// ("user>>>EMAIL>>>online"); older builds the bare email. Feeding the
// full name back into GetStatsOnlineIpList produced
// "user>>>user>>>…>>>online>>>online not found", so xray never
// contributed online addresses before this.
func onlineEmail(name string) string {
	name = strings.TrimPrefix(name, onlineCounterPrefixFn)
	return strings.TrimSuffix(name, onlineCounterSuffix)
}
