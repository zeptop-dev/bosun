package forward

import (
	"context"
	"net"
	"sync"
	"time"
)

// udpSession is one client address mapped to one socket towards the target.
type udpSession struct {
	conn net.Conn
	last time.Time
}

// serveUDP relays datagrams with a per-client NAT table.
func (r *rule) serveUDP(ctx context.Context, pc net.PacketConn) {
	defer r.wg.Done()
	var mu sync.Mutex
	sessions := map[string]*udpSession{}

	// Reaper for idle sessions.
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		t := time.NewTicker(udpIdle / 2)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				mu.Lock()
				for k, s := range sessions {
					s.conn.Close()
					delete(sessions, k)
				}
				mu.Unlock()
				return
			case now := <-t.C:
				mu.Lock()
				for k, s := range sessions {
					if now.Sub(s.last) > udpIdle {
						s.conn.Close()
						delete(sessions, k)
						r.active.Add(-1)
					}
				}
				mu.Unlock()
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		k := from.String()
		mu.Lock()
		s, ok := sessions[k]
		if !ok {
			t, err := net.DialTimeout("udp", r.spec.Target, dialTimeout)
			if err != nil {
				mu.Unlock()
				r.log.Debug("udp dial target failed", "target", r.spec.Target, "err", err)
				continue
			}
			s = &udpSession{conn: t, last: time.Now()}
			sessions[k] = s
			r.total.Add(1)
			r.active.Add(1)
			r.wg.Add(1)
			go r.udpReturn(ctx, pc, from, s, func() {
				mu.Lock()
				if cur, still := sessions[k]; still && cur == s {
					delete(sessions, k)
					r.active.Add(-1)
				}
				mu.Unlock()
			})
		}
		s.last = time.Now()
		mu.Unlock()
		if _, err := s.conn.Write(buf[:n]); err == nil {
			r.bytesIn.Add(int64(n))
		}
	}
}

// udpReturn copies target replies back to the client until the session dies.
func (r *rule) udpReturn(ctx context.Context, pc net.PacketConn, client net.Addr, s *udpSession, done func()) {
	defer r.wg.Done()
	defer done()
	buf := make([]byte, 65535)
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(udpIdle))
		n, err := s.conn.Read(buf)
		if err != nil {
			return
		}
		if _, err := pc.WriteTo(buf[:n], client); err != nil {
			return
		}
		r.bytesOut.Add(int64(n))
		if ctx.Err() != nil {
			return
		}
	}
}
