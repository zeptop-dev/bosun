package forward

import (
	"context"
	"net"
	"sync"
	"time"
)

// udpSession pins one client address to one hop until both directions are idle
// or the socket fails. A successful UDP write is activity, not a health check.
type udpSession struct {
	conn   net.Conn
	hop    *hop
	mu     sync.Mutex
	last   time.Time
	closed bool
}

func (s *udpSession) activity(idle time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.last = time.Now()
		_ = s.conn.SetReadDeadline(s.last.Add(idle))
	}
}

func (s *udpSession) close() {
	s.mu.Lock()
	closed := s.closed
	s.closed = true
	s.mu.Unlock()
	if !closed {
		_ = s.conn.Close()
	}
}

// expire serializes an idle decision with activity. A timeout from an earlier
// deadline must not retire a session whose other direction is still active.
func (s *udpSession) expire(at time.Time, idle time.Duration) bool {
	s.mu.Lock()
	if !s.closed && at.Sub(s.last) < idle {
		_ = s.conn.SetReadDeadline(s.last.Add(idle))
		s.mu.Unlock()
		return false
	}
	closed := s.closed
	s.closed = true
	s.mu.Unlock()
	if !closed {
		_ = s.conn.Close()
	}
	return true
}

// dialUDP opens a socket towards the first candidate hop that can be dialed
// (for UDP that only fails on resolution or routing).
func (r *rule) dialUDP() (net.Conn, *hop) {
	return r.dialUDPContext(context.Background())
}

func (r *rule) dialUDPContext(ctx context.Context) (net.Conn, *hop) {
	for _, h := range r.candidatesFor("udp") {
		d := net.Dialer{Timeout: dialTimeout}
		if r.controlled {
			d.Control = serviceSocketControl
		}
		t, err := d.DialContext(ctx, "udp", h.target)
		if err == nil {
			return t, h
		}
		if ctx.Err() != nil {
			break
		}
		r.log.Debug("udp dial target failed", "target", h.target, "err", err)
	}
	return nil, nil
}

// serveUDP relays datagrams with a per-client NAT table.
func (r *rule) serveUDP(ctx context.Context, pc net.PacketConn) {
	r.serveUDPIdle(ctx, pc, udpIdle)
}

func (r *rule) serveUDPIdle(ctx context.Context, pc net.PacketConn, idle time.Duration) {
	defer r.wg.Done()
	var mu sync.Mutex
	sessions := map[string]*udpSession{}
	remove := func(k string, s *udpSession) {
		s.close()
		mu.Lock()
		defer mu.Unlock()
		if sessions[k] == s {
			delete(sessions, k)
			r.active.Add(-1)
			s.hop.active.Add(-1)
		}
	}
	closeSessions := func() {
		mu.Lock()
		defer mu.Unlock()
		// Readers own removal and counters; close only wakes them. Waiting for
		// r.wg therefore also waits for every session to be retired exactly once.
		for _, s := range sessions {
			s.close()
		}
	}
	// Closing the listener alone cannot interrupt an upstream Write. Cancel
	// closes those sockets too, without waiting for their write deadline.
	cancelDone := make(chan struct{})
	stopCancel := context.AfterFunc(ctx, func() { closeSessions(); close(cancelDone) })
	defer func() {
		if !stopCancel() {
			<-cancelDone
		}
		closeSessions()
	}()

	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() && ctx.Err() == nil {
				continue
			}
			return
		}
		if ctx.Err() != nil {
			return
		}
		k := from.String()
		mu.Lock()
		s := sessions[k]
		mu.Unlock()
		if s == nil {
			// Only this reader creates sessions. Do not hold the map lock over
			// DNS/dial: old readers must remain able to retire their sockets.
			t, h := r.dialUDPContext(ctx)
			if t == nil {
				continue
			}
			if ctx.Err() != nil {
				_ = t.Close()
				return
			}
			s = &udpSession{conn: t, hop: h}
			s.activity(idle)
			mu.Lock()
			if ctx.Err() != nil {
				mu.Unlock()
				s.close()
				return
			}
			sessions[k] = s
			mu.Unlock()
			r.total.Add(1)
			r.active.Add(1)
			h.total.Add(1)
			h.active.Add(1)
			r.wg.Add(1)
			go r.udpReturn(ctx, pc, from, s, idle, func() { remove(k, s) })
		}
		_ = s.conn.SetWriteDeadline(time.Now().Add(dialTimeout))
		if _, err := s.conn.Write(buf[:n]); err == nil {
			s.activity(idle)
			r.bytesIn.Add(int64(n))
		} else {
			remove(k, s)
		}
	}
}

// udpReturn copies target replies back to the client until the session dies.
func (r *rule) udpReturn(ctx context.Context, pc net.PacketConn, client net.Addr, s *udpSession, idle time.Duration, done func()) {
	defer r.wg.Done()
	defer done()
	defer s.close()
	buf := make([]byte, 65535)
	for {
		n, err := s.conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && ctx.Err() == nil && !s.expire(time.Now(), idle) {
				continue
			}
			return
		}
		if _, err := pc.WriteTo(buf[:n], client); err != nil {
			return
		}
		s.activity(idle)
		r.bytesOut.Add(int64(n))
		if ctx.Err() != nil {
			return
		}
	}
}
