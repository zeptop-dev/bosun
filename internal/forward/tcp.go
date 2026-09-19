package forward

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
)

func (r *rule) serveTCP(ctx context.Context, ln net.Listener) {
	defer r.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			r.log.Warn("accept failed", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		r.wg.Add(1)
		go r.handleTCP(ctx, c)
	}
}

func (r *rule) handleTCP(ctx context.Context, c net.Conn) {
	defer r.wg.Done()
	defer c.Close()
	r.total.Add(1)
	r.active.Add(1)
	defer r.active.Add(-1)

	t, h := r.dialTCP(ctx)
	if t == nil {
		return
	}
	defer t.Close()
	h.total.Add(1)
	h.active.Add(1)
	defer h.active.Add(-1)
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
	}
	if tt, ok := t.(*net.TCPConn); ok {
		_ = tt.SetKeepAlive(true)
	}
	if r.spec.ProxyProtocol {
		// Tell the target who really connected (PROXY protocol v2).
		if _, err := t.Write(proxyHeaderV2(c.RemoteAddr(), c.LocalAddr())); err != nil {
			r.log.Debug("proxy protocol header failed", "target", h.target, "err", err)
			return
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(t, c) // client -> target
		r.bytesIn.Add(n)
		closeWrite(t)
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(c, t) // target -> client
		r.bytesOut.Add(n)
		closeWrite(c)
	}()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		c.Close()
		t.Close()
		<-done
	}
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
		return
	}
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
