// Package logring keeps the most recent log records in memory so the local
// UI can show them without shelling out to journalctl.
package logring

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Entry is one captured record.
type Entry struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"msg"`
	Attrs   string    `json:"attrs,omitempty"`
}

// Ring stores the last N entries and forwards every record to the next
// handler.
type Ring struct {
	next slog.Handler
	mu   sync.Mutex
	buf  []Entry
	max  int
	// attrs and group are carried for WithAttrs/WithGroup derived handlers.
	attrs []slog.Attr
}

// New wraps next, keeping max entries.
func New(next slog.Handler, max int) *Ring {
	return &Ring{next: next, max: max}
}

// Enabled implements slog.Handler.
func (r *Ring) Enabled(ctx context.Context, l slog.Level) bool { return r.next.Enabled(ctx, l) }

// Handle implements slog.Handler.
func (r *Ring) Handle(ctx context.Context, rec slog.Record) error {
	var b strings.Builder
	for _, a := range r.attrs {
		b.WriteString(a.String())
		b.WriteByte(' ')
	}
	rec.Attrs(func(a slog.Attr) bool {
		b.WriteString(a.String())
		b.WriteByte(' ')
		return true
	})
	e := Entry{Time: rec.Time, Level: rec.Level.String(), Message: rec.Message, Attrs: strings.TrimSpace(b.String())}
	r.mu.Lock()
	r.buf = append(r.buf, e)
	if len(r.buf) > r.max {
		r.buf = r.buf[len(r.buf)-r.max:]
	}
	r.mu.Unlock()
	return r.next.Handle(ctx, rec)
}

// WithAttrs implements slog.Handler; derived handlers share the buffer.
func (r *Ring) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &child{Ring: r, next: r.next.WithAttrs(attrs), attrs: append(append([]slog.Attr(nil), r.attrs...), attrs...)}
}

// WithGroup implements slog.Handler.
func (r *Ring) WithGroup(name string) slog.Handler {
	return &child{Ring: r, next: r.next.WithGroup(name), attrs: r.attrs}
}

// child is a derived handler writing into the parent's buffer.
type child struct {
	*Ring
	next  slog.Handler
	attrs []slog.Attr
}

func (c *child) Enabled(ctx context.Context, l slog.Level) bool { return c.next.Enabled(ctx, l) }
func (c *child) Handle(ctx context.Context, rec slog.Record) error {
	var b strings.Builder
	for _, a := range c.attrs {
		b.WriteString(a.String())
		b.WriteByte(' ')
	}
	rec.Attrs(func(a slog.Attr) bool {
		b.WriteString(a.String())
		b.WriteByte(' ')
		return true
	})
	e := Entry{Time: rec.Time, Level: rec.Level.String(), Message: rec.Message, Attrs: strings.TrimSpace(b.String())}
	c.Ring.mu.Lock()
	c.Ring.buf = append(c.Ring.buf, e)
	if len(c.Ring.buf) > c.Ring.max {
		c.Ring.buf = c.Ring.buf[len(c.Ring.buf)-c.Ring.max:]
	}
	c.Ring.mu.Unlock()
	return c.next.Handle(ctx, rec)
}
func (c *child) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &child{Ring: c.Ring, next: c.next.WithAttrs(attrs), attrs: append(append([]slog.Attr(nil), c.attrs...), attrs...)}
}
func (c *child) WithGroup(name string) slog.Handler {
	return &child{Ring: c.Ring, next: c.next.WithGroup(name), attrs: c.attrs}
}

// Last returns up to n most recent entries, oldest first.
func (r *Ring) Last(n int) []Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n <= 0 || n > len(r.buf) {
		n = len(r.buf)
	}
	return append([]Entry(nil), r.buf[len(r.buf)-n:]...)
}
