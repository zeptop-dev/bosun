package forward

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

type pathHealthClock struct {
	epoch    string
	sequence atomic.Uint64
	slots    chan struct{}
}

func newPathHealthClock() *pathHealthClock {
	return &pathHealthClock{epoch: rand.Text(), slots: make(chan struct{}, 8)}
}

type pathHealthState struct {
	mu                  sync.Mutex
	clock               *pathHealthClock
	samples             []agentproto.PathHealthSample
	successes, failures []int
}

func (r *rule) initPathHealth(clock *pathHealthClock) {
	if r.spec.PathHealth == nil {
		return
	}
	if clock == nil {
		clock = newPathHealthClock()
	}
	n := len(r.spec.PathHealth.Candidates)
	r.pathHealth = &pathHealthState{clock: clock, samples: make([]agentproto.PathHealthSample, n), successes: make([]int, n), failures: make([]int, n)}
}

func (r *rule) startPathHealth(ctx context.Context) {
	if r.pathHealth == nil {
		return
	}
	r.wg.Add(1)
	go r.pathHealthLoop(ctx)
}

func (r *rule) pathHealthLoop(ctx context.Context) {
	defer r.wg.Done()
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		r.probePathHealth(ctx)
		if r.spec.PathHealth.Protocol == spec.PathHealthUnsupported {
			return
		}
		timer.Reset(time.Duration(r.spec.PathHealth.IntervalSeconds) * time.Second)
	}
}

func (r *rule) probePathHealth(ctx context.Context) {
	var wg sync.WaitGroup
	for i, c := range r.spec.PathHealth.Candidates {
		wg.Add(1)
		go func(i int, c spec.PathHealthCandidate) {
			defer wg.Done()
			// Waiting for the node budget is cancellable and cannot renew an old sample.
			select {
			case r.pathHealth.clock.slots <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-r.pathHealth.clock.slots }()
			started := time.Now()
			result, code := r.pathHandshake(ctx, c.Target)
			if ctx.Err() != nil {
				return
			}
			r.recordPathHealth(i, result, code, time.Since(started), time.Now().UTC())
		}(i, c)
	}
	wg.Wait()
}

// This opens the same next-hop business address used by the client relay, not
// a shadow listener. The fixed pre-authentication exchange cannot request an
// arbitrary destination, authenticate a customer or create a proxy session.
func (r *rule) pathHandshake(parent context.Context, target string) (string, string) {
	p := r.spec.PathHealth
	if p.Protocol == spec.PathHealthUnsupported {
		return "unsupported", "unsupported"
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(p.TimeoutSeconds)*time.Second)
	defer cancel()
	d := net.Dialer{}
	if r.controlled {
		d.Control = serviceSocketControl
	}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return "failure", "dial_failed"
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return "failure", "deadline_failed"
	}
	switch p.Protocol {
	case spec.PathHealthTLS:
		client := tls.Client(conn, &tls.Config{ServerName: p.ServerName, NextProtos: append([]string(nil), p.ALPN...), MinVersion: tls.VersionTLS12})
		if err := client.HandshakeContext(ctx); err != nil {
			return "failure", "tls_handshake_failed"
		}
		if len(client.ConnectionState().VerifiedChains) == 0 {
			return "failure", "tls_identity_unverified"
		}
		return "success", ""
	case spec.PathHealthHTTP:
		if _, err = io.WriteString(conn, "OPTIONS * HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"); err != nil {
			return "failure", "write_failed"
		}
		response, err := http.ReadResponse(bufio.NewReader(io.LimitReader(conn, 8192)), nil)
		if err != nil || response.StatusCode != http.StatusProxyAuthRequired || response.Header.Get("Proxy-Authenticate") == "" {
			return "failure", "http_auth_challenge_missing"
		}
		return "success", ""
	case spec.PathHealthSOCKS5:
		if _, err = conn.Write([]byte{5, 1, 2}); err != nil {
			return "failure", "write_failed"
		}
		var answer [2]byte
		if _, err = io.ReadFull(conn, answer[:]); err != nil || answer != [2]byte{5, 2} {
			return "failure", "socks_auth_method_missing"
		}
		return "success", ""
	}
	return "unsupported", "unsupported"
}

func (r *rule) recordPathHealth(index int, result, code string, rtt time.Duration, at time.Time) {
	p, s := r.spec.PathHealth, r.pathHealth
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.samples[index]
	health := old.Health
	if health == "" || at.Sub(old.ObservedAt) > p.Freshness() {
		health = "unknown"
		s.successes[index] = 0
		s.failures[index] = 0
	}
	switch result {
	case "success":
		s.successes[index]++
		s.failures[index] = 0
		if s.successes[index] >= p.RecoveryThreshold {
			health = "up"
		}
	case "failure":
		s.failures[index]++
		s.successes[index] = 0
		if s.failures[index] >= p.FailureThreshold {
			health = "down"
		}
	default:
		health = "unsupported"
	}
	c := p.Candidates[index]
	s.samples[index] = agentproto.PathHealthSample{Tag: r.spec.Tag, RouteID: p.RouteID, ScopeID: p.ScopeID, CandidateID: c.ID, ConfigDigest: p.Digest(), CandidateDigest: c.Digest, Epoch: s.clock.epoch, Sequence: s.clock.sequence.Add(1), ObservedAt: at, Health: health, Result: result, RTTMillis: rtt.Milliseconds(), Error: code}
}

func (r *rule) pathCandidates(at time.Time) []*hop {
	if r.pathHealth == nil {
		return nil
	}
	s := r.pathHealth
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*hop
	for i, h := range r.hops {
		v := s.samples[i]
		if v.Health == "up" && !v.ObservedAt.IsZero() && !at.Before(v.ObservedAt) && at.Sub(v.ObservedAt) <= r.spec.PathHealth.Freshness() {
			out = append(out, h)
		}
	}
	return out
}

func (m *Manager) PathHealthSnapshot() []agentproto.PathHealthSample {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []agentproto.PathHealthSample{}
	for _, r := range m.rules {
		if r.pathHealth == nil {
			continue
		}
		r.pathHealth.mu.Lock()
		for _, s := range r.pathHealth.samples {
			if s.Sequence > 0 {
				out = append(out, s)
			}
		}
		r.pathHealth.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tag != out[j].Tag {
			return out[i].Tag < out[j].Tag
		}
		return out[i].CandidateID < out[j].CandidateID
	})
	return out
}
