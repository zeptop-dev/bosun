package captain

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

type diagnosticRequest struct {
	started              time.Time
	nonce, session       string
	order, authorization uint64
}

// All fields are guarded by Client.mu. The worker alone owns sampler baselines.
type diagnosticState struct {
	issued, handled          uint64
	challenge, cursor, epoch string
	generation               uint64
	deadline                 time.Time
	wake                     chan struct{}
	done                     chan struct{}
	cancel                   context.CancelFunc
	inflight                 context.CancelFunc
	closed                   bool
	baselineRevision         uint64
	now                      func() time.Time // request clock; defaults to monotonic time.Now
}

func (c *Client) diagnosticsNowLocked() time.Time {
	if c.diagnostics.now != nil {
		return c.diagnostics.now()
	}
	return time.Now()
}

func diagnosticToken(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, b := range []byte(s) {
		if b < 33 || b > 126 || b == ':' {
			return false
		}
	}
	return true
}

// diagnosticsRequestLocked must be called after pairing so the authorization
// generation and process session describe the actual outgoing request.
func (c *Client) diagnosticsRequestLocked(headers map[string]string) diagnosticRequest {
	d := &c.diagnostics
	d.issued++
	r := diagnosticRequest{started: c.diagnosticsNowLocked(), nonce: rand.Text(), session: c.configSession, order: d.issued, authorization: c.authGeneration}
	headers[agentproto.DiagnosticsVersionHeader] = agentproto.DiagnosticsVersion
	headers[agentproto.DiagnosticsNonceHeader] = r.nonce
	if d.challenge != "" {
		headers[agentproto.DiagnosticsChallengeHeader] = d.challenge
	}
	if d.cursor != "" {
		headers[agentproto.DiagnosticsCursorHeader] = d.cursor
	}
	return r
}

// acceptDiagnosticsLocked returns true only when an otherwise matching command
// arrived too late. Its cursor remains unacknowledged so a fresh GET is immediate.
func (c *Client) acceptDiagnosticsLocked(r diagnosticRequest, control *agentproto.DiagnosticsControl, now time.Time) bool {
	d := &c.diagnostics
	if d.closed || r.authorization != c.authGeneration || r.order <= d.handled {
		return false
	}
	d.handled = r.order
	if control == nil {
		c.stopDiagnosticsLocked()
		d.cursor, d.challenge = "", ""
		return false
	}
	if control.Session != r.session || control.RequestNonce != r.nonce || !diagnosticToken(control.Epoch) || !diagnosticToken(control.Challenge) || control.Generation == 0 {
		c.stopDiagnosticsLocked()
		return false
	}
	if now.Sub(r.started) < 0 || now.Sub(r.started) > 10*time.Second {
		return true
	}
	if control.RemainingMS < 0 || control.RemainingMS > agentproto.DiagnosticsMaxLeaseMS || (control.RemainingMS > 0 && control.IntervalMS != 1000) {
		c.stopDiagnosticsLocked()
		return false
	}
	if d.epoch == control.Epoch && control.Generation <= d.generation {
		return false
	}
	d.challenge = control.Challenge
	d.cursor = control.Epoch + ":" + strconv.FormatUint(control.Generation, 10)
	if d.epoch != control.Epoch && d.inflight != nil {
		d.inflight()
	}
	d.epoch, d.generation = control.Epoch, control.Generation
	if control.RemainingMS == 0 {
		c.stopDiagnosticsLocked()
		return false
	}
	// A renewal may arrive before the worker observes the old expiry. Preserve
	// sequence but explicitly invalidate that interrupted sampling baseline.
	if !now.Before(d.deadline) {
		d.baselineRevision++
	}
	d.deadline = r.started.Add(time.Duration(control.RemainingMS) * time.Millisecond)
	if !now.Before(d.deadline) {
		c.stopDiagnosticsLocked()
		return false
	}
	if d.wake == nil {
		d.wake, d.done = make(chan struct{}, 1), make(chan struct{})
		var ctx context.Context
		ctx, d.cancel = context.WithCancel(context.Background())
		go c.diagnosticsWorker(ctx, d.wake, d.done)
	}
	c.wakeDiagnosticsLocked()
	return false
}

func (c *Client) wakeDiagnosticsLocked() {
	if c.diagnostics.wake != nil {
		select {
		case c.diagnostics.wake <- struct{}{}:
		default:
		}
	}
}
func (c *Client) stopDiagnosticsLocked() {
	c.diagnostics.deadline = time.Time{}
	c.diagnostics.baselineRevision++
	if c.diagnostics.inflight != nil {
		c.diagnostics.inflight()
	}
	c.wakeDiagnosticsLocked()
}
func (c *Client) diagnosticsFailed(r diagnosticRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.authorization == c.authGeneration && r.order >= c.diagnostics.handled {
		c.diagnostics.handled = r.order
		c.stopDiagnosticsLocked()
	}
}
func (c *Client) closeDiagnostics() {
	c.mu.Lock()
	c.diagnostics.closed = true
	c.stopDiagnosticsLocked()
	if c.diagnostics.cancel != nil {
		c.diagnostics.cancel()
	}
	done := c.diagnostics.done
	c.mu.Unlock()
	if done != nil {
		<-done
	}
}

// One serial worker, with no sample queue. Refreshes only extend the local
// monotonic deadline; they never restart sequence or CPU/NIC baselines.
func (c *Client) diagnosticsWorker(ctx context.Context, wake <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	var sampler diagnosticSampler
	var epoch string
	var sequence uint64
	var baselineRevision uint64
	var next time.Time
	activeBefore := false
	for {
		c.mu.Lock()
		d := &c.diagnostics
		current, deadline, session, reset := d.epoch, d.deadline, c.configSession, d.baselineRevision
		active := !d.closed && !c.revoked && !c.configRejected && !c.offline && time.Now().Before(deadline)
		c.mu.Unlock()
		if !active {
			if activeBefore {
				sampler.Reset()
				next = time.Time{}
				activeBefore = false
			}
			select {
			case <-ctx.Done():
				return
			case <-wake:
				continue
			}
		}
		activeBefore = true
		if reset != baselineRevision {
			sampler.Reset()
			next = time.Time{}
			baselineRevision = reset
		}
		if current != epoch {
			epoch, sequence, next = current, 0, time.Time{}
			sampler.Reset()
		}
		if !next.IsZero() && time.Now().Before(next) {
			until := next
			if deadline.Before(until) {
				until = deadline
			}
			timer := time.NewTimer(time.Until(until))
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-wake:
				timer.Stop()
				continue
			case <-timer.C:
			}
			continue
		}
		c.mu.Lock()
		if d.epoch != epoch || d.closed || c.revoked || c.configRejected || c.offline || !time.Now().Before(d.deadline) {
			c.mu.Unlock()
			continue
		}
		end := time.Now().Add(2 * time.Second)
		if d.deadline.Before(end) {
			end = d.deadline
		}
		requestCtx, cancel := context.WithDeadline(ctx, end)
		d.inflight = cancel
		generation := d.generation
		c.mu.Unlock()
		next = time.Now().Add(time.Second)
		sample := sampler.Sample(requestCtx)
		if sequence == agentproto.DiagnosticsMaxSequence {
			cancel()
			c.mu.Lock()
			c.stopDiagnosticsLocked()
			c.mu.Unlock()
			continue
		}
		sequence++
		sample.Session, sample.Epoch, sample.Sequence = session, epoch, sequence
		if requestCtx.Err() == nil {
			c.mu.Lock()
			valid := d.epoch == epoch && !d.closed && !c.revoked && !c.configRejected && !c.offline && time.Now().Before(d.deadline)
			c.mu.Unlock()
			if valid {
				if err := c.postDiagnostics(requestCtx, sample); err != nil {
					c.mu.Lock()
					if d.epoch == epoch && d.generation == generation {
						c.stopDiagnosticsLocked()
					}
					c.mu.Unlock()
				}
			}
		}
		cancel()
		c.mu.Lock()
		d.inflight = nil
		c.mu.Unlock()
	}
}

func (c *Client) postDiagnostics(ctx context.Context, sample agentproto.DiagnosticsSample) error {
	if sample.Sequence == 0 || sample.Sequence > agentproto.DiagnosticsMaxSequence {
		return errors.New("invalid diagnostic sequence")
	}
	if len(sample.Interfaces) > agentproto.DiagnosticsMaxInterfaces {
		return errors.New("too many diagnostic interfaces")
	}
	raw, err := json.Marshal(sample)
	if err != nil {
		return err
	}
	if len(raw) > agentproto.DiagnosticsMaxSampleBytes {
		return errors.New("diagnostic sample exceeds size limit")
	}
	code, _, _, err := c.do(ctx, http.MethodPost, "/api/agent/diagnostics", json.RawMessage(raw), nil)
	if err != nil {
		return err
	}
	if code != http.StatusOK && code != http.StatusNoContent {
		return fmt.Errorf("captain: diagnostics HTTP %d", code)
	}
	return nil
}
