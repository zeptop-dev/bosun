package agent

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/zeptop-dev/bosun/internal/panel"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

// Each channel has room for the single outstanding request. Ticker bursts
// coalesce; a slow or unreachable panel cannot create an unbounded queue.
// Report collection, checkpoints and acknowledgement all remain on Run's loop.
type reportTransport struct {
	ctx                               context.Context
	cancel                            context.CancelFunc
	wg                                sync.WaitGroup
	reports                           chan reportDelivery
	beats                             chan beatDelivery
	reportBusy, reportAgain, beatBusy bool
}
type reportDelivery struct {
	report  agentproto.Report
	changed bool
	err     error
}
type beatDelivery struct {
	beat agentproto.Beat
	err  error
}

func newReportTransport(ctx context.Context) *reportTransport {
	ctx, cancel := context.WithCancel(ctx)
	return &reportTransport{ctx: ctx, cancel: cancel, reports: make(chan reportDelivery, 1), beats: make(chan beatDelivery, 1)}
}
func (t *reportTransport) close() { t.cancel(); t.wg.Wait() }

func frozenValue[T any](value T) (T, error) {
	var copy T
	raw, err := json.Marshal(value)
	if err != nil {
		return copy, err
	}
	err = json.Unmarshal(raw, &copy)
	return copy, err
}

func (t *reportTransport) sendReport(reporter panel.Reporter, full agentproto.Report) error {
	// Freeze all slices/maps, including runtime pointers. The original value is
	// returned only as the ACK identity (including its exact diagnostic pointer).
	frozen, err := frozenValue(full)
	if err != nil {
		return err
	}
	t.reportBusy = true
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		ctx, cancel := context.WithTimeout(t.ctx, 30*time.Second)
		defer cancel()
		changed, err := reporter.Report(ctx, frozen)
		// No other request starts until Run consumes this result.
		t.reports <- reportDelivery{full, changed, err}
	}()
	return nil
}
func (t *reportTransport) sendBeat(beater panel.Beater, beat agentproto.Beat) {
	frozen, err := frozenValue(beat)
	if err != nil {
		t.beats <- beatDelivery{beat, err}
		t.beatBusy = true
		return
	}
	t.beatBusy = true
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		ctx, cancel := context.WithTimeout(t.ctx, 8*time.Second)
		defer cancel()
		err := beater.Beat(ctx, frozen)
		t.beats <- beatDelivery{frozen, err}
	}()
}

func (a *Agent) requestReport(ctx context.Context) bool {
	reporter, ok := a.driver.(panel.Reporter)
	// Local and legacy drivers retain synchronous semantics; only the Captain
	// network driver uses this path. Its report/state access is mutex protected.
	if !ok || a.driver.Name() != "captain" || a.delivery == nil {
		return a.report(ctx)
	}
	t := a.delivery
	if t.reportBusy {
		t.reportAgain = true
		return false
	}
	full, err := a.prepareDurableReport(ctx)
	if err != nil {
		return a.reportError(err)
	}
	if err = t.sendReport(reporter, full); err != nil {
		a.requeueJobResults(full.Jobs)
		return a.reportError(err)
	}
	return false
}

// DeliveryStatus contains only accounting health, never subscriber identities,
// credentials, journal paths or traffic destinations. Bytes not yet collected
// from running cores are not included in these durable pending totals.
type DeliveryStatus struct {
	PendingBytes  int64      `json:"pending_bytes"`
	BufferedBytes int64      `json:"buffered_bytes"`
	OldestAt      *time.Time `json:"oldest_at,omitempty"`
	JournalBytes  int64      `json:"journal_bytes"`
}

func (a *Agent) updateDeliveryStatus() {
	var status DeliveryStatus
	unknownStart := false
	if j := a.trafficJournal; j != nil {
		sum := func(b *trafficBatch) int64 {
			if b == nil {
				return 0
			}
			if b.StartedAt.IsZero() {
				unknownStart = true
			}
			if !b.StartedAt.IsZero() && (status.OldestAt == nil || b.StartedAt.Before(*status.OldestAt)) {
				at := b.StartedAt
				status.OldestAt = &at
			}
			var total int64
			for _, v := range b.Traffic {
				total += v.Up + v.Down
			}
			return total
		}
		status.PendingBytes = sum(j.Pending)
		status.BufferedBytes = sum(j.Buffered)
		if info, err := os.Stat(j.path); err == nil {
			status.JournalBytes = info.Size()
		}
	}
	if unknownStart {
		status.OldestAt = nil
	}
	a.setStatus(func(s *Status) { s.Delivery = status })
}
