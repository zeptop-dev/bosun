package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/panel"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// The sole in-flight batch is immutable. While it awaits acknowledgement,
// periodic counters remain in the cores. Lifecycle checkpoints instead append
// to Buffered, which has never been sent and may still be coalesced.
// There is necessarily a small gap between resetting upstream counters and
// fsync: upstream APIs do not support transactional reads with acknowledgement.
type trafficBatch struct {
	Seq       uint64                    `json:"seq"`
	Window    int                       `json:"window"`
	StartedAt time.Time                 `json:"started_at,omitempty"`
	Sample    *agentproto.TrafficSample `json:"sample,omitempty"`
	Traffic   []spec.UserTraffic        `json:"traffic"`
	Inbounds  map[string]spec.Traffic   `json:"inbounds,omitempty"`
	Outbounds map[string]spec.Traffic   `json:"outbounds,omitempty"`
}

type trafficJournal struct {
	Version  int           `json:"version"`
	Epoch    string        `json:"epoch"`
	Next     uint64        `json:"next"`
	Since    time.Time     `json:"since"`
	Pending  *trafficBatch `json:"pending,omitempty"`
	Buffered *trafficBatch `json:"buffered,omitempty"`
	path     string
}

func (a *Agent) loadTrafficJournal() error {
	if a.trafficJournal != nil {
		return nil
	}
	identity := a.driver.Name()
	if d, ok := a.driver.(interface{ TrafficIdentity() string }); ok {
		identity = d.TrafficIdentity()
		if identity == "" {
			return errors.New("traffic journal requires a paired node")
		}
	}
	dir := filepath.Join(a.cfg.DataDir, "traffic")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("traffic journal directory must be private and not a symlink")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return errors.New("traffic journal directory owner mismatch")
	}
	path := filepath.Join(dir, fmt.Sprintf("%x.json", sha256.Sum256([]byte(identity))))
	j := &trafficJournal{Version: 1, Next: uint64(time.Now().UnixNano()), Since: a.started, path: path}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err == nil {
		defer f.Close()
		if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() || st.Size() > 64<<20 {
			return errors.New("invalid traffic journal file")
		}
		if err := json.NewDecoder(io.LimitReader(f, 64<<20)).Decode(j); err != nil {
			return fmt.Errorf("read traffic journal: %w", err)
		}
		if raw, err := hex.DecodeString(j.Epoch); err != nil || len(raw) != 16 || j.Version != 1 || j.Next == 0 || j.Next >= math.MaxInt64 || (j.Pending != nil && j.Pending.Seq != j.Next) {
			return errors.New("invalid traffic journal state")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		j.Epoch = hex.EncodeToString(raw)
		if err := j.save(); err != nil {
			return err
		}
	} else {
		return err
	}
	a.trafficJournal = j
	return nil
}

func (j *trafficJournal) save() error {
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if len(raw) > 64<<20 {
		return errors.New("traffic journal exceeds 64 MiB")
	}
	f, err := os.CreateTemp(filepath.Dir(j.path), ".pending-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), j.path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(j.path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (a *Agent) reportError(err error) bool {
	a.reportFailures.Add(1)
	a.log.Error("report deferred; traffic batch retained", "err", err)
	a.statusMu.Lock()
	a.lastReportErr = err.Error()
	a.statusMu.Unlock()
	return false
}

// checkpointTraffic runs on the serial agent loop before any operation that
// can discard a core's counters. No network acknowledgement is needed for
// Reporter drivers: an unavailable panel must not prevent safe local changes.
func (a *Agent) checkpointTraffic(ctx context.Context) error {
	defer a.updateDeliveryStatus()
	// Every caller may replace or reconfigure counter sources after this read.
	defer func() { a.trafficReads = nil }()
	running := false
	for _, name := range a.reg.Names() {
		c, _ := a.reg.Get(name)
		running = running || c.Running()
	}
	if !running {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, ok := a.driver.(panel.Reporter); !ok {
		if a.pendingTraffic == nil {
			a.pendingTraffic = map[trafficKey]*spec.UserTraffic{}
		}
		traffic, _ := a.collectUserTraffic(ctx)
		if a.statsCollectionErr != nil {
			return a.statsCollectionErr
		}
		if err := a.driver.PushTraffic(ctx, traffic); err != nil {
			return err
		}
		a.pendingTraffic = map[trafficKey]*spec.UserTraffic{}
		return nil
	}
	if err := a.loadTrafficJournal(); err != nil {
		return err
	}
	j := a.trafficJournal
	// A previous failed save may have reset counters into memory. Retry it
	// before reading/resetting any more upstream counters.
	if err := j.save(); err != nil {
		return err
	}
	batch := a.collectTrafficBatch(ctx)
	j.Buffered = mergeTrafficBatches(j.Buffered, batch)
	return errors.Join(j.save(), a.statsCollectionErr)
}

func (a *Agent) collectTrafficBatch(ctx context.Context) *trafficBatch {
	sample := &agentproto.TrafficSample{Version: 1, CollectionStartedAt: time.Now().UTC(), Segments: 1, Reasons: []string{}, Sources: []agentproto.TrafficSampleSource{}}
	a.trafficSample = sample
	defer func() { a.trafficSample = nil }()
	a.pendingTraffic = map[trafficKey]*spec.UserTraffic{}
	_, traffic := a.collectUserTraffic(ctx)
	in := a.collectTagged(ctx, map[string]spec.Traffic{}, "inbound", func(c core.Core) (map[string]spec.Traffic, error) {
		if c, ok := c.(core.InboundStatser); ok {
			return c.InboundStats(ctx, true)
		}
		return nil, errSkip
	})
	out := a.collectTagged(ctx, map[string]spec.Traffic{}, "outbound", func(c core.Core) (map[string]spec.Traffic, error) {
		if c, ok := c.(core.OutboundStatser); ok {
			return c.OutboundStats(ctx, true)
		}
		return nil, errSkip
	})
	j := a.trafficJournal
	started := j.Since
	window := max(1, int(time.Since(j.Since).Seconds()))
	j.Since = time.Now()
	sample.CollectionEndedAt = time.Now().UTC()
	finishTrafficSample(sample)
	return &trafficBatch{StartedAt: started, Sample: sample, Window: window, Traffic: traffic, Inbounds: in, Outbounds: out}
}

func mergeTrafficBatches(old, next *trafficBatch) *trafficBatch {
	if old == nil {
		return next
	}
	sums := map[trafficKey]spec.UserTraffic{}
	for _, list := range [][]spec.UserTraffic{old.Traffic, next.Traffic} {
		for _, t := range list {
			k := trafficKey{t.UserID, t.Inbound}
			cur := sums[k]
			cur.UserID, cur.Inbound = t.UserID, t.Inbound
			cur.Up += t.Up
			cur.Down += t.Down
			sums[k] = cur
		}
	}
	out := &trafficBatch{StartedAt: old.StartedAt, Sample: mergeTrafficSamples(old.Sample, next.Sample), Window: old.Window + next.Window, Inbounds: map[string]spec.Traffic{}, Outbounds: map[string]spec.Traffic{}}
	for _, t := range sums {
		out.Traffic = append(out.Traffic, t)
	}
	merge := func(dst, src map[string]spec.Traffic) {
		for tag, t := range src {
			cur := dst[tag]
			cur.Up += t.Up
			cur.Down += t.Down
			dst[tag] = cur
		}
	}
	merge(out.Inbounds, old.Inbounds)
	merge(out.Inbounds, next.Inbounds)
	merge(out.Outbounds, old.Outbounds)
	merge(out.Outbounds, next.Outbounds)
	return out
}

func (a *Agent) prepareDurableReport(ctx context.Context) (agentproto.Report, error) {
	defer a.updateDeliveryStatus()
	if err := a.loadTrafficJournal(); err != nil {
		return agentproto.Report{}, err
	}
	j := a.trafficJournal
	if j.Pending == nil {
		batch := a.collectTrafficBatch(ctx)
		j.Buffered = mergeTrafficBatches(j.Buffered, batch)
		j.Pending = j.Buffered
		j.Pending.Seq = j.Next
		j.Buffered = nil
	}

	// Always save before sending, including a retry after a failed fsync.
	if err := j.save(); err != nil {
		return agentproto.Report{}, err
	}
	b := j.Pending
	full := a.buildReport(b.Traffic, a.SampleHost(ctx))
	full.TrafficSeq, full.TrafficEpoch, full.TrafficWindowSeconds = b.Seq, j.Epoch, b.Window
	full.TrafficSample = b.Sample
	a.updateDeliveryStatus()
	a.statusMu.Lock()
	delivery := a.status.Delivery
	a.statusMu.Unlock()
	full.TrafficDelivery = &agentproto.TrafficDelivery{SampledAt: time.Now().UTC(), PendingBytes: delivery.PendingBytes, BufferedBytes: delivery.BufferedBytes, JournalBytes: delivery.JournalBytes, OldestAt: delivery.OldestAt}
	full.Inbounds, full.Outbounds, full.Jobs = b.Inbounds, b.Outbounds, a.takeJobResults()
	return full, nil
}

// finishDurableReport runs on the agent loop. In particular it retains lifecycle
// checkpoints appended to Buffered while the immutable Pending batch was in flight.
func (a *Agent) finishDurableReport(full agentproto.Report, changed bool, err error) bool {
	defer a.updateDeliveryStatus()
	if err != nil {
		a.requeueJobResults(full.Jobs)
		return a.reportError(err)
	}
	j := a.trafficJournal
	if j == nil || j.Pending == nil || j.Epoch != full.TrafficEpoch || j.Pending.Seq != full.TrafficSeq {
		a.requeueJobResults(full.Jobs)
		return a.reportError(errors.New("report acknowledgement does not match pending traffic"))
	}
	next := *j
	next.Next++
	next.Pending = nil
	if err := next.save(); err != nil {
		// Keep the original durable batch: the panel deduplicates a retry after ACK loss.
		a.requeueJobResults(full.Jobs)
		return a.reportError(err)
	}
	a.trafficJournal = &next
	a.lastReportOK.Store(time.Now().Unix())
	a.statusMu.Lock()
	a.lastReport, a.lastReportErr = time.Now(), ""
	// A newer diagnostic created during delivery still needs its own acknowledgement.
	if full.Doctor != nil && a.pendingDoctor == full.Doctor {
		a.sentDoctor, a.sentDoctorAt, a.pendingDoctor = full.Doctor, time.Now(), nil
	}
	a.statusMu.Unlock()
	if ur, ok := a.driver.(panel.UpgradeRequester); ok && a.Upgrade != nil && a.serviceLeaseError() == nil {
		if v := ur.UpgradeRequested(); v != "" && v != a.upgradeAsked {
			a.upgradeAsked = v
			go a.Upgrade(v)
		}
	}
	return changed
}

func (a *Agent) reportDurable(ctx context.Context, reporter panel.Reporter) bool {
	full, err := a.prepareDurableReport(ctx)
	if err != nil {
		return a.reportError(err)
	}
	changed, err := reporter.Report(ctx, full)
	return a.finishDurableReport(full, changed, err)
}
