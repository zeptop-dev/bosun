package agent

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

type blockedReporter struct {
	received chan agentproto.Report
	release  chan struct{}
}

func (p *blockedReporter) Report(ctx context.Context, r agentproto.Report) (bool, error) {
	p.received <- r
	select {
	case <-p.release:
		return false, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}
func receiveDelivery(t *testing.T, tr *reportTransport) reportDelivery {
	t.Helper()
	select {
	case r := <-tr.reports:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("report did not finish")
		return reportDelivery{}
	}
}
func TestAsyncReportKeepsConcurrentLifecycleCheckpoint(t *testing.T) {
	a, c, _ := checkpointRig(t)
	c.bytes = 1000
	full, err := a.prepareDurableReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tr := newReportTransport(context.Background())
	defer tr.close()
	p := &blockedReporter{make(chan agentproto.Report, 1), make(chan struct{})}
	if err := tr.sendReport(p, full); err != nil {
		t.Fatal(err)
	}
	sent := <-p.received
	c.bytes = 700
	// A slow network must not own the journal or prevent a local checkpoint.
	if err := a.checkpointTraffic(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.trafficJournal.Pending.Seq != sent.TrafficSeq || a.trafficJournal.Buffered == nil {
		t.Fatal("in-flight checkpoint lost identity")
	}
	close(p.release)
	r := receiveDelivery(t, tr)
	a.finishDurableReport(r.report, r.changed, r.err)
	if a.trafficJournal.Pending != nil || a.trafficJournal.Buffered == nil {
		t.Fatal("ACK discarded the concurrently appended checkpoint")
	}
	a.trafficJournal = nil
	if err := a.loadTrafficJournal(); err != nil {
		t.Fatal(err)
	}
	if a.trafficJournal.Buffered.Traffic[0].Up+a.trafficJournal.Buffered.Traffic[0].Down != 700 {
		t.Fatal("buffered bytes did not survive disk reload")
	}
}
func TestAsyncReportDeepCopiesMutableRuntime(t *testing.T) {
	tr := newReportTransport(context.Background())
	defer tr.close()
	p := &blockedReporter{make(chan agentproto.Report, 1), make(chan struct{})}
	rep := agentproto.Report{Traffic: []spec.UserTraffic{{UserID: 1, Up: 100}}, Online: map[string][]string{"user": {"192.0.2.10"}}}
	if err := tr.sendReport(p, rep); err != nil {
		t.Fatal(err)
	}
	rep.Traffic[0].Up = 999
	rep.Online["user"][0] = "198.51.100.20"
	received := <-p.received
	if received.Traffic[0].Up != 100 || received.Online["user"][0] != "192.0.2.10" {
		t.Fatal("sender shared mutable report state")
	}
	close(p.release)
	receiveDelivery(t, tr)
}
func TestAsyncReportCancellationPreservesRetryIdentity(t *testing.T) {
	a, c, _ := checkpointRig(t)
	c.bytes = 500
	full, err := a.prepareDurableReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tr := newReportTransport(context.Background())
	p := &blockedReporter{make(chan agentproto.Report, 1), make(chan struct{})}
	if err := tr.sendReport(p, full); err != nil {
		t.Fatal(err)
	}
	<-p.received
	tr.close()
	r := receiveDelivery(t, tr)
	if !errors.Is(r.err, context.Canceled) {
		t.Fatal(r.err)
	}
	a.finishDurableReport(r.report, r.changed, r.err)
	a.trafficJournal = nil
	retry, err := a.prepareDurableReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if retry.TrafficSeq != full.TrafficSeq || retry.TrafficEpoch != full.TrafficEpoch || !reflect.DeepEqual(retry.Traffic, full.Traffic) {
		t.Fatal("cancelled delivery changed durable retry")
	}
}
func TestReportAcknowledgementDoesNotClearNewDoctor(t *testing.T) {
	a, _, _ := checkpointRig(t)
	old := &agentproto.DoctorReport{}
	a.pendingDoctor = old
	full, err := a.prepareDurableReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fresh := &agentproto.DoctorReport{}
	a.pendingDoctor = fresh
	a.finishDurableReport(full, false, nil)
	if a.pendingDoctor != fresh {
		t.Fatal("old report acknowledged a newer diagnostic")
	}
}
func TestDeliveryStatusSeparatesPendingAndBuffered(t *testing.T) {
	a, c, _ := checkpointRig(t)
	c.bytes = 300
	full, err := a.prepareDurableReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c.bytes = 200
	if err := a.checkpointTraffic(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := a.Status().Delivery
	// Fixture accounts equal upload and download across two inbounds.
	if st.PendingBytes != 600 || st.BufferedBytes != 400 || st.JournalBytes <= 0 || st.OldestAt == nil {
		t.Fatalf("bad backlog: %+v", st)
	}
	a.finishDurableReport(full, false, nil)
	if st := a.Status().Delivery; st.PendingBytes != 0 || st.BufferedBytes != 400 {
		t.Fatalf("bad ACK backlog: %+v", st)
	}
}

type asyncCaptain struct {
	nopDriver
	blockedReporter
}

func (*asyncCaptain) Name() string { return "captain" }
func TestReportRequestsCoalesceWithoutCollectingMoreCounters(t *testing.T) {
	a, c, _ := checkpointRig(t)
	p := &asyncCaptain{blockedReporter: blockedReporter{make(chan agentproto.Report, 1), make(chan struct{})}}
	a.driver = p
	a.delivery = newReportTransport(context.Background())
	defer a.delivery.close()
	c.bytes = 100
	a.requestReport(context.Background())
	<-p.received
	c.bytes = 250
	for range 100 {
		a.requestReport(context.Background())
	}
	if c.bytes != 250 || !a.delivery.reportAgain || len(a.delivery.reports) != 0 {
		t.Fatal("busy reports collected extra counters or grew a queue")
	}
	close(p.release)
	result := receiveDelivery(t, a.delivery)
	a.delivery.reportBusy = false
	a.finishDurableReport(result.report, result.changed, result.err)
	if c.bytes != 250 {
		t.Fatal("ack consumed later counters")
	}
}

func TestDeliveryStatusKeepsLegacyStartUnknown(t *testing.T) {
	a, c, _ := checkpointRig(t)
	c.bytes = 100
	if _, err := a.prepareDurableReport(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.trafficJournal.Pending.StartedAt = time.Time{}
	c.bytes = 200
	if err := a.checkpointTraffic(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.Status().Delivery.OldestAt != nil {
		t.Fatal("younger known batch hid older unknown batch")
	}
}
