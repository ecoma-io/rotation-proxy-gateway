package analyticsstore

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
)

// The final flush is the reason Stop exists rather than a bare cancel, and it
// is the only chance the buffered tail gets to reach the database: the flush
// loop returns immediately after it, and nothing starts the writer again. So
// the context handed to that flush has to outlive the writer's own cancellation —
// a context derived from an already-cancelled parent fails every statement in
// the batch before any of them is sent, which is how a shutdown that looks
// perfectly healthy ends up silently discarding the tail it was built to keep.
func TestFinalFlushReachesTheBatchConn(t *testing.T) {
	conn := &ctxRecordingBatchConn{results: &stubBatchResults{}}
	w := newWriter(conn, zerolog.Nop(), WriterOptions{BufferSize: 8, FlushInterval: time.Hour})
	w.Start()
	if !w.RecordRotationAttempt(RotationAttempt{EventID: EventID("tail")}) {
		t.Fatal("sample was not queued")
	}

	w.Stop()

	if conn.calls.Load() == 0 {
		t.Fatal("the final flush never reached the batch conn")
	}
	if err := conn.errAtCall(0); err != nil {
		t.Fatalf("the final flush was handed a cancelled context: %v", err)
	}
	if got := w.Count().RotationAttempts; got != 1 {
		t.Fatalf("RotationAttempts = %d after the final flush, want the tail written", got)
	}
}

// ctxRecordingBatchConn is a batchConn that answers from the context it was
// handed, which is what makes "the final flush ran under a live context"
// observable without a database. A cancelled context is exactly what pgx's
// own pool does with any batch it is given.
type ctxRecordingBatchConn struct {
	results *stubBatchResults
	calls   atomic.Int32
	errs    []error
}

func (c *ctxRecordingBatchConn) SendBatch(ctx context.Context, _ *pgx.Batch) pgx.BatchResults {
	if err := ctx.Err(); err != nil {
		c.errs = append(c.errs, err)
	} else {
		c.errs = append(c.errs, nil)
	}
	c.calls.Add(1)
	return c.results
}

func (c *ctxRecordingBatchConn) errAtCall(i int) error {
	if i >= len(c.errs) {
		return nil
	}
	return c.errs[i]
}

// Loss must be visible in the counts, whether the sample was written or not. The
// serving path keeps recording for as long as the process is draining — a
// request that completes during the drain, a rotation procedure unwinding after
// its engine was cancelled — and every one of those samples arrives here after
// the writer's last flush has already drained the queues. A writer that silently
// accepts them reports success while nothing was ever stored, which is the one
// thing the accounting exists to prevent.
func TestSamplesRecordedAfterStopAreWrittenOrCounted(t *testing.T) {
	conn := &ctxRecordingBatchConn{results: &stubBatchResults{}}
	// A zero flush interval would spin, so the ticker is parked far out and the
	// shutdown path is what ends the writer.
	w := newWriter(conn, zerolog.Nop(), WriterOptions{BufferSize: 8, FlushInterval: time.Hour})
	r := &Recorder{writer: w, instance: "i"}
	r.enabled.Store(true)
	w.Start()
	// A sample buffered BEFORE Stop is written by the final flush — that is the
	// fix working, and TestFinalFlushReachesTheBatchConn covers it. The samples
	// that model a drain arrive after it, which is the case that used to vanish.
	r.Stop()
	for _, id := range []EventID{"a", "b", "c"} {
		r.RecordRotationAttempt(RotationAttempt{EventID: id})
	}

	got := r.Count()
	// Written is zero and must stay zero: the final flush ran before these
	// samples were offered, so no batch can carry them. What matters is that the
	// loss is counted rather than absorbed — the queue accepted them and nobody
	// read them back.
	if written := got.RotationAttempts; written != 0 {
		t.Fatalf("RotationAttempts = %d after the drain, want no post-shutdown sample claimed as written", written)
	}
	if dropped := got.DroppedRotationAttempts; dropped != 3 {
		t.Fatalf("DroppedRotationAttempts = %d, want all 3 post-shutdown samples counted as lost", dropped)
	}
	if conn.calls.Load() != 0 {
		t.Fatalf("the post-shutdown samples reached the database in %d batches, want none", conn.calls.Load())
	}
}

// Enabled must survive Stop, because that is what keeps the post-shutdown
// samples reaching the writer's accounting instead of vanishing at a nil-ish
// guard. Turning it off is the tempting fix and it is the wrong one: Record*
// would return before offering, and the loss would move from a visible counter
// to nothing at all.
func TestRecorderKeepsAccountingAfterStop(t *testing.T) {
	w := newWriter(nil, zerolog.Nop(), WriterOptions{BufferSize: 8, FlushInterval: time.Hour})
	r := &Recorder{writer: w, instance: "i"}
	r.enabled.Store(true)
	r.Stop()
	if !r.Enabled() {
		t.Fatal("a stopped recorder reports disabled, so post-shutdown samples are dropped silently")
	}
	r.RecordRequest(RequestSample{})
	if got := r.Count().DroppedRequestSamples; got != 1 {
		t.Fatalf("DroppedRequestSamples = %d after Stop, want the sample counted as lost", got)
	}
}
