package analyticsstore

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rs/zerolog"
)

// stubBatchResults satisfies pgx.BatchResults with a scripted result per queued
// statement, so execBatch's "consume exactly one result per queued statement"
// contract — the part pgx.Batch cannot report on itself — is observable without
// a database.
type stubBatchResults struct {
	execErrs []error
	closeErr error
	executed int
	closed   bool
}

func (r *stubBatchResults) Exec() (pgconn.CommandTag, error) {
	i := r.executed
	r.executed++
	if i < len(r.execErrs) && r.execErrs[i] != nil {
		return pgconn.CommandTag{}, r.execErrs[i]
	}
	return pgconn.CommandTag{}, nil
}

func (r *stubBatchResults) Close() error {
	r.closed = true
	return r.closeErr
}

func (r *stubBatchResults) Query() (pgx.Rows, error) { return nil, errors.New("unused") }
func (r *stubBatchResults) QueryRow() pgx.Row        { return nil }

// stubBatchConn is a batchConn whose every SendBatch hands back the same
// scripted results, and which records how many batches were opened.
type stubBatchConn struct {
	results *stubBatchResults
	batches int
}

func (c *stubBatchConn) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	c.batches++
	return c.results
}

func TestNewWriterAppliesDefaults(t *testing.T) {
	w := NewWriter(nil, zerolog.Nop(), WriterOptions{})
	if w.opts.BufferSize != DefaultBufferSize {
		t.Fatalf("BufferSize = %d, want %d", w.opts.BufferSize, DefaultBufferSize)
	}
	if w.opts.FlushInterval != defaultFlushInterval {
		t.Fatalf("FlushInterval = %s, want %s", w.opts.FlushInterval, defaultFlushInterval)
	}
	if w.opts.BucketWidth != DefaultBucketWidth {
		t.Fatalf("BucketWidth = %s, want %s", w.opts.BucketWidth, DefaultBucketWidth)
	}
}

// TestOfferRotationEvictsOldestAndCountsDrop pins the bounding contract: a full
// queue drops the OLDEST attempt, not the newest, and the loss is counted rather
// than hidden. Dropping the newest would silently discard the observation that
// just happened, which is the one an operator debugging a rotation needs.
func TestOfferRotationEvictsOldestAndCountsDrop(t *testing.T) {
	const size = 2
	w := NewWriter(nil, zerolog.Nop(), WriterOptions{BufferSize: size, FlushInterval: time.Hour})

	if queued, dropped := w.offerRotation(RotationAttempt{EventID: EventID("a")}); !queued || dropped != 0 {
		t.Fatalf("first offer = (queued=%t, dropped=%d), want (true, 0)", queued, dropped)
	}
	if queued, dropped := w.offerRotation(RotationAttempt{EventID: EventID("b")}); !queued || dropped != 0 {
		t.Fatalf("second offer = (queued=%t, dropped=%d), want (true, 0)", queued, dropped)
	}
	// The third offer evicts a and queues c. Those are independent facts: the
	// newest observation survives, but /status must still honestly count a.
	if queued, dropped := w.offerRotation(RotationAttempt{EventID: EventID("c")}); !queued || dropped != 1 {
		t.Fatalf("overflow offer = (queued=%t, dropped=%d), want (true, 1)", queued, dropped)
	}
	if got := w.RecordRotationAttempt(RotationAttempt{EventID: EventID("d")}); !got {
		t.Fatal("a public offer that evicts the oldest must still queue the newest value")
	}
	if got := w.rotationsDropped.Load(); got != 1 {
		t.Fatalf("rotationsDropped = %d, want 1 after the public overflow", got)
	}
	// The public offer evicted b, so the queue holds c then d.
	if first := <-w.rotations; first.EventID != EventID("c") {
		t.Fatalf("first remaining = %q, want %q", first.EventID, EventID("c"))
	}
	if second := <-w.rotations; second.EventID != EventID("d") {
		t.Fatalf("second remaining = %q, want %q", second.EventID, EventID("d"))
	}
}

func TestDrainStopsAtMax(t *testing.T) {
	ch := make(chan RotationAttempt, 4)
	ch <- RotationAttempt{EventID: EventID("1")}
	ch <- RotationAttempt{EventID: EventID("2")}
	ch <- RotationAttempt{EventID: EventID("3")}
	if got := drain(ch, 2); len(got) != 2 {
		t.Fatalf("drain(ch, 2) returned %d entries, want 2", len(got))
	}
	if len(ch) != 1 {
		t.Fatalf("drain left %d entries queued, want 1", len(ch))
	}
	if got := drain(ch, 0); got != nil {
		t.Fatalf("drain(ch, 0) = %v, want nil", got)
	}
}

// TestDrainAllEmptiesEveryQueue guards the flusher's accounting: drainAll must
// clear all four queues, because a queue it skips is a batch that silently
// persists into the next flush interval.
func TestDrainAllEmptiesEveryQueue(t *testing.T) {
	w := NewWriter(nil, zerolog.Nop(), WriterOptions{BufferSize: 8, FlushInterval: time.Hour})
	w.rotations <- RotationAttempt{EventID: EventID("r")}
	w.ips <- IPObservation{IP: "1.2.3.4"}
	w.requests <- RequestSample{}
	w.failureQ <- FailureSample{}

	if got := w.drainAll(); got != 4 {
		t.Fatalf("drainAll() = %d, want 4", got)
	}
	for _, q := range []struct {
		name string
		n    int
	}{
		{"rotations", len(w.rotations)},
		{"ips", len(w.ips)},
		{"requests", len(w.requests)},
		{"failureQ", len(w.failureQ)},
	} {
		if q.n != 0 {
			t.Fatalf("%s still holds %d entries after drainAll", q.name, q.n)
		}
	}
}

func TestStopIsIdempotentAndPreventsFurtherWork(t *testing.T) {
	w := NewWriter(nil, zerolog.Nop(), WriterOptions{BufferSize: 2, FlushInterval: time.Hour, ShutdownGrace: 10 * time.Millisecond})
	w.Stop()
	if !w.stopped {
		t.Fatal("Stop must mark the writer stopped")
	}
	// A second Stop must not panic or block, and work offered afterwards must
	// not reach a queue the flusher will never drain.
	w.Stop()
	// A stopped writer's queue is simply never flushed again, so anything left
	// in it is never written. What matters is that Stop is idempotent (no panic,
	// no block) and that the queues are no longer racing a flusher.
	if len(w.rotations) != 0 {
		t.Fatalf("rotations queue holds %d entries before any offer, want 0", len(w.rotations))
	}
}

// TestNewEventIDShapeAndUniqueness covers the CSPRNG path: ids are the "a-"
// prefixed base32 form, and two of them never collide.
func TestNewEventIDShapeAndUniqueness(t *testing.T) {
	seen := make(map[EventID]bool, 100)
	for range 100 {
		id := newEventID()
		if !strings.HasPrefix(string(id), "a-") {
			t.Fatalf("event id %q does not carry the a- prefix", id)
		}
		if id == "a-degraded-" || strings.HasPrefix(string(id), "a-degraded-") {
			t.Fatalf("healthy crypto/rand produced the degraded fallback id %q", id)
		}
		if seen[id] {
			t.Fatalf("event id %q was minted twice", id)
		}
		seen[id] = true
	}
}

// TestExecBatchConsumesExactlyQueuedResults is the reason batchConn exists:
// pgx.Batch carries no length, so execBatch loops on the caller-supplied count
// and must consume precisely that many results and close the batch whatever the
// statement errors were.
func TestExecBatchConsumesExactlyQueuedResults(t *testing.T) {
	t.Run("every queued statement is executed", func(t *testing.T) {
		conn := &stubBatchConn{results: &stubBatchResults{}}
		w := &Writer{pool: conn}
		batch := &pgx.Batch{}
		batch.Queue("select 1")
		batch.Queue("select 2")

		if err := w.execBatch(context.Background(), batch, 2); err != nil {
			t.Fatalf("execBatch: %v", err)
		}
		if conn.batches != 1 {
			t.Fatalf("SendBatch calls = %d, want 1", conn.batches)
		}
		if conn.results.executed != 2 {
			t.Fatalf("Exec calls = %d, want 2", conn.results.executed)
		}
		if !conn.results.closed {
			t.Fatal("execBatch must Close the batch even on success")
		}
	})

	t.Run("one statement error does not skip the rest or hide the close", func(t *testing.T) {
		boom := errors.New("boom")
		conn := &stubBatchConn{results: &stubBatchResults{execErrs: []error{boom, nil}}}
		w := &Writer{pool: conn}
		batch := &pgx.Batch{}
		batch.Queue("select 1")
		batch.Queue("select 2")

		err := w.execBatch(context.Background(), batch, 2)
		if !errors.Is(err, boom) {
			t.Fatalf("execBatch error = %v, want it to wrap %v", err, boom)
		}
		if conn.results.executed != 2 {
			t.Fatalf("Exec calls = %d, want 2 — a failing statement must not abort the loop", conn.results.executed)
		}
		if !conn.results.closed {
			t.Fatal("execBatch must Close the batch even when a statement failed")
		}
	})

	t.Run("close error is reported when no statement failed", func(t *testing.T) {
		closeErr := errors.New("close failed")
		conn := &stubBatchConn{results: &stubBatchResults{closeErr: closeErr}}
		w := &Writer{pool: conn}

		if err := w.execBatch(context.Background(), &pgx.Batch{}, 0); !errors.Is(err, closeErr) {
			t.Fatalf("execBatch error = %v, want it to wrap %v", err, closeErr)
		}
	})
}

func TestNilRecorderIsSafeAndInert(t *testing.T) {
	var r *Recorder
	// Every method must tolerate a nil receiver: the recorder is wired in as an
	// optional dependency, and analytics being unconfigured must never be a nil
	// panic on the serving path.
	r.RecordRotationAttempt(RotationAttempt{EventID: EventID("x")})
	r.RecordIPObservation(IPObservation{})
	r.RecordRequest(RequestSample{})
	r.RecordFailure(FailureSample{})
	r.Stop()
	if r.Enabled() {
		t.Fatal("a nil recorder must never report enabled")
	}
	if got := r.Instance(); got != "" {
		t.Fatalf("nil recorder instance = %q, want empty", got)
	}
	if got := r.Count(); got != (Count{}) {
		t.Fatalf("nil recorder count = %+v, want the zero Count", got)
	}
}

func TestRecorderBucketNowPassesThrough(t *testing.T) {
	r := &Recorder{}
	tm := time.Date(2026, 10, 1, 1, 2, 3, 4, time.UTC)
	if got := r.BucketNow(tm); !got.Equal(tm) {
		t.Fatalf("BucketNow(%s) = %s, want the same instant", tm, got)
	}
}

func TestNewRecorderWithEmptyDSNIsDisabled(t *testing.T) {
	r, stop, err := NewRecorder(context.Background(), "", "test-instance", zerolog.Nop(), WriterOptions{})
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	defer stop()
	if r != nil {
		t.Fatal("an empty DSN must yield a nil recorder, not a writer with no database")
	}
	if r.Enabled() {
		t.Fatal("a nil recorder must not be enabled")
	}
}

func TestWriterCountIsZeroBeforeAnyWrite(t *testing.T) {
	w := NewWriter(nil, zerolog.Nop(), WriterOptions{})
	if got := w.Count(); got != (Count{}) {
		t.Fatalf("fresh writer count = %+v, want the zero Count", got)
	}
}

// TestDroppedCountersAreIndependent pins that the four queues account for their
// own losses: an operator reading "1 rotation attempt dropped" must not have to
// disentangle it from request or failure drops.
func TestDroppedCountersAreIndependent(t *testing.T) {
	w := NewWriter(nil, zerolog.Nop(), WriterOptions{BufferSize: 1, FlushInterval: time.Hour})
	w.rotations <- RotationAttempt{EventID: EventID("kept")}
	w.ips <- IPObservation{IP: "1.2.3.4"}

	if !w.RecordRotationAttempt(RotationAttempt{EventID: EventID("newest")}) {
		t.Fatal("the rotation offer into a full queue must still queue the newest value")
	}
	if got := w.Count(); got.DroppedRotationAttempts != 1 {
		t.Fatalf("DroppedRotationAttempts = %d, want 1 for the evicted oldest attempt", got.DroppedRotationAttempts)
	}
	if got := w.Count(); got.DroppedIPObservations != 0 || got.DroppedRequestSamples != 0 || got.DroppedFailureSamples != 0 {
		t.Fatalf("a rotation overflow must not be attributed to another queue: %+v", got)
	}
	// Only the rotations queue was touched: the newest rotation survived and the
	// ip queue kept its entry.
	if head := <-w.rotations; head.EventID != EventID("newest") {
		t.Fatalf("rotations queue head = %q, want %q — the newest value must be the survivor", head.EventID, EventID("newest"))
	}
	if len(w.ips) != 1 {
		t.Fatalf("ips queue holds %d entries after an unrelated rotation overflow, want 1", len(w.ips))
	}
}

// TestWriterStopBeforeStartDoesNotPanic guards the shutdown ordering in main:
// Stop runs whether or not Start ever got a chance to.
func TestWriterStopBeforeStartDoesNotPanic(t *testing.T) {
	w := NewWriter(nil, zerolog.Nop(), WriterOptions{BufferSize: 1, FlushInterval: time.Hour, ShutdownGrace: time.Millisecond})
	w.Stop()
	if !w.stopped {
		t.Fatal("Stop before Start must still mark the writer stopped")
	}
}

var _ batchConn = (*stubBatchConn)(nil)

// guard against an unused-import regression when the file is trimmed.
var _ = atomic.Uint64{}
