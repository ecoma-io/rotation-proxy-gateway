package analyticsstore

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// batchConn is the slice of pgx a Writer actually uses: opening a batch and
// releasing it. A *pgxpool.Pool satisfies it unchanged, and a test can satisfy
// it without a database.
//
// It exists so the writer's SQL-carrying code — the four write* methods and
// execBatch — is reachable by a unit test at all. What proves the statements
// and the migration agree is a live PostgreSQL, which a unit test cannot
// provide; this seam covers the batching and error handling wrapped around
// them, and it is deliberately the smallest one that does.
type batchConn interface {
	SendBatch(context.Context, *pgx.Batch) pgx.BatchResults
}

// Writer bounds and batches every write this package makes. It is the only
// component that talks SQL, and it runs entirely off the serving path: callers
// hand it observations, it hands the database batches on a timer.
//
// Three properties it guarantees, in priority order:
//
//  1. It never blocks a caller. Record* appends to a buffered channel and
//     returns; if the channel is full the sample is dropped (oldest-first) and
//     counted. A slow or absent database can therefore never add latency to a
//     proxied request.
//  2. It never grows without bound. Every queue is a fixed-size buffered
//     channel, so a producer faster than the flushes cannot grow memory — it can
//     only lose samples, and the loss is counted rather than silent.
//  3. A replay is a no-op. Event batches insert by event_id, so a batch
//     re-presented after a partial failure collides on the primary key and adds
//     nothing. Aggregate batches upsert a *delta*, and a delta leaves the
//     channel exactly once, so the same delta is never presented twice.
//
// Idempotency across a crash mid-flush therefore needs no bookkeeping table of
// its own: the event tables' primary keys are the ledger.
type Writer struct {
	// pool is the batchConn the writer sends through: a *pgxpool.Pool in
	// production, and the seam a unit test substitutes.
	pool   batchConn
	log    zerolog.Logger
	opts   WriterOptions
	ctx    context.Context
	cancel context.CancelFunc
	// wg tracks the flush goroutine. mu guards started/stopped, which are
	// plain fields because Start runs before the writer is shared and Stop
	// after; WaitGroup cannot be locked and so cannot guard them itself.
	wg sync.WaitGroup
	mu sync.Mutex

	// Queues. Each is fixed-capacity; a full queue drops its oldest sample.
	rotations chan RotationAttempt
	ips       chan IPObservation
	requests  chan RequestSample
	failureQ  chan FailureSample

	// started guards against a second Start, and stopped against work after a
	// Stop. Both are plain under wg's discipline rather than atomic: Start runs
	// before the writer is shared, and Stop after.
	started bool
	stopped bool

	rotationsWritten atomic.Uint64
	ipsWritten       atomic.Uint64
	requestsWritten  atomic.Uint64
	failuresWritten  atomic.Uint64
	rotationsDropped atomic.Uint64
	ipsDropped       atomic.Uint64
	requestsDropped  atomic.Uint64
	failuresDropped  atomic.Uint64
	flushes          atomic.Uint64
	// writeFailures counts FAILED flushes, distinct from the failureQ channel
	// of failure samples and from the per-sample drop counter.
	writeFailures atomic.Uint64
}

// WriterOptions configures a Writer. The zero value is not usable: New fills
// the buffer sizes and interval with defaults for any field left at zero.
type WriterOptions struct {
	// FlushInterval is how often the writer drains its queues. Smaller is more
	// timely and more chatty; the default is one second, which keeps rotation
	// history near-real-time without a query per event.
	FlushInterval time.Duration
	// BufferSize bounds each of the four queues. This is the memory ceiling:
	// with the default, a writer can hold at most 4×BufferSize samples before
	// the oldest of a kind is dropped.
	BufferSize int
	// BackoffBase and BackoffMax bound the retry delay after a failed flush.
	// The writer backs off exponentially so a database that is down does not
	// receive a reconnect storm, and never waits longer than BackoffMax.
	BackoffBase time.Duration
	BackoffMax  time.Duration
	// ShutdownGrace bounds the final flush during Stop. Whatever is still
	// buffered is flushed within this budget; whatever does not fit is dropped
	// and counted, because blocking shutdown indefinitely on a dead database is
	// strictly worse than losing a last batch of history.
	ShutdownGrace time.Duration
	// BucketWidth is the aggregation window for request and failure counters.
	BucketWidth time.Duration
}

func (o *WriterOptions) applyDefaults() {
	if o.FlushInterval <= 0 {
		o.FlushInterval = defaultFlushInterval
	}
	if o.BufferSize <= 0 {
		o.BufferSize = DefaultBufferSize
	}
	if o.BackoffBase <= 0 {
		o.BackoffBase = defaultBackoffBase
	}
	if o.BackoffMax <= 0 {
		o.BackoffMax = defaultBackoffMax
	}
	if o.ShutdownGrace <= 0 {
		o.ShutdownGrace = defaultShutdownGrace
	}
	if o.BucketWidth <= 0 {
		o.BucketWidth = DefaultBucketWidth
	}
}

// The writer's defaults, named rather than inlined in applyDefaults so the
// startup log and /status can report the values the process is actually
// running under instead of restating numbers that can drift from the code.
const (
	// defaultFlushInterval is how often a started writer drains its queues.
	defaultFlushInterval = time.Second
	// DefaultBufferSize bounds each of the four queues, and so the writer's
	// whole in-memory footprint. It is exported because the startup log names
	// it: an operator has to be able to compute what "the buffer is full"
	// costs in samples per second before deciding whether the drops matter.
	DefaultBufferSize = 4096
	// defaultBackoffBase and defaultBackoffMax bound the retry delay after a
	// failed flush, so a database that is down receives a reconnect ramp rather
	// than a storm and rather than an unbounded wait.
	defaultBackoffBase = 100 * time.Millisecond
	defaultBackoffMax  = 30 * time.Second
	// defaultShutdownGrace bounds the final flush during Stop. It is inside the
	// process's own drain budget, never on top of it.
	defaultShutdownGrace = 5 * time.Second
)

// NewWriter builds a Writer over an already-migrated pool. It does not start
// the writer; call Start for that. The caller owns the pool.
func NewWriter(pool *pgxpool.Pool, log zerolog.Logger, opts WriterOptions) *Writer {
	// A typed nil would land in the batchConn as a non-nil interface, so the
	// conversion goes through this helper and the nil stays nil.
	return newWriter(connOrNil(pool), log, opts)
}

// connOrNil converts a possibly-nil pool to a possibly-nil batchConn without
// producing a non-nil interface wrapping a nil pointer.
func connOrNil(pool *pgxpool.Pool) batchConn {
	if pool == nil {
		return nil
	}
	return pool
}

func newWriter(pool batchConn, log zerolog.Logger, opts WriterOptions) *Writer {
	opts.applyDefaults()
	ctx, cancel := context.WithCancel(context.Background())
	return &Writer{
		pool:   pool,
		log:    log,
		opts:   opts,
		ctx:    ctx,
		cancel: cancel,
		// Buffered by the full size: a non-blocking send never waits, and a
		// full channel is the drop signal rather than a blocking point.
		rotations: make(chan RotationAttempt, opts.BufferSize),
		ips:       make(chan IPObservation, opts.BufferSize),
		requests:  make(chan RequestSample, opts.BufferSize),
		failureQ:  make(chan FailureSample, opts.BufferSize),
	}
}

// Start launches the single flush goroutine. It is idempotent, and calling it
// after Stop is a no-op, so the wiring in main cannot start a writer twice by
// accident.
func (w *Writer) Start() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started || w.stopped {
		return
	}
	w.started = true
	w.wg.Add(1)
	go w.run()
}

// Stop flushes whatever is buffered, within ShutdownGrace, then stops the
// goroutine. It is safe to call more than once and safe on a Writer that was
// never started (in which case it flushes the still-empty queues and returns).
//
// The final flush is the reason Stop exists rather than a bare cancel: rotation
// history and the last aggregate buckets are worth keeping if the database is
// reachable at shutdown, and worth abandoning quickly if it is not.
func (w *Writer) Stop() {
	w.mu.Lock()
	if w.stopped {
		w.mu.Unlock()
		return
	}
	w.stopped = true
	started := w.started
	w.mu.Unlock()

	if !started {
		// Never started: nothing is running, so drain-and-drop is immediate.
		w.drainAll()
		w.cancel()
		return
	}

	// Give the running goroutine a bounded chance to flush the tail.
	grace := w.opts.ShutdownGrace
	stopped := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(stopped)
	}()
	w.cancel()
	select {
	case <-stopped:
	case <-time.After(grace):
		// The goroutine is wedged (most likely on a dead database inside a
		// flush). Its context is already cancelled, so the query will abort;
		// this branch only stops us from waiting on it. Whatever it held is
		// counted as lost, which the shutdown log reports.
		w.log.Warn().Int("pending", w.pending()).
			Msg("analytics writer did not stop within the grace budget; dropping the tail")
	}
}

// Close stops the writer if it is running. The caller retains ownership of the
// pool and closes it; this exists so a deferred Close reads the same at every
// call site.
func (w *Writer) Close() { w.Stop() }

// run is the flush loop: a timer, plus a select on the context so Stop is
// observed promptly even mid-interval.
func (w *Writer) run() {
	defer w.wg.Done()
	interval := w.opts.FlushInterval
	backoff := w.opts.BackoffBase
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-w.ctx.Done():
			// Final best-effort flush on the way out, then the tail is dropped.
			w.flushOnce()
			return
		case <-ticker.C:
			if w.flushOnce() {
				backoff = w.opts.BackoffBase // a good flush resets the backoff
			} else {
				// A failed flush waits out the backoff before the next attempt,
				// so a database that is down is not hammered.
				pause := backoff
				backoff = min(backoff*2, w.opts.BackoffMax)
				if !sleepCtx(w.ctx, pause) {
					w.flushOnce()
					return
				}
			}
		}
	}
}

// flushOnce drains every queue and writes one batch of each kind. It reports
// whether the flush succeeded (no kind errored), which is what resets the
// backoff.
//
// A failure in one kind does not abandon the others: rotation history and IP
// observations are independent of request aggregates, and losing all of them
// because a request-bucket upsert failed would be a worse outcome than storing
// what did fit.
func (w *Writer) flushOnce() bool {
	attempts := drain(w.rotations, len(w.rotations))
	ips := drain(w.ips, len(w.ips))
	requests := drain(w.requests, len(w.requests))
	failures := drain(w.failureQ, len(w.failureQ))

	ok := true
	ctx, cancel := context.WithTimeout(w.ctx, 10*time.Second)
	defer cancel()

	if len(attempts) > 0 {
		if err := w.writeRotationAttempts(ctx, attempts); err != nil {
			w.writeFailures.Add(1)
			ok = false
			w.log.Warn().Err(err).Int("events", len(attempts)).
				Msg("analytics: rotation history flush failed; the batch is dropped (it is not retried, and history is best-effort)")
		} else {
			w.rotationsWritten.Add(uint64(len(attempts)))
			w.flushes.Add(1)
		}
	}
	if len(ips) > 0 {
		if err := w.writeIPObservations(ctx, ips); err != nil {
			w.writeFailures.Add(1)
			ok = false
			w.log.Warn().Err(err).Int("events", len(ips)).
				Msg("analytics: IP history flush failed; the batch is dropped (history is best-effort)")
		} else {
			w.ipsWritten.Add(uint64(len(ips)))
			w.flushes.Add(1)
		}
	}
	if len(requests) > 0 {
		if err := w.writeRequestAggregates(ctx, requests); err != nil {
			w.writeFailures.Add(1)
			ok = false
			w.log.Warn().Err(err).Int("buckets", len(requests)).
				Msg("analytics: request aggregate flush failed; the deltas are dropped (counters are best-effort)")
		} else {
			w.requestsWritten.Add(uint64(len(requests)))
			w.flushes.Add(1)
		}
	}
	if len(failures) > 0 {
		if err := w.writeFailureEvents(ctx, failures); err != nil {
			w.writeFailures.Add(1)
			ok = false
			w.log.Warn().Err(err).Int("buckets", len(failures)).
				Msg("analytics: failure event flush failed; the deltas are dropped (counters are best-effort)")
		} else {
			w.failuresWritten.Add(uint64(len(failures)))
			w.flushes.Add(1)
		}
	}
	return ok
}

// pending reports how many samples are buffered right now, for the shutdown
// log line. A racy read, and deliberately so: it is a diagnostic, not a
// correctness input, and locking the four channels to obtain it would put a
// contended lock on the shutdown path.
func (w *Writer) pending() int {
	return len(w.rotations) + len(w.ips) + len(w.requests) + len(w.failureQ)
}

// RecordRotationAttempt enqueues one rotation attempt. It never blocks. An
// attempt whose event id is zero is refused (and logged) rather than stored:
// it would collide with every other zero id.
//
// A full queue drops the oldest attempt so the most recent history survives, and
// counts the drop. Rotation history is the substrate's headline value, so it
// gets its own generous default buffer and, unlike the counters, a drop is
// logged rather than only counted.
func (w *Writer) RecordRotationAttempt(a RotationAttempt) bool {
	if a.EventID.IsZero() {
		w.log.Warn().Msg("analytics: rotation attempt with no event id was refused")
		return false
	}
	queued, dropped := w.offerRotation(a)
	if dropped != 0 {
		w.rotationsDropped.Add(dropped)
		// Rotation history is sparse, operator-facing evidence of a provider
		// transition — unlike high-volume request samples, every loss is worth
		// making visible immediately. The record itself is deliberately omitted:
		// route identity and provider detail must never move from durable data
		// into a log line just because the queue overflowed.
		w.log.Warn().Uint64("dropped", dropped).Msg("analytics: rotation history queue overflow; observation discarded")
	}
	return queued
}

// RecordIPObservation enqueues one egress-IP observation, dropping the oldest
// on overflow. It never blocks.
func (w *Writer) RecordIPObservation(o IPObservation) bool {
	if o.IP == "" {
		// An observation with no address is not an observation. The engine never
		// produces one (a probe that cannot parse an IP fails instead), so this
		// is a guard rather than a path.
		return false
	}
	queued, dropped := offer(w.ips, o)
	w.ipsDropped.Add(dropped)
	return queued
}

// ObserveRequest enqueues a rolled-up request sample, dropping the oldest on
// overflow. It never blocks, and it is the only method the serving path calls.
func (w *Writer) ObserveRequest(s RequestSample) bool {
	queued, dropped := offer(w.requests, s)
	w.requestsDropped.Add(dropped)
	return queued
}

// ObserveFailure enqueues a bucketed failure sample, dropping the oldest on
// overflow. It never blocks.
func (w *Writer) ObserveFailure(s FailureSample) bool {
	if s.Failures <= 0 {
		return false
	}
	queued, dropped := offer(w.failureQ, s)
	w.failuresDropped.Add(dropped)
	return queued
}

// offerRotation enqueues a rotation attempt, evicting the oldest when full.
// See offer for the distinction between whether the new observation was queued
// and how many observations the operation lost.
func (w *Writer) offerRotation(a RotationAttempt) (queued bool, dropped uint64) {
	return offer(w.rotations, a)
}

// offer enqueues onto a channel, evicting the oldest when full. It returns two
// independent facts: whether value was queued, and how many observations the
// operation lost.
//
// A full queue that evicts the oldest and queues value succeeds for the caller —
// the newest observation, the one an operator debugging the current event needs,
// survives — but it has still lost the evicted observation. Its result is
// (true, 1). Conflating those facts is how the original code made /status report
// zero drops while durable history was being silently discarded.
//
// The rare producer race after an eviction can lose both observations: the
// oldest was removed, then another producer filled the freed slot before this
// send could queue value. That result is (false, 2). Every return path is
// non-blocking; database slowness must cost bounded history, never request
// latency.
func offer[T any](ch chan T, value T) (queued bool, dropped uint64) {
	// Fast path: room in the queue.
	select {
	case ch <- value:
		return true, 0
	default:
	}
	// Full: evict the oldest to make room for the newest. The non-blocking
	// receive guard means an empty queue (raced with the flusher) simply falls
	// through to a second send attempt below.
	select {
	case <-ch:
		select {
		case ch <- value:
			return true, 1
		default:
			// The flusher drained the queue between the eviction and this send;
			// both the evicted oldest observation and value are lost.
			return false, 2
		}
	default:
		select {
		case ch <- value:
			return true, 0
		default:
			// No observation was removed by this call, but value could not be
			// queued — count the refused new observation.
			return false, 1
		}
	}
}

// drain empties a channel into a slice of at most max entries, using the
// two-value receive so it stops on an empty queue rather than spinning.
func drain[T any](ch chan T, max int) []T {
	if max == 0 {
		return nil
	}
	out := make([]T, 0, max)
	for i := 0; i < max; i++ {
		select {
		case v := <-ch:
			out = append(out, v)
		default:
			return out
		}
	}
	return out
}

// drainAll empties every queue and returns the total, discarding the samples.
// Used only on a Stop of a writer that never started, and on a writer whose
// goroutine is wedged past the grace budget (via the shutdown warning path).
func (w *Writer) drainAll() int {
	total := 0
	for _, n := range []int{
		len(drain(w.rotations, len(w.rotations))),
		len(drain(w.ips, len(w.ips))),
		len(drain(w.requests, len(w.requests))),
		len(drain(w.failureQ, len(w.failureQ))),
	} {
		total += n
	}
	return total
}

// Count reports a snapshot of the writer's accounting. Every dropped counter is
// the honest cost of never blocking a request, and a deployment that shows
// drops has a writer that cannot keep up with its traffic or a database that is
// too slow — both are operator-actionable signals, which is why they are counted
// at all rather than discarded quietly.
func (w *Writer) Count() Count {
	return Count{
		RotationAttempts:        w.rotationsWritten.Load(),
		IPObservations:          w.ipsWritten.Load(),
		RequestSamples:          w.requestsWritten.Load(),
		FailureSamples:          w.failuresWritten.Load(),
		DroppedRotationAttempts: w.rotationsDropped.Load(),
		DroppedIPObservations:   w.ipsDropped.Load(),
		DroppedRequestSamples:   w.requestsDropped.Load(),
		DroppedFailureSamples:   w.failuresDropped.Load(),
		Flushes:                 w.flushes.Load(),
		Failures:                w.writeFailures.Load(),
	}
}

// ---------------------------------------------------------------- SQL writers

// writeRotationAttempts inserts a batch of rotation attempts. Each INSERT is
// ON CONFLICT (event_id) DO NOTHING, so a batch re-presented after a partial
// failure adds only the rows the previous attempt did not land. The canonical
// IPs are computed here, at the last possible moment, so a caller cannot store
// an uncanonical address even by accident.
func (w *Writer) writeRotationAttempts(ctx context.Context, attempts []RotationAttempt) error {
	if len(attempts) == 0 {
		return nil
	}
	const q = `
		INSERT INTO rotation_history (
			event_id, instance, route_host, route_kind, route_origin, mode,
			rotation_epoch, started_at, ended_at, duration_ms, outcome,
			failure_kind, baseline_ip, observed_ip, api_attempts,
			probe_attempts, config_revision, consecutive_same_ip
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		ON CONFLICT (event_id) DO NOTHING`
	batch := &pgx.Batch{}
	queued := 0
	for _, a := range attempts {
		if a.EventID.IsZero() {
			// Defensive: RecordRotationAttempt already refused these, so this can
			// only be reached by a direct call. Skipping is right — inserting an
			// empty id would collide with every other empty id.
			continue
		}
		baseline, err := optionalIP(a.BaselineIP)
		if err != nil {
			// An unparseable IP is a caller bug, not a transient failure. Skip
			// the row rather than failing the whole batch, so one bad attempt
			// does not cost the history of every other route in it.
			w.log.Warn().Err(err).Msg("analytics: rotation attempt with an unparseable IP was skipped")
			continue
		}
		observed, err := optionalIP(a.ObservedIP)
		if err != nil {
			w.log.Warn().Err(err).Msg("analytics: rotation attempt with an unparseable IP was skipped")
			continue
		}
		queued++
		batch.Queue(q,
			string(a.EventID), a.Instance, a.Route.Host, a.Route.Kind, a.Route.Origin,
			a.Mode, int64(a.RotationEpoch), a.StartedAt, a.EndedAt,
			a.Duration().Milliseconds(), string(a.Outcome), a.FailureKind,
			nullableInet(baseline), nullableInet(observed),
			a.APIAttempts, a.ProbeAttempts, nullableInt8(a.ConfigRevision), a.ConsecutiveSameIP,
		)
	}
	return w.execBatch(ctx, batch, queued)
}

// writeIPObservations inserts a batch of IP observations, ON CONFLICT DO
// NOTHING against the observation primary key. The egress IP is canonicalized
// through Unmap before it is bound to the inet column and before the
// human-readable twin is derived, so the two always agree.
func (w *Writer) writeIPObservations(ctx context.Context, observations []IPObservation) error {
	if len(observations) == 0 {
		return nil
	}
	const q = `
		INSERT INTO ip_history (
			route_host, route_kind, route_origin, egress_ip, observed_at,
			source, revisit, rotation_epoch, instance, egress_ip_text
		) VALUES ($1,$2,$3,$4::inet,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (route_host, route_kind, observed_at, egress_ip) DO NOTHING`
	batch := &pgx.Batch{}
	queued := 0
	for _, o := range observations {
		canonical, err := canonicalizeIP(o.IP)
		if err != nil {
			w.log.Warn().Err(err).Msg("analytics: IP observation with an unparseable address was skipped")
			continue
		}
		queued++
		batch.Queue(q,
			o.Route.Host, o.Route.Kind, o.Route.Origin, canonical, o.ObservedAt,
			string(o.Source), o.Revisit, int64(o.RotationEpoch), o.Instance, canonical,
		)
	}
	return w.execBatch(ctx, batch, queued)
}

// writeRequestAggregates upserts a batch of request deltas. Each row ADDs its
// counters to whatever the bucket already holds (ON CONFLICT DO UPDATE), so
// repeated flushes of the same bucket accumulate rather than replace. The
// values written are deltas since the previous flush, and each delta leaves the
// queue exactly once, so a delta is never added twice by this process.
func (w *Writer) writeRequestAggregates(ctx context.Context, samples []RequestSample) error {
	if len(samples) == 0 {
		return nil
	}
	const q = `
		INSERT INTO request_aggregates (
			bucket_start, route_host, route_kind, route_origin, listener,
			family, requests, successes, failures, to_client_bytes,
			to_upstream_bytes, instance
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (bucket_start, route_host, route_kind, listener, family)
		DO UPDATE SET
			requests             = request_aggregates.requests             + EXCLUDED.requests,
			successes            = request_aggregates.successes            + EXCLUDED.successes,
			failures             = request_aggregates.failures             + EXCLUDED.failures,
			to_client_bytes      = request_aggregates.to_client_bytes      + EXCLUDED.to_client_bytes,
			to_upstream_bytes    = request_aggregates.to_upstream_bytes    + EXCLUDED.to_upstream_bytes,
			instance             = EXCLUDED.instance,
			updated_at           = now()`
	batch := &pgx.Batch{}
	queued := 0
	for _, s := range samples {
		queued++
		batch.Queue(q,
			bucketOf(s.BucketStart, w.opts.BucketWidth),
			s.Route.Host, s.Route.Kind, s.Route.Origin, s.Listener, s.Family,
			s.Requests, s.Successes, s.Failures,
			s.ToClientBytes, s.ToUpstreamBytes, s.Instance,
		)
	}
	return w.execBatch(ctx, batch, queued)
}

// writeFailureEvents upserts a batch of failure deltas, adding to the bucket
// like the request aggregates do. The target host is host-only by the time it
// reaches here (the caller passes the same value the logs use), and the
// migration's CHECK refuses a userinfo-shaped value as a second line of defense.
func (w *Writer) writeFailureEvents(ctx context.Context, samples []FailureSample) error {
	if len(samples) == 0 {
		return nil
	}
	const q = `
		INSERT INTO failure_events (
			bucket_start, route_host, route_kind, error_kind, target_host,
			listener, family, failures, instance
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (bucket_start, route_host, route_kind, error_kind, target_host, listener, family)
		DO UPDATE SET
			failures   = failure_events.failures + EXCLUDED.failures,
			instance   = EXCLUDED.instance,
			updated_at = now()`
	batch := &pgx.Batch{}
	queued := 0
	for _, s := range samples {
		queued++
		batch.Queue(q,
			bucketOf(s.BucketStart, w.opts.BucketWidth),
			s.Route.Host, s.Route.Kind, s.ErrorKind, s.TargetHost,
			s.Listener, s.Family, s.Failures, s.Instance,
		)
	}
	return w.execBatch(ctx, batch, queued)
}

// execBatch runs a pgx batch, reporting the first error but having queued (and
// thus attempted) every statement. A partial success is fine: the event tables
// dedupe on replay and the aggregate tables add deltas that this process will
// not re-present, so the next flush continues from wherever the batch left off.
func (w *Writer) execBatch(ctx context.Context, batch *pgx.Batch, queued int) error {
	results := w.pool.SendBatch(ctx, batch)
	var firstErr error
	// queued is the number of statements this batch carries. pgx.Batch exposes
	// no length, so each writer counts as it queues and passes the total here;
	// the loop must consume exactly one result per queued statement.
	for range queued {
		if _, err := results.Exec(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// Close releases the batch's connection regardless of the statement errors.
	if err := results.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	if firstErr != nil {
		return fmt.Errorf("analytics batch write: %w", firstErr)
	}
	return nil
}

// nullableInet renders an optional canonical address for an inet column. An
// absent address binds NULL, which the rotation_history schema allows and which
// means "this attempt learned no IP" — not an empty address.
func nullableInet(canonical string) any {
	if canonical == "" {
		return nil
	}
	return canonical
}

// nullableInt8 renders an optional revision. Zero means "this instance is on its
// local seed file", which is stored as NULL rather than as revision 0, so a
// reader can tell "no durable revision" from "the store's first revision".
func nullableInt8(revision int64) any {
	if revision <= 0 {
		return nil
	}
	return revision
}

// ---------------------------------------------------------------- identities

// newEventID mints one observation's stable identity from crypto/rand, the
// only entropy source this repository uses (the semgrep security gate rejects
// every math/rand variant, v2 included).
//
// The encoding is base32 with no padding over 16 random bytes: 26 characters,
// URL-safe and log-safe by construction, and long enough that two ids minted in
// the same process collide with negligible probability. The "a-" prefix marks it
// as analytics-minted, distinguishing it from the proxyserver's "r-" request
// correlation ids, which are a different namespace for a different purpose.
func newEventID() EventID {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// crypto/rand does not fail on any supported platform, but a degraded
		// id must still be unique within the process or a retry would not
		// dedupe. The monotonic suffix guarantees that even if the CSPRNG is
		// unavailable, at the cost of cross-instance uniqueness for the rare id.
		return EventID("a-degraded-" + strconv.FormatUint(degradedEventIDs.Add(1), 10))
	}
	return EventID("a-" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:]))
}

// degradedEventIDs backs the fallback id above so a process with a broken
// CSPRNG still produces distinct ids, which is what keeps a retry idempotent
// even in that degraded case.
var degradedEventIDs atomic.Uint64

// NewEventID mints one stable observation identity. Callers mint once per
// observation and reuse the value across every retry, which is what makes a
// write idempotent.
func NewEventID() EventID { return newEventID() }

// ---------------------------------------------------------------- helpers

// sleepCtx waits for d, reporting false if ctx ended first. Used by the flush
// loop's backoff so a Stop during a backoff is observed immediately.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// ErrWriterStopped reports an enqueue against a writer that has been stopped.
// The writer's Record* methods do not return an error — they are called from
// paths that must not branch on analytics — so this is retained for the tests
// and for any future caller that wants to distinguish "dropped" from "closed".
var ErrWriterStopped = errors.New("analytics writer is stopped")
