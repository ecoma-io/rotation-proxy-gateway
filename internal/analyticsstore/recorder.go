package analyticsstore

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// Recorder is the whole durable-analytics surface the rest of the gateway sees.
//
// It exists as its own type, and a nil *Recorder is the disabled state, so that
// "analytics is off" costs one nil check per call and starts no goroutine,
// opens no connection, and reads no configuration. Every method is safe to call
// on a nil receiver, which is what lets the serving path call RecordRequest
// unconditionally instead of branching on whether the operator configured a
// DSN — a branch on the request path is exactly the kind of thing that later
// grows into work nobody benchmarked.
//
// With a DSN configured, a Recorder wraps a started Writer. Without one, New
// returns nil and every call is a no-op. That is the mode the e2e suite runs
// in, and it is why adding this package changed nothing it measures.
type Recorder struct {
	writer   *Writer
	instance string
	enabled  atomic.Bool
}

// Instance names this process in every row it writes, so a cluster's history
// says which replica produced which observation. A blank name falls back to the
// hostname, and a hostname that cannot be read falls back to a fixed label: the
// column is NOT NULL, and an unnamed instance is better than a failed batch.
func Instance() string {
	name, err := os.Hostname()
	if err != nil || strings.TrimSpace(name) == "" {
		return "unknown"
	}
	// The hostname reaches a durable row and an operator's SQL, so it is
	// bounded and stripped of anything control-shaped here rather than trusted.
	return sanitizeInstance(name)
}

// sanitizeInstance bounds an instance label to a single safe line.
func sanitizeInstance(name string) string {
	const max = 128
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)
	if len(cleaned) > max {
		cleaned = cleaned[:max]
	}
	if cleaned == "" {
		return "unknown"
	}
	return cleaned
}

// NewRecorder builds the analytics surface. A blank dsn returns a nil
// *Recorder and no error: analytics is off by default, and that is a
// configuration state, not a failure.
//
// A non-blank dsn opens the pool, migrates the schema, and returns a Recorder
// wrapping a started Writer plus a release function that stops the writer and
// closes the pool. A migration failure is returned rather than worked around:
// serving against a schema this build does not expect is refused, the same rule
// the configuration substrate applies.
func NewRecorder(ctx context.Context, dsn, instance string, log zerolog.Logger, opts WriterOptions) (*Recorder, func(), error) {
	if dsn == "" {
		return nil, func() {}, nil
	}
	pool, err := openPool(ctx, dsn)
	if err != nil {
		return nil, nil, err
	}
	if err := Migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, nil, err
	}
	writer := NewWriter(pool, log, opts)
	writer.Start()
	r := &Recorder{writer: writer, instance: instance}
	r.enabled.Store(true)
	return r, func() {
		writer.Stop()
		pool.Close()
	}, nil
}

// openPool dials a DSN and verifies it answers.
//
// The DSN is a secret — it commonly carries the database password. It is passed
// to pgx and never retained here, formatted into an error, or logged; the
// errors below are pgx's own, which name a host and database but not a password.
func openPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		// pgx's parse error names the offending keyword, never the value.
		return nil, fmt.Errorf("parse analytics store DSN: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open analytics store: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("analytics store unreachable: %w", err)
	}
	return pool, nil
}

// Enabled reports whether any durable store is configured. It exists for the
// one place that must branch — /status, so an operator can tell a gateway with
// no analytics from one whose analytics is merely quiet.
func (r *Recorder) Enabled() bool { return r != nil && r.enabled.Load() }

// Count reports the writer's accounting, or the zero Count when disabled. A
// disabled recorder reports zeros rather than anything else, so /status can
// show the field unconditionally.
func (r *Recorder) Count() Count {
	if !r.Enabled() {
		return Count{}
	}
	return r.writer.Count()
}

// Instance reports the instance name rows are stamped with.
func (r *Recorder) Instance() string {
	if r == nil {
		return ""
	}
	return r.instance
}

// BucketNow truncates t to the current aggregation window, so a caller
// accumulating in-process counters can label them with the bucket they belong
// to without knowing the width.
func (r *Recorder) BucketNow(t time.Time) time.Time {
	// A Recorder with no writer is the disabled configuration — NewRecorder
	// returns nil, and callers hold the nil *Recorder — but the zero-value
	// &Recorder{} is reachable too. Guarding only r would nil-dereference
	// r.writer.opts, and bucketing needs no database, so an inert recorder must
	// still hand back the instant it was given rather than take the caller down.
	if r == nil || r.writer == nil {
		return t
	}
	return bucketOf(t, r.writer.opts.BucketWidth)
}

// RecordRotationAttempt hands one completed rotation attempt to the writer. A
// nil recorder discards it.
func (r *Recorder) RecordRotationAttempt(a RotationAttempt) {
	if !r.Enabled() {
		return
	}
	if a.Instance == "" {
		a.Instance = r.instance
	}
	r.writer.RecordRotationAttempt(a)
}

// RecordIPObservation hands one egress-IP observation to the writer. A nil
// recorder discards it.
func (r *Recorder) RecordIPObservation(o IPObservation) {
	if !r.Enabled() {
		return
	}
	if o.Instance == "" {
		o.Instance = r.instance
	}
	r.writer.RecordIPObservation(o)
}

// RecordRequest hands one rolled-up request sample to the writer. This is the
// only method the serving path calls, and on a nil recorder it returns
// immediately — the hot path's entire cost when analytics is off.
func (r *Recorder) RecordRequest(s RequestSample) {
	if !r.Enabled() {
		return
	}
	if s.Instance == "" {
		s.Instance = r.instance
	}
	r.writer.ObserveRequest(s)
}

// RecordFailure hands one bucketed failure sample to the writer. A nil
// recorder discards it.
func (r *Recorder) RecordFailure(s FailureSample) {
	if !r.Enabled() {
		return
	}
	if s.Instance == "" {
		s.Instance = r.instance
	}
	r.writer.ObserveFailure(s)
}

// Stop flushes and stops the writer, bounded by its shutdown grace. A nil
// recorder's Stop does nothing, so the deferred call in main needs no branch.
func (r *Recorder) Stop() {
	if !r.Enabled() {
		return
	}
	r.writer.Stop()
}
