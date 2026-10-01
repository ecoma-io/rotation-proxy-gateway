// Package control reconciles the durable configuration into the local serving
// generation.
//
// The reconciler is the defensive half of the durable store. Everything it
// reads is untrusted input, including what a peer instance wrote and including
// what this process itself wrote moments ago: a revision is a claim, and the
// claim is checked by decoding and validating it against the same rules a
// hand-written configuration file must satisfy. Nothing reaches the serving
// path without passing that check.
//
// The materialization order is fixed and normative (docs/architecture.md):
//
//	committed durable revision
//	        ↓
//	load and validate complete candidate
//	        ↓
//	build immutable configuration + pool + router generation
//	        ↓
//	atomic local publication
//
// A failure anywhere before the last step leaves the previous generation
// serving, untouched. There is no partial application: a document that fails on
// route 7 of 20 never publishes a 6-route pool.
package control

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/configstore"
	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/sanitize"

	"github.com/rs/zerolog"
)

// DefaultReconcileInterval is how often the reconciler polls the active
// revision. Polling rather than notification is deliberate and is the same
// trade the configuration file poller made: a bounded interval keeps the
// failure mode "an instance converges within one interval of the write" instead
// of "an instance diverges forever if a notification is lost". A control-plane
// write is an operator action measured in tens of seconds, not a per-request
// decision, so the latency is free.
const DefaultReconcileInterval = time.Second

// Backoff bounds. A failure backs off rather than spinning: the most common
// persistent failure is a document this build refuses (a too-new version, an
// invalid route), and retrying that every second turns a stale-but-serving
// instance into a log flood. The ceiling keeps convergence eventually.
const (
	initialBackoff = 250 * time.Millisecond
	maxBackoff     = 30 * time.Second
)

// Reconciler keeps the local serving generation in step with the durable active
// revision.
//
// One instance runs one reconciler. applyMu serializes every publication, so
// local reconciliation and a control-plane write — which arrive through
// different paths but converge on the same store — cannot race to build two
// generations from contradictory views. Everything else in this type is
// concurrency-safe.
type Reconciler struct {
	store configstore.Repository
	pool  *pool.Store
	log   zerolog.Logger

	// applyMu is the single-writer gate around materialization. It is held
	// across read-validate-build-publish as one critical section, so two
	// callers cannot interleave a read of one revision with a publication of
	// another and leave the serving generation behind the store.
	applyMu sync.Mutex

	// interval and backoff are fields rather than constants so tests can drive
	// the loop without sleeping through production backoff.
	interval time.Duration
	now      func() time.Time

	// notifyMu guards notify, the post-publication hook. It is separate from
	// applyMu because the hook runs after the lock is released: a subscriber
	// that takes its own locks must never run while the single-writer gate is
	// held, or a slow subscriber would stall every subsequent materialization.
	notifyMu sync.Mutex
	notify   func(*config.RuntimeConfig)

	// observed is the durable store's last active-pointer observation. It is
	// deliberately separate from pool.ConfigRevision: the latter says what this
	// instance is serving, while this one says what the reconciler last saw the
	// cluster point at. /status reads the two from memory so it can truthfully
	// show a convergence window without turning its unauthenticated endpoint into
	// a control-database query amplifier.
	//
	// It is written on every completed Active read — before Apply, including an
	// invalid revision that Apply refuses — so an operator can tell "the cluster
	// moved but this instance rejected it" from "the cluster did not move".
	// NoRevision is represented as zero.
	observed atomic.Int64
}

// Subscribe registers a callback invoked after each successful publication, with
// the configuration now serving. It exists for the process-global effects of a
// configuration change — the log level and the kind-listener warnings — which
// the reconciler itself must not own.
//
// The callback receives only validated, already-published configurations: a
// rejected revision never invokes it, so a subscriber cannot observe a
// configuration the gateway refused to serve. A nil callback clears the hook.
// Registration after Run has started is safe, and a subscriber set after boot
// still sees every later publication.
func (r *Reconciler) Subscribe(fn func(*config.RuntimeConfig)) {
	r.notifyMu.Lock()
	defer r.notifyMu.Unlock()
	r.notify = fn
}

// ObservedRevision is the durable active revision this reconciler most recently
// read, or zero when it has not observed an active revision yet.
//
// It is intentionally a cached observation rather than a store read. The
// unauthenticated /status handler needs to distinguish the revision serving in
// this process from the cluster pointer it is converging toward, but asking the
// database on every status request would turn an operational endpoint into a
// query amplifier. ReconcileOnce updates the observation on every completed
// Active read, even when the candidate fails validation and cannot be served.
func (r *Reconciler) ObservedRevision() int64 { return r.observed.Load() }

// announce reports a published configuration to the subscriber, if any. It is
// called with applyMu held but takes only notifyMu, which no other path holds
// while waiting for applyMu — so a subscriber that calls back into the
// reconciler cannot deadlock, and a slow hook delays only its own caller, never
// a concurrent publication that has already committed.
func (r *Reconciler) announce(cfg *config.RuntimeConfig) {
	r.notifyMu.Lock()
	fn := r.notify
	r.notifyMu.Unlock()
	if fn != nil {
		fn(cfg)
	}
}

// Options configures a Reconciler. The zero value of each duration field takes
// its documented default, so a caller need only set what it wants to change.
type Options struct {
	// Interval is the poll period. Zero takes DefaultReconcileInterval.
	Interval time.Duration
}

// NewReconciler builds a reconciler over a store and the generation store it
// publishes into. It panics on nil inputs: a reconciler that cannot read or
// cannot publish would silently do nothing, which is the failure this type
// exists to prevent.
func NewReconciler(repo configstore.Repository, generations *pool.Store, log zerolog.Logger, opts Options) *Reconciler {
	if repo == nil {
		panic("control: NewReconciler requires a non-nil config store")
	}
	if generations == nil {
		panic("control: NewReconciler requires a non-nil pool store")
	}
	interval := opts.Interval
	if interval <= 0 {
		interval = DefaultReconcileInterval
	}
	return &Reconciler{
		store:    repo,
		pool:     generations,
		log:      log,
		interval: interval,
		now:      time.Now,
	}
}

// Run reconciles until ctx is canceled. It performs one immediate pass before
// waiting, so a fresh start does not spend a full interval serving the seed
// configuration after the durable store already holds a newer revision.
func (r *Reconciler) Run(ctx context.Context) {
	backoff := time.Duration(0)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		if backoff > 0 {
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		err := r.ReconcileOnce(ctx)
		switch {
		case err == nil:
			backoff = 0
		case ctx.Err() != nil:
			return
		default:
			// Doubling from a small base, capped: a persistent rejection
			// (an invalid document, a version this build does not implement)
			// backs off to the ceiling instead of retrying every second,
			// while a transient database failure still converges quickly.
			backoff = nextBackoff(backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// nextBackoff doubles the current delay, capped. Zero means the previous pass
// succeeded, so the next failure starts from the initial delay again — a single
// transient error never escalates the steady-state poll.
func nextBackoff(current time.Duration) time.Duration {
	if current <= 0 {
		return initialBackoff
	}
	if current >= maxBackoff/2 {
		return maxBackoff
	}
	return current * 2
}

// ReconcileOnce reads the active revision and, when it differs from what is
// serving, validates and materializes it.
//
// The error it returns is a report, not a decision: whatever it says, the
// previous generation is still serving. Callers that treat an error as fatal
// (the boot path) and callers that retry (Run) are both correct, because the
// serving state is unchanged either way.
func (r *Reconciler) ReconcileOnce(ctx context.Context) error {
	active, err := r.store.Active(ctx)
	if err != nil {
		if errors.Is(err, configstore.ErrNoActiveRevision) {
			// Nothing committed yet. The serving generation is whatever the seed
			// produced, which is the correct thing to keep serving: an empty
			// store is not a reason to stop proxying. The zero observation tells
			// /status there is no active cluster pointer to converge on.
			r.observed.Store(0)
			r.log.Debug().Msg("config store has no active revision; keeping the current generation")
			return nil
		}
		return fmt.Errorf("read active config revision: %w", err)
	}
	// Publish the observation before validating and materializing it. A durable
	// revision this binary cannot serve is still where the cluster points, and
	// /status must show that the replica is behind rather than report a stale
	// pointer as though it were current. This is one atomic memory write, never a
	// database read on a status request.
	r.observed.Store(int64(active.Revision))
	return r.Apply(ctx, configstore.Document{Version: active.DocVersion, JSON: active.Document}, active.Revision)
}

// Apply validates and materializes one candidate revision.
//
// The candidate is untrusted input whatever produced it. It is decoded and
// fully validated first; only a configuration that satisfies every existing
// rule reaches Store.Publish, and the store's own Publish contract requires the
// same validated value. There is no path here that publishes a partially
// checked configuration.
//
// The revision is compared against what is already serving before any work is
// done, so the steady-state poll of an unchanged configuration costs one query
// and no publication. That comparison is an optimization only: it is never what
// makes an unchanged revision safe, because a same-numbered revision is
// impossible (history is append-only and revisions only increase).
func (r *Reconciler) Apply(ctx context.Context, doc configstore.Document, revision configstore.Revision) error {
	// Held across the whole read-validate-build-publish sequence. Releasing it
	// between decode and publish would let a second writer publish a newer
	// revision in between, and this generation would then overwrite it with an
	// older configuration while reporting an older revision.
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	return r.applyLocked(ctx, doc, revision)
}

// Seed commits the first durable revision from a local configuration and applies
// it, for a store that has no active revision yet.
//
// It is the bootstrap path and it is deliberately narrow. A store that already
// has an active revision is left alone: seeding would overwrite a
// cluster-wide configuration with one instance's local file, which is exactly
// the file-as-authority behavior the durable store replaces. An instance that
// finds an existing revision does not seed — it reconciles to it.
//
// The commit is unconditional (no expected revision), which is correct for a
// first write: there is nothing to be stale against. Two instances racing to
// seed an empty store both succeed, appending two revisions, and the later
// pointer move wins — the loser's configuration is history, and every instance
// converges on the winner. That is a deliberate property of an empty store
// rather than a hazard, because seeding an empty store is a human action, not a
// concurrent one.
//
// The seed is idempotent by content: a store already serving this exact
// document is left untouched, so a restart cannot append a duplicate revision
// on every boot.
func (r *Reconciler) Seed(ctx context.Context, cfg *config.RuntimeConfig) (configstore.Revision, error) {
	if cfg == nil {
		return 0, errors.New("seeding requires a non-nil configuration")
	}
	r.applyMu.Lock()
	defer r.applyMu.Unlock()

	active, err := r.store.Active(ctx)
	switch {
	case err == nil:
		// Already seeded. Converge on what is there rather than overwriting it.
		// Record the pointer first for the same reason ReconcileOnce does: a
		// durable revision that cannot be materialized is still the cluster's
		// active revision, and the status cache must not make it disappear.
		r.observed.Store(int64(active.Revision))
		if err := r.applyLocked(ctx, configstore.Document{Version: active.DocVersion, JSON: active.Document}, active.Revision); err != nil {
			return active.Revision, err
		}
		return active.Revision, nil
	case !errors.Is(err, configstore.ErrNoActiveRevision):
		return 0, fmt.Errorf("read active config revision: %w", err)
	}

	doc, err := configstore.NewDocument(cfg)
	if err != nil {
		return 0, err
	}
	// An empty document must never be committed, so a first revision always
	// carries a real configuration.
	record, err := r.store.Commit(ctx, configstore.NoRevision, doc, configstore.Meta{
		Author: "seed",
		Note:   "initial configuration seeded from the local configuration file",
	})
	if err != nil {
		return 0, fmt.Errorf("seed initial config revision: %w", err)
	}
	// The commit moved the durable pointer. Preserve that fact before applying:
	// should validation ever reject the just-written document, /status must show
	// the pointer this instance is behind rather than pretend it is still at the
	// previous revision.
	r.observed.Store(int64(record.Revision))
	if err := r.applyLocked(ctx, doc, record.Revision); err != nil {
		return record.Revision, err
	}
	r.log.Info().Int64("revision", int64(record.Revision)).Msg("seeded initial durable configuration revision")
	return record.Revision, nil
}

// applyLocked is Apply's body with applyMu already held, and the one place a
// generation is ever published from a durable document.
//
// Everything between the decode and the publication is deliberately absent: no
// partial application, no best-effort route set, no fallback to the previously
// decoded configuration. The decode is total, so either it produced a
// configuration that satisfies every rule or there is nothing to publish.
func (r *Reconciler) applyLocked(ctx context.Context, doc configstore.Document, revision configstore.Revision) error {
	current := r.pool.Load()
	if revision.IsValid() && current.ConfigRevision == int64(revision) {
		return nil
	}

	// Untrusted input, treated as such: the decode applies every route, routing,
	// rotation, and warm-pool rule, and rejects an unknown or too-new document
	// version before reading a field. Its errors never quote document content —
	// a document holds route credentials and rotate-API headers.
	cfg, err := configstore.Decode(doc)
	if err != nil {
		return fmt.Errorf("durable revision %d is not a valid configuration: %s", int64(revision), sanitize.ErrorString(err))
	}

	// Publish swaps one immutable generation atomically. Reconfigure inside it
	// retains every route whose canonical URL+kind+origin is unchanged, so a
	// revision that renames an operator-facing route id — or changes only the
	// log level — keeps all route health, cooldowns, and rotation state.
	//
	// The revision is recorded on the generation rather than used to build it:
	// it is metadata of what is serving, never an input to route identity.
	r.pool.PublishRevision(cfg, int64(revision))

	// The subscriber runs after the publication and outside applyMu, so a slow
	// hook cannot delay the next reconcile tick and cannot observe a generation
	// that was never published. It is called here rather than by each caller so
	// there is exactly one path from a published generation to the process-wide
	// effects of a configuration change — the log level among them, which must
	// follow the revision that set it.
	//
	// Only validated, already-published configurations reach it: a rejected
	// revision returns above before this point.
	r.announce(cfg)

	r.log.Info().
		Int64("revision", int64(revision)).
		Str("document_version", fmt.Sprint(doc.Version)).
		Int("upstreams", len(cfg.AllRoutes())).
		Bool("routing", cfg.Routing != nil).
		Msg("durable configuration revision applied")
	return nil
}
