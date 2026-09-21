// Package warmpool maintains a bounded pool of half-established upstream
// SOCKS5 connections — TCP dialed, greeting and method/auth negotiated,
// CONNECT not sent — so a serving request can swap its outbound dial for a
// ready connection reusable with any target.
//
// The pool is strictly background: requests never wait on it (Borrow is a
// non-blocking pop that returns nil on any miss, and the caller then dials
// cold exactly as before the pool existed), and it never writes route
// health — cooldown, auth, and rotation state change only on the request
// path. Rotation isolation is enforced by epoch stamping: every warm
// connection records the route's rotation epoch as it was BEFORE its dial
// began, and a rotation bumps the route epoch at BeginRotation, so a
// connection that straddled a rotation — or was parked before one — can
// never be borrowed into the new egress generation.
//
// Lock and lifecycle invariants, kept so the pool cannot deadlock or leak:
//
//   - wp.mu is a leaf lock. No pool lock, no I/O, and no wait happens under
//     it. The sweeper collects the live route-pointer set (RoutePointers
//     takes the pool lock) BEFORE acquiring wp.mu, so the two never nest.
//   - Borrow touches only Proxy atomics (RotatingNow and friends) and never
//     takes a pool lock.
//   - The wake channel is never closed — a send racing a close would panic
//     on the request path; workers exit on the context alone.
//   - Stop closes ready connections under mu, then waits for workers outside
//     the lock with a bounded timeout: a worker deep in a slow dial unwinds
//     at its stage deadline, and the post-dial stopped check discards
//     anything it finishes afterwards.
package warmpool

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/url"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/socksdial"
)

// Sweep cadence and teardown bounds. The sweep is level-triggered: a dropped
// wake token costs at most one interval because every tick re-derives the
// deficits from scratch — do not replace that with hint-only replenishment.
const (
	sweepInterval = time.Second
	stopWaitLimit = time.Second
)

// Per-route backoff for replenish dials that keep failing: doubling from 1s
// capped at 8s, with ±10% jitter. The worker count is the hard ceiling on
// concurrent dials toward any endpoint; the backoff keeps a dead one from
// pinning them cycle after cycle.
const (
	warmBackoffBase = time.Second
	warmBackoffMax  = 8 * time.Second
)

// DialHalfFunc dials one half connection; socksdial.DialHalf in production
// and a scriptable stand-in in tests.
type DialHalfFunc func(ctx context.Context, pu *url.URL, timeout time.Duration) (*socksdial.HalfConn, error)

// Pool is the warm-connection pool over one route store. It is created once
// per process and stopped exactly once at shutdown.
type Pool struct {
	store *pool.Store
	log   zerolog.Logger
	dial  DialHalfFunc

	ctx    context.Context
	cancel context.CancelFunc

	// mu guards buckets, stopped, and the worker count; see the package
	// comment for the leaf-lock contract.
	mu      sync.Mutex
	buckets map[*pool.Proxy]*routeBucket
	stopped bool
	started bool
	workers int

	// wake coalesces replenish wakeups toward workers (capacity 1). Never
	// closed. sweepWake is the request-path nudge to the sweeper: a borrow
	// opened a deficit, so run a sweep pass now instead of at the next tick.
	// Both are capacity 1 and never closed.
	wake      chan struct{}
	sweepWake chan struct{}

	// sweepEvery is the level-triggered cadence; 1s in production, stretched
	// by tests that must prove wakeups work without a tick landing by luck.
	sweepEvery time.Duration

	wg sync.WaitGroup

	// Monotonic lifecycle counters — Phase-2 instrumentation surfaced by
	// Snapshot. Gauges (idle counts) are derived from bucket state under mu
	// rather than kept as separately-decremented atomics, which drift.
	created               atomic.Uint64
	borrowed              atomic.Uint64
	discardedStale        atomic.Uint64
	discardedOverflow     atomic.Uint64
	generationInvalidated atomic.Uint64
	connectFailed         atomic.Uint64
	replenishAttempts     atomic.Uint64
	dialing               atomic.Int64
}

// routeBucket is one route's slice of the pool. Fields are guarded by Pool.mu;
// the dials themselves run outside the lock.
type routeBucket struct {
	p *pool.Proxy

	// ready holds parked half connections, oldest first.
	ready []*warmConn

	// pending counts deficits the sweeper scheduled that no worker has
	// claimed yet, so bursts of wakeups do not become thundering-herd dials.
	pending int

	// failStreak/backoffUntil slow replenishment after dial failures.
	failStreak   int
	backoffUntil time.Time

	// authBroken stops replenishment for a route whose endpoint rejects the
	// route's credentials at the half stage. It clears when the rotation
	// epoch moves (manual routes get a fresh endpoint per rotation); auto
	// routes keep it forever, which is correct — the credentials cannot fix
	// themselves. Route health is never touched from here.
	authBroken      bool
	authBrokenEpoch uint64
}

// warmConn is one parked half connection. The rotation epoch is the one the
// route carried BEFORE the dial began — never re-read after the dial — so a
// rotation beginning mid-dial always invalidates the result.
type warmConn struct {
	hc        *socksdial.HalfConn
	epoch     uint64
	created   time.Time
	closeOnce sync.Once
}

// close releases the connection exactly once; a second call is a no-op
// (sweep and Stop can both reach the same conn across an interleaving).
func (wc *warmConn) close() {
	wc.closeOnce.Do(func() { _ = wc.hc.Close() })
}

// New creates the pool over store. dial may be nil for socksdial.DialHalf.
func New(store *pool.Store, log zerolog.Logger, dial DialHalfFunc) *Pool {
	if dial == nil {
		dial = socksdial.DialHalf
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Pool{
		store:      store,
		log:        log,
		dial:       dial,
		ctx:        ctx,
		cancel:     cancel,
		buckets:    map[*pool.Proxy]*routeBucket{},
		wake:       make(chan struct{}, 1),
		sweepWake:  make(chan struct{}, 1),
		sweepEvery: sweepInterval,
	}
}

// Start launches the sweeper and the first replenish workers. Workers live
// for the process lifetime; a config that disables the pool parks them (they
// claim nothing), and one that re-enables it needs no restart logic. The
// sweeper grows the fleet when the configured concurrency rises; surplus
// workers retire on their next wakeup when it falls.
func (wp *Pool) Start() {
	wp.mu.Lock()
	wp.started = true
	wp.mu.Unlock()
	wp.wg.Add(1)
	go wp.sweeper()
	if wp.store.Load().Config.WarmPool.Enabled {
		wp.reconcileWorkers(wp.store.Load().Config.WarmPool.MaxReplenishConcurrency)
	}
}

func (wp *Pool) sweeper() {
	defer wp.wg.Done()
	// One immediate pass fills the pool at startup instead of one interval in.
	wp.sweep()
	ticker := time.NewTicker(wp.sweepEvery)
	defer ticker.Stop()
	for {
		select {
		case <-wp.ctx.Done():
			return
		case <-ticker.C:
		case <-wp.sweepWake:
		}
		wp.sweep()
	}
}

// sweep is one level-triggered pass: drop buckets for removed routes, expire
// stale and wrong-epoch connections, trim to bounds, then schedule deficits.
// It loads the generation exactly once per pass so bucket deletion and config
// read agree on one snapshot.
func (wp *Pool) sweep() {
	gen := wp.store.Load()
	cfg := gen.Config.WarmPool
	// Collect the live route set before taking mu: RoutePointers takes the
	// pool lock, and the sweep must never nest wp.mu under it.
	live := make(map[*pool.Proxy]bool)
	for _, p := range gen.Pool.RoutePointers() {
		live[p] = true
	}
	now := time.Now()

	wp.mu.Lock()
	if wp.stopped {
		wp.mu.Unlock()
		return
	}
	for p, b := range wp.buckets {
		if !live[p] {
			delete(wp.buckets, p)
			wp.closeReadyLocked(b)
			wp.log.Debug().Str("upstream", p.URL.Host).Msg("warm bucket removed: route gone")
		}
	}
	// Every live route gets a bucket this pass — including ones appearing for
	// the first time — so the deficit pass below can schedule them.
	for p := range live {
		if _, ok := wp.buckets[p]; !ok {
			wp.buckets[p] = &routeBucket{p: p}
		}
	}
	for _, b := range wp.buckets {
		if b.authBroken && b.authBrokenEpoch != b.p.RotationEpoch() {
			b.authBroken = false // the route rotated into a fresh endpoint
		}
		keep := b.ready[:0]
		for _, wc := range b.ready {
			switch {
			case wc.epoch != b.p.RotationEpoch():
				wp.generationInvalidated.Add(1)
				wc.close()
			case now.Sub(wc.created) > cfg.IdleTTL:
				wp.discardedStale.Add(1)
				wc.close()
			default:
				keep = append(keep, wc)
			}
		}
		b.ready = keep
		// A reload may have shrunk the per-route bound; drop from the newest.
		for len(b.ready) > cfg.MaxIdlePerProxy {
			i := len(b.ready) - 1
			wc := b.ready[i]
			b.ready[i] = nil
			b.ready = b.ready[:i]
			wp.discardedOverflow.Add(1)
			wc.close()
		}
	}
	if !cfg.Enabled {
		// Disabled by config: drain everything this tick. Workers stay alive
		// and park — claimTask refuses tasks under a disabled config — so a
		// reload that re-enables the pool just works on the next tick.
		for _, b := range wp.buckets {
			wp.closeReadyLocked(b)
		}
		wp.mu.Unlock()
		return
	}
	total := wp.totalIdleLocked()
	for p, b := range wp.buckets {
		if !wp.replenishEligibleLocked(p, b, now) {
			continue
		}
		for deficit := cfg.MinIdlePerProxy - (len(b.ready) + b.pending); deficit > 0; deficit-- {
			if total >= cfg.MaxTotalIdle {
				break
			}
			b.pending++
			total++
		}
		if b.pending > 0 {
			wp.wakeNow()
		}
	}
	// Grow the fleet here only once Start has launched it: a sweep before
	// Start (tests drive the state machine directly) must not spawn workers
	// that race the caller's claims.
	if wp.started {
		wp.reconcileWorkersLocked(cfg.MaxReplenishConcurrency)
	}
	wp.mu.Unlock()
}

// replenishEligibleLocked reports whether the route may receive new warm
// dials right now. Rotating routes are mid-procedure; auth-broken ones cannot
// authenticate a half handshake; cooling ones just produced request-path
// failures, and their worker capacity is better spent elsewhere until the
// cooldown lifts. Pausing replenish changes no cooldown value anywhere — the
// warm pool never writes route health.
func (wp *Pool) replenishEligibleLocked(p *pool.Proxy, b *routeBucket, now time.Time) bool {
	if p.RotatingNow() || p.AuthBlockedNow() || p.CooldownActive() {
		return false
	}
	if b.authBroken || now.Before(b.backoffUntil) {
		return false
	}
	return true
}

func (wp *Pool) closeReadyLocked(b *routeBucket) {
	for _, wc := range b.ready {
		wc.close()
	}
	b.ready = nil
}

func (wp *Pool) totalIdleLocked() int {
	n := 0
	for _, b := range wp.buckets {
		n += len(b.ready)
	}
	return n
}

// wakeNow nudges one worker without blocking and without ever closing the
// channel. Capacity 1 coalesces bursts; the level-triggered sweep recovers
// any dropped token within one interval.
func (wp *Pool) wakeNow() {
	select {
	case wp.wake <- struct{}{}:
	default:
	}
}

// nudgeSweep asks the sweeper for an immediate pass without blocking.
func (wp *Pool) nudgeSweep() {
	select {
	case wp.sweepWake <- struct{}{}:
	default:
	}
}

func (wp *Pool) reconcileWorkers(want int) {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	wp.reconcileWorkersLocked(want)
}

func (wp *Pool) reconcileWorkersLocked(want int) {
	if want < 1 {
		want = 1
	}
	for wp.workers < want {
		wp.workers++
		wp.wg.Add(1)
		go wp.worker()
	}
	// Shrinking is opportunistic: surplus workers retire in retireIfSurplus
	// on their next wakeup, so the live count converges within a tick.
}

func (wp *Pool) worker() {
	defer wp.wg.Done()
	for {
		select {
		case <-wp.ctx.Done():
			return
		case <-wp.wake:
		}
		if wp.retireIfSurplus() {
			return
		}
		for wp.ctx.Err() == nil {
			t, ok := wp.claimTask()
			if !ok {
				break
			}
			wp.runDial(t)
		}
	}
}

// retireIfSurplus lets this worker exit when the configured concurrency fell
// below the live worker count.
func (wp *Pool) retireIfSurplus() bool {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	if wp.workers > wp.store.Load().Config.WarmPool.MaxReplenishConcurrency {
		wp.workers--
		return true
	}
	return false
}

// dialTask is one claimed replenish dial. The epoch is captured at claim
// time — before the dial — and the connection is stamped with it; a rotation
// beginning mid-dial therefore fails the post-dial equality check.
type dialTask struct {
	p     *pool.Proxy
	b     *routeBucket
	epoch uint64
}

// claimTask takes one scheduled dial, re-checking every bound under mu: the
// sweeper's deficit pass ran up to an interval ago and the world may have
// changed since. Map iteration order varies, so which eligible bucket is
// served first is arbitrary but bounded by the pending counts.
func (wp *Pool) claimTask() (dialTask, bool) {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	if wp.stopped {
		return dialTask{}, false
	}
	cfg := wp.store.Load().Config.WarmPool
	if !cfg.Enabled {
		return dialTask{}, false
	}
	if wp.totalIdleLocked() >= cfg.MaxTotalIdle {
		// Pending reservations are already counted against the cap by the
		// sweep that scheduled them; claiming one does not create a new
		// reservation, only idle growth does — so gate on idle alone.
		return dialTask{}, false
	}
	if int(wp.dialing.Load()) >= cfg.MaxReplenishConcurrency {
		return dialTask{}, false
	}
	now := time.Now()
	for p, b := range wp.buckets {
		if b.pending == 0 || !wp.replenishEligibleLocked(p, b, now) {
			continue
		}
		b.pending--
		return dialTask{p: p, b: b, epoch: p.RotationEpoch()}, true
	}
	return dialTask{}, false
}

// runDial performs one warm dial and re-validates everything in one post-dial
// critical section. A bucket deleted by a sweep while the dial was in flight,
// a rotation begun under it, a config that disabled the pool, a bound that
// shrank, or a stopped pool each turn the fresh connection into a close
// instead of an enqueue — an orphaned socket must never outlive its bucket.
func (wp *Pool) runDial(t dialTask) {
	wp.replenishAttempts.Add(1)
	wp.dialing.Add(1)
	defer wp.dialing.Add(-1)
	gen := wp.store.Load()
	hc, err := wp.dial(wp.ctx, t.p.URL, gen.Config.DialTimeout)

	if err != nil {
		wp.mu.Lock()
		wp.connectFailed.Add(1)
		var authErr *socksdial.ProxyAuthError
		if errors.As(err, &authErr) {
			t.b.authBroken = true
			t.b.authBrokenEpoch = t.p.RotationEpoch()
			wp.log.Debug().Str("upstream", t.p.URL.Host).Msg("warm replenish auth failure stops warming route")
		} else {
			t.b.failStreak++
			t.b.backoffUntil = time.Now().Add(jitteredBackoff(pool.SaturatingCooldown(warmBackoffBase, warmBackoffMax, t.b.failStreak)))
		}
		wp.mu.Unlock()
		return
	}

	cfg := gen.Config.WarmPool
	wp.mu.Lock()
	if t.p.RotationEpoch() != t.epoch {
		wp.generationInvalidated.Add(1)
		wp.mu.Unlock()
		_ = hc.Close()
		return
	}
	if wp.stopped || wp.buckets[t.p] != t.b || !cfg.Enabled ||
		len(t.b.ready) >= cfg.MaxIdlePerProxy || wp.totalIdleLocked() >= cfg.MaxTotalIdle {
		wp.discardedOverflow.Add(1)
		wp.mu.Unlock()
		_ = hc.Close()
		return
	}
	t.b.failStreak = 0
	t.b.backoffUntil = time.Time{}
	t.b.ready = append(t.b.ready, &warmConn{hc: hc, epoch: t.epoch, created: time.Now()})
	wp.created.Add(1)
	wp.mu.Unlock()
}

// Borrow hands out the oldest ready half connection for p, or nil
// immediately. It never blocks, never dials, and never creates a bucket: a
// miss means the caller dials cold, exactly as before the pool existed. Pop
// and rotation-epoch check share one critical section, so a connection is
// either handed out or invalidated — never both. A half connection handed
// out here is single-use: CompleteConnect consumes it.
func (wp *Pool) Borrow(p *pool.Proxy) *socksdial.HalfConn {
	if p == nil {
		return nil
	}
	wp.mu.Lock()
	defer wp.mu.Unlock()
	b, ok := wp.buckets[p]
	if !ok || len(b.ready) == 0 {
		return nil
	}
	wc := b.ready[0]
	b.ready = b.ready[1:]
	if wc.epoch != p.RotationEpoch() {
		wp.generationInvalidated.Add(1)
		wc.close()
		return nil
	}
	wp.borrowed.Add(1)
	// Handing one out opens a deficit; nudge the sweeper (non-blocking,
	// coalesced) so steady consumption refills at consumption rate instead of
	// waiting for the next tick.
	wp.nudgeSweep()
	return wc.hc
}

// DiscardRoute closes every ready connection for p. The serving path calls
// it when a borrowed connection fails at the transport level, on the theory
// that its siblings parked on the same endpoint died with it. It only closes
// — route health stays the request path's to mutate.
func (wp *Pool) DiscardRoute(p *pool.Proxy) {
	if p == nil {
		return
	}
	wp.mu.Lock()
	defer wp.mu.Unlock()
	b, ok := wp.buckets[p]
	if !ok {
		return
	}
	wp.discardedStale.Add(uint64(len(b.ready)))
	wp.closeReadyLocked(b)
}

// Stop tears the pool down: cancels the context, closes every ready
// connection, and waits a bounded time for the sweeper and workers to
// unwind. See the package comment for why the wait is bounded and the wake
// channel is never closed.
func (wp *Pool) Stop() {
	wp.cancel()
	wp.mu.Lock()
	wp.stopped = true
	for _, b := range wp.buckets {
		wp.closeReadyLocked(b)
		b.pending = 0
	}
	wp.mu.Unlock()
	done := make(chan struct{})
	go func() {
		wp.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(stopWaitLimit):
	}
}

// RouteStatus is one route's warm-pool view; Upstream is the endpoint's
// host:port — credentials never appear.
type RouteStatus struct {
	Upstream string `json:"upstream"`
	Idle     int    `json:"idle"`
	Pending  int    `json:"pending"`
}

// Status is the /status view of the warm pool: configured bounds, gauges
// derived from bucket state, and the monotonic lifecycle counters.
type Status struct {
	Enabled                 bool          `json:"enabled"`
	Stopped                 bool          `json:"stopped"`
	Workers                 int           `json:"workers"`
	IdleTotal               int           `json:"idleTotal"`
	MinIdlePerProxy         int           `json:"minIdlePerProxy"`
	MaxIdlePerProxy         int           `json:"maxIdlePerProxy"`
	MaxTotalIdle            int           `json:"maxTotalIdle"`
	MaxReplenishConcurrency int           `json:"maxReplenishConcurrency"`
	IdleTTL                 string        `json:"idleTtl"`
	Created                 uint64        `json:"created"`
	Borrowed                uint64        `json:"borrowed"`
	DiscardedStale          uint64        `json:"discardedStale"`
	DiscardedOverflow       uint64        `json:"discardedOverflow"`
	GenerationInvalidated   uint64        `json:"generationInvalidated"`
	ConnectFailed           uint64        `json:"connectFailed"`
	ReplenishAttempts       uint64        `json:"replenishAttempts"`
	Routes                  []RouteStatus `json:"routes"`
}

// Snapshot renders the pool's status. Routes are sorted by endpoint for a
// stable /status ordering.
func (wp *Pool) Snapshot() Status {
	gen := wp.store.Load()
	cfg := gen.Config.WarmPool
	wp.mu.Lock()
	defer wp.mu.Unlock()
	st := Status{
		Enabled:                 cfg.Enabled,
		Stopped:                 wp.stopped,
		Workers:                 wp.workers,
		MinIdlePerProxy:         cfg.MinIdlePerProxy,
		MaxIdlePerProxy:         cfg.MaxIdlePerProxy,
		MaxTotalIdle:            cfg.MaxTotalIdle,
		MaxReplenishConcurrency: cfg.MaxReplenishConcurrency,
		IdleTTL:                 cfg.IdleTTL.String(),
		Created:                 wp.created.Load(),
		Borrowed:                wp.borrowed.Load(),
		DiscardedStale:          wp.discardedStale.Load(),
		DiscardedOverflow:       wp.discardedOverflow.Load(),
		GenerationInvalidated:   wp.generationInvalidated.Load(),
		ConnectFailed:           wp.connectFailed.Load(),
		ReplenishAttempts:       wp.replenishAttempts.Load(),
		Routes:                  make([]RouteStatus, 0, len(wp.buckets)),
	}
	for p, b := range wp.buckets {
		st.IdleTotal += len(b.ready)
		st.Routes = append(st.Routes, RouteStatus{Upstream: p.URL.Host, Idle: len(b.ready), Pending: b.pending})
	}
	sort.Slice(st.Routes, func(i, j int) bool { return st.Routes[i].Upstream < st.Routes[j].Upstream })
	return st
}

// jitteredBackoff spreads a backoff by ±10% so routes whose providers fail
// and recover on the same cadence do not retry in lockstep.
func jitteredBackoff(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	delta := float64(d) * (jitterFactor()*0.2 - 0.1)
	return d + time.Duration(delta)
}

// jitterFactor returns a uniform float64 in [0, 1). crypto/rand because the
// semgrep security gate rejects every math/rand variant, v2 included, and the
// syscall-backed read runs too rarely for its cost to matter. The top 53 bits
// keep the value uniform despite float64 rounding.
func jitterFactor() float64 {
	var b [8]byte
	_, _ = rand.Read(b[:]) // documented never to fail; all-zero bytes still yield a usable factor
	return float64(binary.LittleEndian.Uint64(b[:])>>11) / (1 << 53)
}
