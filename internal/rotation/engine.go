// Package rotation drives manual-route egress IP rotation. A scheduler admits
// at most rotation.max-concurrent procedures at a time; each procedure drains
// the route's in-flight work, learns the baseline IP, calls the provider
// rotate API, and verifies the egress IP actually changed. A rotation that
// leaves the IP unchanged is retried forever with growing backoff; the route
// keeps serving in the meantime.
package rotation

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/sanitize"
	"rotation-proxy-gateway/internal/socksdial"

	"github.com/rs/zerolog"
)

const (
	// scheduleTick is how often the scheduler re-evaluates due routes; it
	// also bounds how soon a freed concurrency slot is reused.
	scheduleTick = time.Second
	// drainPoll is the in-flight recheck cadence while draining.
	drainPoll = 100 * time.Millisecond
	// baselineAttempts bounds the pre-rotation IP probe before rotating
	// unverified; probeRetryPause separates the attempts.
	baselineAttempts = 3
	probeRetryPause  = time.Second
)

// dlog renders a duration for log fields at millisecond precision, matching
// the proxy server's duration fields.
func dlog(d time.Duration) string { return d.Truncate(time.Millisecond).String() }

// RotationOutcome is how one rotation attempt ended. It is the engine's own
// small vocabulary, kept separate from the durable store's so this package does
// not depend on where an attempt is recorded.
type RotationOutcome string

const (
	// OutcomeRotated: the route committed a verified egress IP that differed
	// from its baseline.
	OutcomeRotated RotationOutcome = "rotated"
	// OutcomeUnchangedIP: verification ran to its deadline and the egress IP
	// never changed. The route keeps serving in the stale state.
	OutcomeUnchangedIP RotationOutcome = "unchanged_ip"
	// OutcomeAPIFailed: the provider's rotate call failed. Verification still
	// ran, because a provider can rotate in spite of a failed call — so this
	// outcome only means the observed IP did not change either.
	OutcomeAPIFailed RotationOutcome = "api_failed"
	// OutcomeAborted: the attempt unwound without a terminal rotation state —
	// shutdown, or a reload removed or replaced the route. Deliberately not a
	// provider failure, and never counted as one.
	OutcomeAborted RotationOutcome = "aborted"
)

// Attempt is one rotation procedure, from drain to terminal outcome, as the
// engine states it.
//
// Every field is a fixed label, a count, or an address the engine already
// holds in rotation state. The attempt's error text is deliberately absent: a
// rotate-API failure's message can quote the provider's URL, and that detail
// belongs in the process log, where internal/sanitize governs it. A recorder
// receiving an Attempt therefore cannot persist a rotate-API URL, a header, a
// body, or a route credential — none of them is in the struct.
type Attempt struct {
	// EventID is the attempt's idempotency key, minted by the engine when the
	// attempt completes. A recorder reuses it across every retry, so a replay
	// of the same attempt is a no-op rather than a second history row.
	EventID string
	// RouteHost, RouteKind and RouteOrigin identify the route. RouteHost is
	// the URL host only — never the full canonical route ID, which embeds the
	// route's SOCKS userinfo and must not reach a durable row.
	RouteHost   string
	RouteKind   string
	RouteOrigin string
	// Mode names how this attempt was driven. The engine drives manual routes
	// only, so it carries ModeManual on every attempt — stated per attempt
	// rather than assumed by the recorder, so a future driver cannot be filed
	// under today's rows' mode.
	Mode string
	// RotationEpoch is the route's rotation generation this attempt ran under,
	// read at the attempt's start.
	RotationEpoch uint64
	StartedAt     time.Time
	EndedAt       time.Time
	Outcome       RotationOutcome
	// FailureKind is a fixed label ("none" when the attempt reached a verified
	// terminal state), never error text.
	FailureKind string
	// BaselineIP and ObservedIP are the egress addresses the attempt learned,
	// already canonical in the pool's sense; empty when it learned none.
	BaselineIP string
	ObservedIP string
	// APIAttempts and ProbeAttempts count this attempt's provider call and its
	// verify probes.
	APIAttempts   int
	ProbeAttempts int
	// ConfigRevision is the durable configuration revision serving at the
	// attempt's start, or 0 when this instance runs on its local seed file.
	ConfigRevision int64
	// ConsecutiveSameIP is the run of same-IP outcomes ending at this attempt.
	ConsecutiveSameIP int
	// Revisit reports that ObservedIP was an address this route had already
	// verified earlier in its lifetime — the engine's commit-time decision,
	// passed through rather than reconstructed by a reader.
	Revisit bool
}

// History receives completed rotation attempts and the egress addresses they
// verified.
//
// It is an interface so this package stays independent of the durable store,
// and a nil History is the disabled state. Every method MUST be non-blocking:
// the engine calls them from its procedure goroutines, and a rotation must
// never wait on — or know about — a database. Implementations are expected to
// buffer and return.
type History interface {
	// RecordRotationAttempt reports one finished attempt. The engine calls it
	// exactly once per attempt, at the moment the attempt's terminal decision
	// was made, with the EventID it minted for it.
	RecordRotationAttempt(a Attempt)

	// RecordIPObservation reports one egress address a route was verified
	// serving from, with the revisit flag the commit already decided.
	RecordIPObservation(o IPObservation)
}

// IPObservation is one egress address a route was observed serving from.
type IPObservation struct {
	RouteHost   string
	RouteKind   string
	RouteOrigin string
	// IP is the address as the engine holds it, already canonical by the pool's
	// definition; a recorder canonicalizes again on the way in.
	IP string
	// Source is "baseline" or "rotation".
	Source string
	At     time.Time
	// Revisit is the engine's commit-time decision for this address.
	Revisit       bool
	RotationEpoch uint64
}

// Engine schedules and runs rotation procedures for manual routes. Run drives
// one Engine; all methods are safe for concurrent use.
type Engine struct {
	store *pool.Store
	log   zerolog.Logger
	// Now is the clock used for scheduling; tests replace it.
	Now func() time.Time

	rotations atomic.Uint64 // completed rotations that observed a changed IP
	// ipRevisits counts those of them that committed an address the same route
	// had already verified; it is the global aggregate of the per-route
	// ipRevisitCount, never larger than rotations.
	ipRevisits atomic.Uint64

	// history receives each completed rotation attempt. It is an interface, not
	// a concrete store, so this package does not depend on the durable
	// analytics substrate — the engine states what it observed and the store
	// decides where it goes. A nil History discards every attempt, which is the
	// default and the reason the e2e suite measures no analytics at all.
	//
	// Every method on it is required to be non-blocking: the engine calls them
	// from its procedure goroutines, and a rotation must never wait on a
	// database.
	history History

	// dial and probeTLS are seams for tests. Production dials through the
	// route's SOCKS endpoint and always verifies the ip-check certificate.
	dial     func(ctx context.Context, pu *url.URL, target socksdial.Target, timeout time.Duration) (net.Conn, error)
	probeTLS func(host string) *tls.Config

	wake chan struct{} // capacity 1: a procedure finished, re-evaluate now

	mu     sync.Mutex
	due    map[string]time.Time // canonical route ID -> next attempt
	active map[string]*pool.Proxy
	consec map[string]int // canonical route ID -> consecutive same-IP outcomes
}

// New builds an Engine over a generation store.
func New(store *pool.Store, log zerolog.Logger) *Engine {
	return &Engine{
		store:  store,
		log:    log,
		Now:    time.Now,
		wake:   make(chan struct{}, 1),
		due:    map[string]time.Time{},
		active: map[string]*pool.Proxy{},
		consec: map[string]int{},
		dial:   socksdial.Dial,
		probeTLS: func(host string) *tls.Config {
			return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		},
	}
}

// UseHistory attaches where completed attempts and verified egress addresses go.
//
// It is a method rather than a New parameter because it is optional and the
// decision belongs to the operator, not the engine: with no History — the
// default — the engine discards every attempt, starts nothing, and behaves
// exactly as it did before the durable analytics substrate existed. Passing nil
// restores that state.
//
// It is safe to call before Run and from a single goroutine at startup. It is
// not safe to call while procedures are in flight, because it writes the
// history field without synchronization; the engine does not need a live swap,
// and a data race in exchange for one is a bad trade.
func (e *Engine) UseHistory(h History) { e.history = h }

// Rotations reports how many rotations completed with a verified new egress IP.
func (e *Engine) Rotations() uint64 { return e.rotations.Load() }

// IPRevisits reports how many completed rotations committed an egress IP the
// same route had already verified earlier in its lifetime — the sum of the
// per-route ipRevisitCount, aggregated here exactly as Rotations aggregates
// the per-route rotation counts.
func (e *Engine) IPRevisits() uint64 { return e.ipRevisits.Load() }

// routeID keys engine state by canonical URL+kind, matching pool.Lookup.
func routeID(spec config.RouteSpec) string {
	return config.CanonicalRouteID(spec.URL) + "|" + string(spec.Kind)
}

// Run blocks until ctx is canceled, scheduling procedures and starting them in
// their own goroutines. Canceling ctx aborts all procedures immediately; it
// never extends process shutdown, which cancels this context first.
func (e *Engine) Run(ctx context.Context) {
	e.mu.Lock()
	gen := e.store.Load()
	for _, spec := range gen.Config.ManualRoutes {
		id := routeID(spec.RouteSpec)
		when := e.Now().Add(spec.RotateInterval)
		if gen.Config.Rotation.RotateOnStart {
			// Rotate immediately at boot; each procedure's baseline probe
			// naturally staggers the starts.
			when = e.Now()
		}
		e.due[id] = when
	}
	e.mu.Unlock()

	if !gen.Config.Rotation.RotateOnStart {
		go e.bootPrecheck(ctx, gen)
	}

	ticker := time.NewTicker(scheduleTick)
	defer ticker.Stop()
	for {
		e.evaluate(ctx)
		select {
		case <-ctx.Done():
			e.abortAll()
			return
		case <-ticker.C:
		case <-e.wake:
		}
	}
}

// bootPrecheck learns each manual route's starting egress IP and warns when a
// route's IP changes between two probes without any rotation: such a provider
// cannot be trusted to hold an IP, so rotation success there is best-effort.
func (e *Engine) bootPrecheck(ctx context.Context, gen *pool.Generation) {
	for _, spec := range gen.Config.ManualRoutes {
		if ctx.Err() != nil {
			return
		}
		p := gen.Pool.Lookup(routeID(spec.RouteSpec))
		if p == nil || !e.store.Load().Pool.Contains(p) {
			continue
		}
		log := e.log.With().Str("route", p.URL.Host).Str("kind", string(p.Kind)).Logger()
		first, ok := e.baselineProbe(ctx, gen, spec, gen.Config.Rotation.IPCheckTimeout, log)
		if !ok {
			log.Warn().Msg("boot baseline probe failed; the route starts unverified")
			continue
		}
		second, ok := e.baselineProbe(ctx, gen, spec, gen.Config.Rotation.IPCheckTimeout, log)
		if !ok {
			p.SetBaselineIP(first)
			log.Debug().Msg("second boot probe failed; keeping the first baseline")
			continue
		}
		if !pool.SameIP(first, second) {
			log.Warn().Msg("route egress IP changed between boot probes without a rotation; provider IPs are not sticky")
		}
		p.SetBaselineIP(second)
		// The route's starting address belongs in the same history a rotation
		// commit writes to, so "which IPs has this route ever served from"
		// covers it — and a rotation that later returns to this address is
		// visibly a revisit rather than a first sighting.
		e.recordBaselineObservation(p, second, e.Now())
		log.Debug().Str("egress_ip", second).Msg("boot baseline set")
	}
}

// evaluate admits every due route while the resolved concurrency cap allows.
func (e *Engine) evaluate(ctx context.Context) {
	gen := e.store.Load()
	specs := gen.Config.ManualRoutes
	cap := gen.Config.Rotation.ResolveMaxConcurrent(len(specs))
	now := e.Now()

	e.mu.Lock()
	defer e.mu.Unlock()

	current := make(map[string]bool, len(specs))
	for _, spec := range specs {
		id := routeID(spec.RouteSpec)
		current[id] = true
		if _, scheduled := e.due[id]; !scheduled {
			// A route added by a reload rotates on the next cycle.
			e.due[id] = now
			e.log.Debug().Str("route", spec.RouteSpec.URL.Host).Msg("route added by reload; due immediately")
		}
	}
	for id := range e.due {
		if !current[id] {
			delete(e.due, id)
			delete(e.consec, id)
		}
	}
	for id, p := range e.active {
		if !current[id] {
			// Its procedure aborts on its own; stop counting it now so the
			// freed slot is reused promptly.
			delete(e.active, id)
			p.AbandonRotation()
		}
	}

	active := len(e.active)
	for _, spec := range specs {
		id := routeID(spec.RouteSpec)
		if e.active[id] != nil {
			continue
		}
		due, scheduled := e.due[id]
		if !scheduled || due.After(now) {
			continue
		}
		if active >= cap {
			// The routine not-due and already-active skips stay silent — they
			// are the common case and would log every tick. A due route held
			// back by the cap is the diagnosable anomaly.
			e.log.Debug().Str("route", spec.RouteSpec.URL.Host).Msg("rotation due but the concurrency cap is reached")
			return
		}
		p := gen.Pool.Lookup(id)
		if p == nil {
			e.log.Debug().Str("route", spec.RouteSpec.URL.Host).Msg("rotation due but the route is not in the live pool")
			continue
		}
		e.active[id] = p
		active++
		go e.runProcedure(ctx, gen, spec, p, id)
	}
}

func (e *Engine) runProcedure(ctx context.Context, gen *pool.Generation, spec config.ManualRouteSpec, p *pool.Proxy, id string) {
	defer e.finishProcedure(id, p)

	// gone reports that the procedure must stop: shutdown, or a reload
	// removed or replaced this route. It consults the store's current pool:
	// the procedure's own generation always contains the route it admitted.
	gone := func() bool { return ctx.Err() != nil || !e.store.Load().Pool.Contains(p) }
	if p == nil || gone() {
		return
	}
	if e.rotate(ctx, gen, spec, p, id, gone) {
		// The procedure aborted — shutdown, or a reload removed or replaced
		// the route — so its rotation marker must be cleared. Every other
		// outcome leaves the route's rotation state terminal already.
		p.AbandonRotation()
	}
}

// rotate runs one full rotation procedure: drain, baseline probe, rotate
// call, verify, and the terminal bookkeeping. It reports that the procedure
// aborted without reaching a terminal rotation state, so the caller clears
// the route's rotation marker.
func (e *Engine) rotate(ctx context.Context, gen *pool.Generation, spec config.ManualRouteSpec, p *pool.Proxy, id string, gone func() bool) bool {
	settings := gen.Config.Rotation
	log := e.log.With().Str("route", p.URL.Host).Str("kind", string(p.Kind)).Logger()

	// Phase transitions carry how long the previous phase took and how far
	// the procedure is from its start: together they answer "where did the
	// rotation spend its time" without cross-referencing timestamps.
	started, phaseStart, phase := e.Now(), e.Now(), "draining"
	enterPhase := func(name string) {
		log.Debug().Str("phase", name).Str("previous", phase).
			Str("in_previous", dlog(e.Now().Sub(phaseStart))).
			Str("since_start", dlog(e.Now().Sub(started))).
			Msg("rotation phase entered")
		phase, phaseStart = name, e.Now()
	}

	p.BeginRotation(pool.RotationDraining)
	// The rotation epoch is read after BeginRotation, which is what advances it,
	// so it names the generation this attempt actually ran under. Read once
	// here: a later read could observe the next attempt's increment and stamp
	// this attempt with a generation it predates.
	epoch := p.RotationEpoch()
	// One identity for this whole procedure, minted once and reused by whichever
	// terminal path ends it. It is what makes recording the attempt twice — which
	// two overlapping abort paths could otherwise do — a no-op at the store's
	// primary key rather than a duplicate history row.
	attemptID := newAttemptID()
	// Probe and API counters, accumulated where each call actually happens, so
	// the recorded attempt says what it cost rather than what it could have.
	var (
		apiAttempts   int
		probeAttempts int
	)
	// abort records the attempt as an unwind rather than a provider failure.
	// Every early return below is one of the two: the procedure could not reach
	// a terminal rotation state, because the engine is shutting down or a
	// reload removed or replaced the route. That is a different event from a
	// rotation that ran and failed, and an operator asking "did this route's IP
	// fail to rotate" must not have to read a restart into the answer.
	abort := func() {
		e.recordAbort(p, gen, attemptID, epoch, started)
	}
	drainEv := log.Debug().Str("phase", "draining").Str("drain_timeout", dlog(settings.DrainTimeout))
	if n := p.InFlight(); n > 0 {
		drainEv = drainEv.Int("in_flight", n)
	}
	drainEv.Msg("rotation procedure started")

	// 1. Drain in-flight work, bounded by rotation.drain-timeout. Expiry
	// abandons the wait and rotates anyway: in-flight work keeps running
	// on its existing tunnels, none are broken.
	drainDeadline := e.Now().Add(settings.DrainTimeout)
	for p.InFlight() > 0 {
		if !e.Now().Before(drainDeadline) {
			log.Warn().Int("in_flight", p.InFlight()).Msg("drain timeout expired; forcing rotation")
			break
		}
		if gone() {
			abort()
			return true
		}
		if !sleepCtx(ctx, drainPoll) {
			abort()
			return true
		}
	}
	if gone() {
		abort()
		return true
	}

	// 2. Baseline: what the egress IP is before rotating. Without it the
	// rotation can only be verified as "not colliding with other routes".
	p.SetRotationPhase(pool.RotationRotating)
	enterPhase("rotating")
	baseline, verified := e.baselineProbe(ctx, gen, spec, settings.IPCheckTimeout, log)
	if gone() {
		abort()
		return true
	}
	if !verified {
		log.Warn().Msg("baseline probe failed; rotating without IP comparison")
	}

	// 3. Call the provider rotate API, directly — never through the pool.
	apiAttempts++
	retryAfter, apiErr := e.callRotateAPI(ctx, spec.API)
	// The provider call can sit in flight for its whole timeout; a reload
	// that removed or replaced the route meanwhile is caught here, at the
	// phase boundary, instead of after a verify window of probes through the
	// removed route's endpoint.
	if gone() {
		abort()
		return true
	}

	// 4. Verify: the egress IP must actually have changed. Carriers can hand
	// back the same address, which does not count as a rotation. A candidate
	// that survives every check is committed through commit, which re-checks
	// the collision set atomically with the record.
	p.SetRotationPhase(pool.RotationVerifying)
	enterPhase("verifying")
	commit := func(ip string) commitOutcome {
		if gone() {
			return commitAborted
		}
		// The live pool decides both remaining questions in one critical
		// section: whether this route is still a member of it (a reload may
		// have removed or replaced it since the check above — that check is a
		// fast path, not the guarantee), and whether a second procedure
		// committed this same candidate between verify's screen above and
		// here.
		//
		// The commit's timestamp is read before the pool is loaded so the pool
		// committed into is the one live at the commit, not one observed a
		// moment earlier: operand order decides which pool the check runs
		// against, and the later load is the one whose answer is worth having.
		at := e.Now()
		revisit, err := e.store.Load().Pool.CommitRotation(e.store, p, ip, at)
		switch {
		case errors.Is(err, pool.ErrRotationRouteGone):
			// The route left the live pool while the procedure was verifying.
			// Nothing was recorded, and the route this procedure owns no
			// longer serves traffic, so the attempt must not be reported as a
			// rotation failure either: unwinding as an abort is what lets the
			// caller stop without marking the route stale or backing it off.
			log.Debug().Str("egress_ip", ip).Msg("route left the live pool before the commit")
			// Not recorded here: verify returns on this outcome, and the caller
			// sees the same route-gone state through its own gone() check, so
			// recording the abort there covers this path exactly once.
			return commitAborted
		case err != nil: // pool.ErrRotationCollision
			return commitLateCollision
		}
		// 5. Success: the new IP became the baseline, dial health earned by
		// the old IP is discarded, and the route serves fresh.
		p.MarkRotated()
		e.clearConsecutive(id)
		e.rotations.Add(1)
		if revisit {
			// The provider handed back an address this route had already
			// verified: the commit is still a rotation, but it did not widen
			// the route's egress diversity.
			e.ipRevisits.Add(1)
		}
		e.setDue(id, e.Now().Add(spec.RotateInterval))
		log.Info().Str("egress_ip", ip).Str("next_in", dlog(spec.RotateInterval)).Msg("rotation complete")
		// Recorded here, at the one place the rotation is known to have
		// succeeded and the revisit flag is known: the commit. A recorder never
		// re-derives either from the pool's counters, which it cannot see and
		// which would be a second, divergent account of the same event. Enqueue
		// only — this runs on a procedure goroutine, and a rotation must not
		// wait on a database.
		e.recordRotated(p, gen, attemptID, ip, e.Now(), revisit, epoch, started, baseline, verified, apiAttempts, probeAttempts)
		return commitDone
	}
	changed := e.verify(ctx, gen, spec, p, baseline, verified, settings, apiErr != nil, log, commit, &probeAttempts)

	if gone() {
		// verify returned because the procedure was told to stop, not because
		// the IP did or did not change. Recording it as unchanged_ip would blame
		// the provider for a shutdown.
		abort()
		return true
	}
	if apiErr != nil {
		log.Warn().Str("error", sanitize.ErrorString(apiErr)).Msg("rotate API call failed")
	}
	if changed {
		// The commit closure already recorded this attempt, at the instant the
		// rotation became true. There is nothing terminal left to record here.
		return false
	}
	consecutive := e.bumpConsecutive(id)
	backoff := BackoffFor(spec.RotateInterval, consecutive, settings.RetryBackoffMax)
	// A provider Retry-After hint may extend the wait, but never past the
	// configured ceiling: an unbounded hint would let one response silence
	// the route's rotation retries for days.
	backoff = min(max(retryAfter, backoff), settings.RetryBackoffMax)
	// Mark the pool that is serving now: a reload may have swapped the
	// generation between the gone() check and here, and jumpToBack must
	// land on the route the live pool actually picks from.
	e.store.Load().Pool.MarkStale(p, backoff, consecutive)
	e.setDue(id, e.Now().Add(backoff))
	warnEv := log.Warn().Int("consecutive_same_ip", consecutive).Str("retry_in", dlog(backoff))
	if retryAfter > 0 {
		// The provider's raw hint, before the ceiling clamp: the gap
		// between it and retry_in is the clamp at work.
		warnEv = warnEv.Str("retry_after_hint", dlog(retryAfter))
	}
	warnEv.Msg("rotation did not change the egress IP; retrying")
	// The attempt ran to a terminal state that was not a rotation. Recorded
	// here, where that decision was just made and where the consecutive-same-IP
	// run and the observed address are both in hand — a reader reconstructing
	// them later would be guessing at values that move.
	e.recordUnchanged(p, gen, attemptID, epoch, started, baseline, verified, consecutive, apiErr != nil, apiAttempts, probeAttempts)
	return false
}

// commitOutcome is the commit seam's decision for one verified candidate.
type commitOutcome uint8

const (
	// commitDone: the candidate was free of collisions at commit time and the
	// rotation is recorded.
	commitDone commitOutcome = iota
	// commitAborted: the route was removed, replaced, or the engine is
	// shutting down before the commit; nothing is recorded and the procedure
	// unwinds.
	commitAborted
	// commitLateCollision: another procedure committed the same candidate
	// between this procedure's screen and its commit; the candidate counts
	// as rejected and verification continues for a distinct address.
	commitLateCollision
)

// verify polls the route's egress IP until it differs from the baseline and
// no other manual route reports it. With an unknown baseline any
// non-colliding IP counts. apiFailed shortens the window to a single probe:
// the call failed, but the provider may have rotated anyway. Each rejected
// candidate is logged at debug — when verification fails, these lines are
// the only record of why. A candidate that survives every check is handed to
// commit, which re-checks the collision set atomically with the record; it
// reports whether that commit happened.
func (e *Engine) verify(ctx context.Context, gen *pool.Generation, spec config.ManualRouteSpec, p *pool.Proxy, baseline string, verified bool, settings config.RotationSettings, apiFailed bool, log zerolog.Logger, commit func(ip string) commitOutcome, probes *int) bool {
	deadline := e.Now().Add(settings.IPCheckTimeout)
	for attempt := 0; ; attempt++ {
		if ctx.Err() != nil {
			return false
		}
		if apiFailed && attempt >= 1 {
			return false
		}
		if attempt > 0 {
			pause := settings.IPCheckInterval
			if remaining := deadline.Sub(e.Now()); remaining < pause {
				pause = remaining
			}
			if !sleepCtx(ctx, pause) || !e.Now().Before(deadline) {
				return false
			}
		}
		remaining := settings.IPCheckTimeout
		if d := deadline.Sub(e.Now()); d > 0 && d < remaining {
			remaining = d
		}
		ip, err := e.probeIP(ctx, gen, spec, remaining)
		if probes != nil {
			*probes++
		}
		if err != nil {
			log.Debug().Int("attempt", attempt+1).Str("error", sanitize.ErrorString(err)).Msg("ip check probe failed")
			continue
		}
		// Every comparison below is made under the canonical identity the pool
		// defines, never on the literal the probe returned: two spellings of
		// one address are one address, so a provider that switches between
		// them has not rotated anything. A candidate that gets past these
		// checks therefore differs from the current address — which is what
		// keeps a revisit (a return to an older, already-verified address) from
		// ever meaning "the IP did not change".
		if verified && pool.SameIP(ip, baseline) {
			log.Debug().Int("attempt", attempt+1).Str("egress_ip", ip).Msg("ip unchanged since the baseline")
			continue
		}
		if !verified && pool.SameIP(ip, p.LastIP()) {
			// Without a baseline, an address identical to the route's last
			// verified one is the provider declining to rotate, not a change;
			// counting it would inflate the rotations metric.
			log.Debug().Int("attempt", attempt+1).Str("egress_ip", ip).Msg("ip matches the route's last verified address")
			continue
		}
		// The collision set comes from the live pool so a reload that added
		// or removed manual routes mid-procedure is reflected. Its keys are
		// canonical, so the candidate is screened in the same form.
		if held := e.store.Load().Pool.LastIPs(p); held[pool.CanonicalIP(ip)] {
			// The "new" IP is another manual route's current address; that
			// defeats rotating either route. Keep waiting for a distinct one.
			log.Debug().Int("attempt", attempt+1).Str("egress_ip", ip).Msg("ip collides with another manual route")
			continue
		}
		switch commit(ip) {
		case commitDone:
			return true
		case commitAborted:
			return false
		default: // commitLateCollision
			// A second procedure committed this same candidate after the
			// screen above passed for this one: the candidate counts as
			// rejected and the window keeps watching for an address no other
			// route holds.
			log.Debug().Int("attempt", attempt+1).Str("egress_ip", ip).Msg("ip collides with another manual route")
		}
	}
}

// finishProcedure releases the route's active slot when its procedure ends.
// The pointer guard matters under remove→re-add reloads: a stale procedure
// from before the swap must not unregister its replacement, which would make
// the concurrency cap a slot looser than configured. finishProcedure still
// wakes the scheduler either way — a finished procedure always frees real
// capacity, and the spurious wake for the stale caller is harmless.
func (e *Engine) finishProcedure(id string, p *pool.Proxy) {
	e.mu.Lock()
	if e.active[id] == p {
		delete(e.active, id)
	}
	e.mu.Unlock()
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

func (e *Engine) setDue(id string, when time.Time) {
	e.mu.Lock()
	e.due[id] = when
	e.mu.Unlock()
}

func (e *Engine) bumpConsecutive(id string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.consec[id]++
	return e.consec[id]
}

func (e *Engine) clearConsecutive(id string) {
	e.mu.Lock()
	delete(e.consec, id)
	e.mu.Unlock()
}

// abortAll abandons every running procedure during shutdown.
func (e *Engine) abortAll() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, p := range e.active {
		p.AbandonRotation()
		delete(e.active, id)
	}
}
