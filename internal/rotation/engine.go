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
	"log/slog"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/sanitize"
	"rotation-proxy-gateway/internal/socksdial"
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

// Engine schedules and runs rotation procedures for manual routes. Run drives
// one Engine; all methods are safe for concurrent use.
type Engine struct {
	store *pool.Store
	log   *slog.Logger
	// Now is the clock used for scheduling; tests replace it.
	Now func() time.Time

	rotations atomic.Uint64 // completed rotations that observed a changed IP

	// dial and probeTLS are seams for tests. Production dials through the
	// route's SOCKS endpoint and always verifies the ip-check certificate.
	dial     func(ctx context.Context, pu *url.URL, target string, timeout time.Duration) (net.Conn, error)
	probeTLS func(host string) *tls.Config

	wake chan struct{} // capacity 1: a procedure finished, re-evaluate now

	mu     sync.Mutex
	due    map[string]time.Time // canonical route ID -> next attempt
	active map[string]*pool.Proxy
	consec map[string]int // canonical route ID -> consecutive same-IP outcomes
}

// New builds an Engine over a generation store.
func New(store *pool.Store, log *slog.Logger) *Engine {
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

// Rotations reports how many rotations completed with a verified new egress IP.
func (e *Engine) Rotations() uint64 { return e.rotations.Load() }

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
		if p == nil || !gen.Pool.Contains(p) {
			continue
		}
		first, ok := e.baselineProbe(ctx, gen, spec, gen.Config.Rotation.IPCheckTimeout)
		if !ok {
			e.log.Warn("boot baseline probe failed; the route starts unverified",
				"route", p.URL.Host)
			continue
		}
		second, ok := e.baselineProbe(ctx, gen, spec, gen.Config.Rotation.IPCheckTimeout)
		if !ok {
			p.SetBaselineIP(first)
			continue
		}
		if first != second {
			e.log.Warn("route egress IP changed between boot probes without a rotation; provider IPs are not sticky",
				"route", p.URL.Host)
		}
		p.SetBaselineIP(second)
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
			return
		}
		p := gen.Pool.Lookup(id)
		if p == nil {
			continue
		}
		e.active[id] = p
		active++
		go e.runProcedure(ctx, gen, spec, p, id)
	}
}

func (e *Engine) runProcedure(ctx context.Context, gen *pool.Generation, spec config.ManualRouteSpec, p *pool.Proxy, id string) {
	defer e.finishProcedure(id)

	// gone reports that the procedure must stop: shutdown, or a reload
	// removed or replaced this route.
	gone := func() bool { return ctx.Err() != nil || !gen.Pool.Contains(p) }
	if p == nil || gone() {
		return
	}

	settings := gen.Config.Rotation
	log := e.log.With("route", p.URL.Host, "kind", string(p.Kind))

	p.BeginRotation(pool.RotationDraining)
	log.Debug("rotation procedure started", "phase", "draining")

	// 1. Drain in-flight work, bounded by rotation.drain-timeout. Expiry
	// abandons the wait and rotates anyway: in-flight work keeps running
	// on its existing tunnels, none are broken.
	drainDeadline := e.Now().Add(settings.DrainTimeout)
	for p.InFlight() > 0 {
		if !e.Now().Before(drainDeadline) {
			log.Warn("drain timeout expired; forcing rotation")
			break
		}
		if gone() {
			p.AbandonRotation()
			return
		}
		if !sleepCtx(ctx, drainPoll) {
			p.AbandonRotation()
			return
		}
	}
	if gone() {
		p.AbandonRotation()
		return
	}

	// 2. Baseline: what the egress IP is before rotating. Without it the
	// rotation can only be verified as "not colliding with other routes".
	p.SetRotationPhase(pool.RotationRotating)
	baseline, verified := e.baselineProbe(ctx, gen, spec, settings.IPCheckTimeout)
	if gone() {
		p.AbandonRotation()
		return
	}
	if !verified {
		log.Warn("baseline probe failed; rotating without IP comparison")
	}

	// 3. Call the provider rotate API, directly — never through the pool.
	retryAfter, apiErr := e.callRotateAPI(ctx, spec.API)

	// 4. Verify: the egress IP must actually have changed. Carriers can hand
	// back the same address, which does not count as a rotation.
	p.SetRotationPhase(pool.RotationVerifying)
	newIP, changed := e.verify(ctx, gen, spec, p, baseline, verified, settings, apiErr != nil)

	if gone() {
		p.AbandonRotation()
		return
	}
	if apiErr != nil {
		log.Warn("rotate API call failed", "error", sanitize.ErrorString(apiErr))
	}
	if !changed {
		consecutive := e.bumpConsecutive(id)
		backoff := BackoffFor(spec.RotateInterval, consecutive, settings.RetryBackoffMax)
		if retryAfter > backoff {
			backoff = retryAfter
		}
		gen.Pool.MarkStale(p, backoff, consecutive)
		e.setDue(id, e.Now().Add(backoff))
		log.Warn("rotation did not change the egress IP; retrying",
			"consecutive_same_ip", consecutive, "retry_in", backoff.Truncate(time.Millisecond).String())
		return
	}

	// 5. Success: the new IP becomes the baseline, dial health earned by the
	// old IP is discarded, and the route serves fresh.
	e.clearConsecutive(id)
	p.MarkRotated()
	p.EndRotation(newIP, e.Now())
	e.rotations.Add(1)
	e.setDue(id, e.Now().Add(spec.RotateInterval))
	log.Info("rotation complete", "egress_ip", newIP,
		"next_in", spec.RotateInterval.Truncate(time.Millisecond).String())
}

// verify polls the route's egress IP until it differs from the baseline and
// no other manual route reports it. With an unknown baseline any
// non-colliding IP counts. apiFailed shortens the window to a single probe:
// the call failed, but the provider may have rotated anyway.
func (e *Engine) verify(ctx context.Context, gen *pool.Generation, spec config.ManualRouteSpec, p *pool.Proxy, baseline string, verified bool, settings config.RotationSettings, apiFailed bool) (string, bool) {
	deadline := e.Now().Add(settings.IPCheckTimeout)
	for attempt := 0; ; attempt++ {
		if ctx.Err() != nil {
			return "", false
		}
		if apiFailed && attempt >= 1 {
			return "", false
		}
		if attempt > 0 {
			pause := settings.IPCheckInterval
			if remaining := time.Until(deadline); remaining < pause {
				pause = remaining
			}
			if !sleepCtx(ctx, pause) || !e.Now().Before(deadline) {
				return "", false
			}
		}
		remaining := settings.IPCheckTimeout
		if d := time.Until(deadline); d > 0 && d < remaining {
			remaining = d
		}
		ip, err := e.probeIP(ctx, gen, spec, remaining)
		if err != nil {
			continue
		}
		if verified && ip == baseline {
			continue
		}
		if gen.Pool.LastIPs(p)[ip] {
			// The "new" IP is another manual route's current address; that
			// defeats rotating either route. Keep waiting for a distinct one.
			continue
		}
		return ip, true
	}
}

func (e *Engine) finishProcedure(id string) {
	e.mu.Lock()
	delete(e.active, id)
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
