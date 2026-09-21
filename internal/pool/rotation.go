// Rotation state transitions driven by the rotation engine
// (internal/rotation). Serving paths never call these: they only read state
// through PickFor and Snapshot.
package pool

import (
	"errors"
	"time"

	"rotation-proxy-gateway/internal/config"
)

// BeginRotation makes a manual route ineligible for new picks and records the
// first phase of its rotation procedure. The route stays out of picks until
// EndRotation or MarkStale returns it to serving; in-flight requests picked
// before BeginRotation keep running and drain on their own.
//
// It is also the only writer of the rotation epoch, advanced after the
// rotating flag is set: anything stamped with an older epoch was established
// before this procedure began and — however the procedure ends — predates the
// route's next verified egress IP. The flag-then-epoch order means a reader
// that still sees rotating == false also still sees the old epoch, so nothing
// can start through the beginning of a rotation and validate as the new
// generation.
func (p *Proxy) BeginRotation(phase RotationState) {
	p.rotating.Store(true)
	p.rotationEpoch.Add(1)
	p.mu.Lock()
	p.rotationState = phase
	p.nextRetryIn = 0
	p.mu.Unlock()
}

// SetRotationPhase advances the displayed phase (draining → rotating →
// verifying) of a rotation already begun. The rotating flag and the state
// write are guarded by the same lock that the terminal transitions
// (EndRotation, MarkStale, AbandonRotation) use to clear the flag, so a
// procedure finishing concurrently can never have its terminal state
// overwritten by a late phase write — checking the flag outside the lock
// would race exactly that window.
func (p *Proxy) SetRotationPhase(phase RotationState) {
	p.mu.Lock()
	if p.rotating.Load() {
		p.rotationState = phase
	}
	p.mu.Unlock()
}

// EndRotation records a rotation that observed a changed egress IP and returns
// the route to serving. The recency pass is not advanced, so the freshly
// verified route is the least recently used and absorbs traffic first. Dial
// health is left to MarkRotated. The flag clears under p.mu so SetRotationPhase's
// guarded check cannot slip between the state write and the flag clear.
//
// The rotation engine must not call this directly with a candidate that only
// an unlocked check cleared: it records unconditionally, so two procedures
// that verified the same address could both commit it. CommitRotation is the
// engine's seam — the collision check and this record as one section.
func (p *Proxy) EndRotation(ip string, at time.Time) {
	p.mu.Lock()
	p.rotationState = RotationIdle
	p.lastIP = ip
	p.lastRotationAt = at
	p.nextRetryIn = 0
	p.consecutiveSameIP = 0
	p.rotating.Store(false)
	p.mu.Unlock()
}

// ErrRotationCollision reports that CommitRotation rejected a candidate egress
// IP because another manual route already holds it as its current verified
// address. Fixed text only: it flows into sanitized logs.
var ErrRotationCollision = errors.New("egress IP collides with another manual route")

// CommitRotation records ip as p's verified new egress IP and returns the
// route to serving — unless another manual route in this pool already holds
// the same address, in which case nothing is written and the caller treats
// the candidate as rejected, not the rotation as failed. The collision scan
// and the record are one critical section: two rotation procedures that
// verified the same candidate concurrently cannot both commit it — the loser
// observes the winner's address under the lock. Dial health stays with
// MarkRotated, which the caller runs only after a successful commit.
func (pl *Pool) CommitRotation(p *Proxy, ip string, at time.Time) error {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	for _, e := range pl.entries {
		if e == p || e.Origin != config.RouteOriginManual {
			continue
		}
		e.mu.Lock()
		collides := e.lastIP != "" && e.lastIP == ip
		e.mu.Unlock()
		if collides {
			return ErrRotationCollision
		}
	}
	p.EndRotation(ip, at)
	return nil
}

// MarkStale returns a route to serving after a rotation that did not change
// its egress IP. It records the retry wait and the run of same-IP rotations,
// and jumps the route to the recency back so picks prefer fresher routes
// until the next rotation attempt. The flag clears under p.mu, as in
// EndRotation.
func (pl *Pool) MarkStale(p *Proxy, nextRetryIn time.Duration, consecutiveSameIP int) {
	p.mu.Lock()
	p.rotationState = RotationStale
	p.nextRetryIn = nextRetryIn
	p.consecutiveSameIP = consecutiveSameIP
	p.rotating.Store(false)
	p.mu.Unlock()
	pl.jumpToBack(p)
}

// MarkRotated clears dial-failure health accumulated against the previous
// egress IP: the cooldown and consecutive-failure count describe an address
// the route no longer uses. Authentication blocks are deliberately unchanged —
// credentials did not rotate with the IP.
func (p *Proxy) MarkRotated() {
	p.mu.Lock()
	p.consecutiveFailures = 0
	p.lastDialError = ""
	p.mu.Unlock()
	p.cooldownUntil.Store(0)
}

// AbandonRotation returns a route to serving when its rotation procedure is
// canceled mid-flight (route removed or identity changed by a reload). A route
// whose last verified rotation did not change its IP goes back to stale rather
// than idle: idle would wrongly suggest a verified-fresh route.
func (p *Proxy) AbandonRotation() {
	p.mu.Lock()
	switch p.rotationState {
	case RotationDraining, RotationRotating, RotationVerifying:
		if p.consecutiveSameIP > 0 {
			p.rotationState = RotationStale
		} else {
			p.rotationState = RotationIdle
		}
	}
	p.nextRetryIn = 0
	p.rotating.Store(false)
	p.mu.Unlock()
}

// LastIPs returns the last verified egress IP of every manual route other than
// exclude. The rotation engine rejects a "new" IP that duplicates one of
// these: two manual routes serving from the same address defeats the purpose
// of rotating either.
func (pl *Pool) LastIPs(exclude *Proxy) map[string]bool {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	out := make(map[string]bool)
	for _, e := range pl.entries {
		if e == exclude || e.Origin != config.RouteOriginManual {
			continue
		}
		e.mu.Lock()
		if e.lastIP != "" {
			out[e.lastIP] = true
		}
		e.mu.Unlock()
	}
	return out
}

// LastIP returns the route's last verified egress IP, or "" before the first
// verified observation.
func (p *Proxy) LastIP() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastIP
}

// SetBaselineIP records an observed egress IP before any rotation has run —
// the boot precheck uses it so cross-route collision checks and the status
// view have a starting point. Unlike EndRotation it records no rotation time,
// and it never overwrites a known IP: a slow boot probe must not clobber the
// baseline a rotation recorded while the probe was in flight.
func (p *Proxy) SetBaselineIP(ip string) {
	p.mu.Lock()
	if p.lastIP == "" {
		p.lastIP = ip
	}
	p.mu.Unlock()
}

// Contains reports whether p is part of this pool's route list. The rotation
// engine re-checks between procedure steps: a reload that removed or replaced
// the route makes the procedure's proxy stale, and the procedure must abort.
func (pl *Pool) Contains(p *Proxy) bool {
	if p == nil {
		return false
	}
	pl.mu.Lock()
	defer pl.mu.Unlock()
	for _, e := range pl.entries {
		if e == p {
			return true
		}
	}
	return false
}

// Lookup returns the route with the given canonical route ID, or nil. The
// engine maps config route specs onto pool entries with it.
func (pl *Pool) Lookup(id string) *Proxy {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	for _, e := range pl.entries {
		if config.CanonicalRouteID(e.URL)+"|"+string(e.Kind) == id {
			return e
		}
	}
	return nil
}
