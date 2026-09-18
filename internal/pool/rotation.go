// Rotation state transitions driven by the rotation engine
// (internal/rotation). Serving paths never call these: they only read state
// through PickFor and Snapshot.
package pool

import (
	"time"

	"rotation-proxy-gateway/internal/config"
)

// BeginRotation makes a manual route ineligible for new picks and records the
// first phase of its rotation procedure. The route stays out of picks until
// EndRotation or MarkStale returns it to serving; in-flight requests picked
// before BeginRotation keep running and drain on their own.
func (p *Proxy) BeginRotation(phase RotationState) {
	p.mu.Lock()
	p.rotating = true
	p.rotationState = phase
	p.nextRetryIn = 0
	p.mu.Unlock()
}

// SetRotationPhase advances the displayed phase (draining → rotating →
// verifying) of a rotation already begun. It is a no-op once the route left
// the rotating set, so a stale procedure can never resurrect the flag.
func (p *Proxy) SetRotationPhase(phase RotationState) {
	p.mu.Lock()
	if p.rotating {
		p.rotationState = phase
	}
	p.mu.Unlock()
}

// EndRotation records a rotation that observed a changed egress IP and returns
// the route to serving. The usedSeq is not bumped, so the freshly verified
// route is the least recently used and absorbs traffic first. Dial health is
// left to MarkRotated.
func (p *Proxy) EndRotation(ip string, at time.Time) {
	p.mu.Lock()
	p.rotating = false
	p.rotationState = RotationIdle
	p.lastIP = ip
	p.lastRotationAt = at
	p.nextRetryIn = 0
	p.consecutiveSameIP = 0
	p.mu.Unlock()
}

// MarkStale returns a route to serving after a rotation that did not change
// its egress IP. It records the retry wait and the run of same-IP rotations,
// and pushes the route to the LRU back so picks prefer fresher routes until
// the next rotation attempt.
func (pl *Pool) MarkStale(p *Proxy, nextRetryIn time.Duration, consecutiveSameIP int) {
	p.mu.Lock()
	p.rotating = false
	p.rotationState = RotationStale
	p.nextRetryIn = nextRetryIn
	p.consecutiveSameIP = consecutiveSameIP
	p.usedSeq = pl.nextSeq()
	p.mu.Unlock()
}

// MarkRotated clears dial-failure health accumulated against the previous
// egress IP: the cooldown and consecutive-failure count describe an address
// the route no longer uses. Authentication blocks are deliberately unchanged —
// credentials did not rotate with the IP.
func (p *Proxy) MarkRotated() {
	p.mu.Lock()
	p.consecutiveFailures = 0
	p.cooldownUntil = time.Time{}
	p.lastDialError = ""
	p.mu.Unlock()
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
	p.rotating = false
	p.nextRetryIn = 0
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
