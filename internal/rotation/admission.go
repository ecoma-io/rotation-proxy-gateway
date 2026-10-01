// Traffic admission: the one thing that differs between the disruptive and the
// seamless manual-rotation modes.
//
// Both modes run the same RotationProcedure — drain, baseline probe, rotate
// call, verify — and both record their outcome through the same pool
// transitions. A policy decides only one question, at each phase boundary: is
// this route allowed to take new picks right now?
//
// It answers that question by constraining the pool's existing eligibility, not
// by adding one. Proxy.rotating is the single flag Pool.PickFor already reads
// on both of its paths — the ordinary candidate scan and the all-cooling
// fallback — so "admitting traffic" is exactly the ability to set and clear that
// flag. A mode that keeps serving across the rotation needs a hold that is not a
// whole-procedure flag, and the pool expresses that in the same vocabulary: a
// bounded hold deadline, checked by the same eligibility predicate the flag is
// checked by, on both of those paths. A policy raises and clears eligibility
// through those two doors and nothing else. Cooldown, auth block and pair
// cooldown are unreachable from here, which is what keeps the policy from
// becoming a second eligibility mechanism that could disagree with the first.
//
// Epoch handling is likewise untouched by the mode: the rotation epoch advances
// exactly once per procedure, and both modes do it at Admit. The warm pool
// discards a parked connection whose stamped epoch no longer equals the route's
// current one, so bumping the epoch while the route is still serving — the
// seamless case — discards exactly the connections established under the old
// egress IP, while a connection stamped after the bump is fresh and eligible.
// Both modes keep the invariant without a mode-specific branch.
package rotation

import (
	"sync"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"

	"github.com/rs/zerolog"
)

// TrafficAdmissionPolicy decides, at each phase boundary of one rotation
// procedure, whether its route may take new picks.
//
// Implementations act only on the pool's rotation eligibility: they take the
// route out of picks through BeginRotation, through a bounded HoldRotationUntil
// hold, or both, and let it back in by clearing what they raised. They must not
// touch any other aspect of route health. A policy that did could put the route
// into a state the request path does not expect and that no pool transition
// reconciles.
//
// Every method is called from the single goroutine running its procedure, at
// that procedure's phase boundaries only, and never concurrently with itself.
// That is a property of where the procedure calls them, not something a policy
// may rely on for cross-route work: policies for different routes run in
// different goroutines.
type TrafficAdmissionPolicy interface {
	// Name reports the mode this policy implements, for logs and /status.
	Name() string

	// Admit records that the procedure for p has begun at phase. The pool's
	// rotating flag and the route's rotation epoch move here (disruptive), or
	// the procedure is admitted as invisible traffic (seamless).
	Admit(p *pool.Proxy, phase pool.RotationState, log zerolog.Logger)

	// HoldTraffic announces the changeover: from here until it completes, the
	// route takes no new picks. A disruptive route is already out of picks and
	// has nothing to announce; a seamless route opens a bounded hold here and
	// closes it in Settle.
	HoldTraffic(p *pool.Proxy, log zerolog.Logger)

	// ShouldContinue reports whether the drain loop should keep waiting, and
	// the instant it is willing to wait to: the effective deadline, which is
	// the earlier of the caller's configured drain timeout and whatever bound
	// the mode imposes. A disruptive route's drain is bounded by
	// rotation.drain-timeout alone; seamless adds a hard bound so a changeover
	// can never be held open by continuous load.
	ShouldContinue(p *pool.Proxy, now, deadline time.Time) (keep bool, until time.Time)

	// Settle closes whatever HoldTraffic opened once the changeover is settled — a
	// candidate committed or verification given up — and reports whether it
	// actually released a hold. attempt is the route's rotation epoch as of
	// Admit, so a changeover can only ever be closed by the procedure that
	// opened it. A mode that holds nothing back reports false.
	Settle(p *pool.Proxy, attempt uint64, log zerolog.Logger) bool

	// Readmit returns a route to service when a procedure ends without a
	// terminal rotation state of its own — shutdown, or a reload that removed
	// or replaced the route. Transitions that do record an outcome (a verified
	// commit, an unchanged IP) are left to the pool transitions themselves and
	// never reach this.
	Readmit(p *pool.Proxy, log zerolog.Logger)
}

// Mode is a manual route's traffic-admission mode. It is an alias for the
// configuration type rather than a second type: the mode is configuration, it
// is validated as configuration, and the engine reads it straight off the
// validated settings. One type means the value that passed validation is
// exactly the value the policy is chosen from, with no conversion in between
// that could disagree about what was configured.
type Mode = config.RotationMode

const (
	// ModeSeamless keeps serving traffic on the route across the rotation.
	ModeSeamless = config.RotationModeSeamless
	// ModeDisruptive takes the route out of service for the rotation and
	// re-admits it after verification.
	ModeDisruptive = config.RotationModeDisruptive
)

// ChangeoverTimeout bounds the gap between a seamless route's changeover
// opening and its traffic being admitted again — the cap on how long a route
// serving through a rotation may spend out of picks. It is a property of the
// mode, not a configuration knob: a seamless rotation that cannot complete
// within it resumes admitting traffic rather than holding the route out
// indefinitely.
//
// The same budget bounds the drain (see ShouldContinue) and the hold (see
// HoldTraffic), both measured from the moment the procedure was admitted, so a
// procedure cannot spend ChangeoverTimeout in the drain and then hold for it
// again across the changeover.
//
// It must be short enough to sit inside an ordinary rotation attempt, whose
// verify window is rotation.ip-check-timeout (20s by default), and comfortably
// above the healthy path: a route whose provider rotates immediately needs
// milliseconds.
const ChangeoverTimeout = 10 * time.Second

// changeoverDeadline is the instant a changeover must be over by: the instant
// the route was admitted plus ChangeoverTimeout. The drain is bounded to it and
// the hold is bounded to it, both anchored at the same instant, so the two
// halves of the mode spend one budget rather than each getting their own.
//
// Measuring from Admit rather than from the moment the hold opens is what keeps
// the hold bounded: the drain, the baseline probe and the rotate call all run
// first, and whatever they spent is gone. A changeover that opens after the
// budget is already spent gets no hold at all, which is the same statement the
// drain loop makes when it stops waiting.
func changeoverDeadline(visibleAt time.Time) time.Time {
	return visibleAt.Add(ChangeoverTimeout)
}

// seamState is the live state of one route's seamless changeover: the instant
// the procedure became traffic-visible, the instant its hold opened, and which
// attempt that hold belongs to.
//
// The attempt number is the guard against a second changeover for one rotation
// closing a hold the first one is still waiting on: each attempt holds under
// its own number, so a concurrent retry can never release the current
// generation's hold. heldAt is what makes "already held" answerable, so Settle
// releases a hold once however many times it is asked to.
type seamState struct {
	visibleAt   time.Time
	heldAt      time.Time
	heldAttempt uint64
}

// seamlessPolicy is the seamless TrafficAdmissionPolicy. It admits the route to
// traffic for the whole procedure and holds the route out of picks only across
// the changeover itself, which is the smallest window the provider swapping the
// egress IP underneath it can affect.
//
// The distinction is the point of the mode, and it comes from a documented
// property of the upstream rather than an assumption: the gateway's own
// AGENTS.md and docs/rotation.md both state that in-flight work keeps running
// on its existing tunnels and finishes on the egress IP it started with. A
// disruptionless changeover is therefore possible — a CONNECT in progress
// completes on the IP it began with — and only connections opened during the
// changeover can observe it mid-flight. The hold keeps exactly those out, so the
// route serves continuously except across the swap.
type seamlessPolicy struct {
	now func() time.Time

	mu    sync.Mutex
	seams map[*pool.Proxy]*seamState
}

// newSeamlessPolicy builds the seamless policy over the engine's clock. The map
// is lazily allocated so the policy is usable before its first rotation.
func newSeamlessPolicy(now func() time.Time) *seamlessPolicy {
	return &seamlessPolicy{now: now, seams: map[*pool.Proxy]*seamState{}}
}

// Name reports the seamless mode.
func (s *seamlessPolicy) Name() string { return string(ModeSeamless) }

// Admit records that the procedure for p began, without taking the route out of
// picks: the route was already serving and keeps serving. What moves is the
// rotation epoch, which is what retires the warm connections established under
// the old egress IP.
//
// The epoch is advanced through pool.AdmitRotationEpoch rather than
// BeginRotation, because BeginRotation's other effect is precisely the one this
// mode must not use at this point: it raises the rotating flag that takes a
// route out of picks for the whole procedure. AdmitRotationEpoch is the epoch
// half of that same operation, exposed separately so a mode that keeps serving
// can invalidate its old-generation connections without claiming the route is
// out of service. The flag-then-epoch ordering argument on BeginRotation does not
// apply here — this mode raises no flag at Admit — and nothing needs it to: a
// seamless route has no window in which it is simultaneously ineligible and
// advertising a new epoch. Its hold comes later, once the changeover is actually
// happening, and by then the epoch has long since settled.
//
// The phase argument is not recorded: a seamless route stays in its previous
// display state for the whole procedure, because it never stops serving and
// there is no phase to report. Its changeover is bounded by its own deadlines.
func (s *seamlessPolicy) Admit(p *pool.Proxy, _ pool.RotationState, _ zerolog.Logger) {
	if p == nil {
		return
	}
	p.AdmitRotationEpoch()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seams == nil {
		s.seams = map[*pool.Proxy]*seamState{}
	}
	s.seams[p] = &seamState{visibleAt: s.now()}
}

// HoldTraffic opens the changeover hold: from now until the changeover
// completes, the route takes no new picks, so nothing is opened against an
// egress IP that is mid-swap. In-flight requests are untouched and finish on
// the tunnels they already have, which is what the mode promises.
//
// The hold is a deadline rather than a flag, so it cannot outlive its bound:
// the pool serves the route again once the deadline passes whether or not the
// procedure survives to close it, and Settle closes it early whenever the
// changeover completes inside the window. The deadline is anchored at Admit, not
// here — see changeoverDeadline — so the drain and the rotate call spend the
// same budget the hold is drawn from and a slow provider cannot reopen a window
// it has already spent.
func (s *seamlessPolicy) HoldTraffic(p *pool.Proxy, log zerolog.Logger) {
	if p == nil {
		return
	}
	s.mu.Lock()
	st := s.seamStateLocked(p)
	if st == nil {
		s.mu.Unlock()
		return
	}
	heldAt := s.now()
	st.heldAt = heldAt
	st.heldAttempt = p.RotationEpoch()
	visibleAt := st.visibleAt
	until := changeoverDeadline(visibleAt)
	// The hold is the remainder of the changeover budget, so it can be zero — a
	// drain that ran to the deadline has spent it all — and a zero-length hold is
	// the right answer then: the changeover is already over budget, so the route
	// takes picks again immediately rather than opening a window the mode has no
	// budget for. The pool decides that, from the elapsed deadline, rather than
	// the policy second-guessing it here.
	holdFor := until.Sub(heldAt)
	s.mu.Unlock()
	p.HoldRotationUntil(until)
	// Two numbers, because they answer two questions an operator reading a stuck
	// rotation will ask: hold is how long this route is out of picks, and it can
	// be shorter than budget_left if the changeover settles first; budget_left is
	// the whole budget, and it is what bounds the hold even if nothing settles it.
	log.Debug().Str("traffic", "held back").
		Str("hold", max(holdFor, 0).Truncate(time.Millisecond).String()).
		Str("budget_left", until.Sub(visibleAt).Truncate(time.Millisecond).String()).
		Msg("seamless changeover opened; route takes no new picks until it completes")
}

// ShouldContinue bounds the drain by the changeover budget as well as by the
// configured drain timeout, and reports the earlier of the two.
//
// The budget is anchored to the moment the procedure was admitted, not to the
// instant of this call: a bound recomputed from now would be "ten more
// seconds" on every poll and so could never be reached by a route under
// continuous load, which is exactly the case the bound exists for.
func (s *seamlessPolicy) ShouldContinue(p *pool.Proxy, now, deadline time.Time) (bool, time.Time) {
	s.mu.Lock()
	var started time.Time
	if p != nil {
		if st := s.seams[p]; st != nil {
			started = st.visibleAt
		}
	}
	s.mu.Unlock()
	if started.IsZero() {
		return now.Before(deadline), deadline
	}
	if cut := changeoverDeadline(started); cut.Before(deadline) {
		return now.Before(cut), cut
	}
	return now.Before(deadline), deadline
}

// Readmit clears the changeover and forgets the route. It releases the hold as
// well as the bookkeeping, because Readmit is the abort path and Settle — the
// only other release — does not run on it: a rotation cut short by shutdown or
// by a reload that dropped the route would otherwise leave the route out of
// picks until its deadline. Releasing here does not release anything a hold
// deadline was still covering, because a bounded hold expires on its own if no
// procedure survives to close it.
//
// The pool's own terminal transitions clear the rotating flag, which a seamless
// route never raised; the epoch deliberately stays advanced, so a connection
// borrowed under the old egress IP is still discarded afterwards.
func (s *seamlessPolicy) Readmit(p *pool.Proxy, _ zerolog.Logger) {
	if p == nil {
		return
	}
	p.ReleaseRotationHold()
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.seams, p)
}

// seamStateLocked returns p's changeover state, allocating it for a route a
// reload re-admitted after the previous attempt forgot it.
func (s *seamlessPolicy) seamStateLocked(p *pool.Proxy) *seamState {
	if s.seams == nil {
		s.seams = map[*pool.Proxy]*seamState{}
	}
	st := s.seams[p]
	if st == nil {
		st = &seamState{visibleAt: s.now()}
		s.seams[p] = st
	}
	return st
}

// Settle closes the holdback this procedure opened, returns the route to picks,
// and reports whether it was still held.
//
// The attempt check is what makes a changeover belong to one procedure: it runs
// under s.mu against the seam state, so an attempt number that has moved on
// means the hold being tested is not the one this procedure opened — a newer
// changeover's hold is left exactly as it is rather than released early.
func (s *seamlessPolicy) Settle(p *pool.Proxy, attempt uint64, _ zerolog.Logger) bool {
	if p == nil {
		return false
	}
	s.mu.Lock()
	st := s.seams[p]
	released := st != nil && st.heldAttempt == attempt && !st.heldAt.IsZero()
	if released {
		st.heldAt = time.Time{}
	}
	s.mu.Unlock()
	// Released outside s.mu: the pool call takes p.mu, and holding the seam lock
	// across it would invert the order every other path takes.
	if !released {
		return false
	}
	p.ReleaseRotationHold()
	return true
}

// disruptivePolicy is the disruptive TrafficAdmissionPolicy: the route leaves
// service for the whole procedure and is re-admitted by whichever terminal
// transition records the outcome.
type disruptivePolicy struct{}

func (disruptivePolicy) Name() string { return string(ModeDisruptive) }

// Admit takes the route out of picks and advances its rotation epoch, the way
// every rotation has behaved.
func (disruptivePolicy) Admit(p *pool.Proxy, phase pool.RotationState, _ zerolog.Logger) {
	p.BeginRotation(phase)
}

// HoldTraffic is a no-op: the route is already out of picks.
func (disruptivePolicy) HoldTraffic(*pool.Proxy, zerolog.Logger) {}

// ShouldContinue waits on the configured drain timeout alone.
func (disruptivePolicy) ShouldContinue(_ *pool.Proxy, now, deadline time.Time) (bool, time.Time) {
	return now.Before(deadline), deadline
}

// Settle reports no changeover to close: a disruptive rotation held nothing
// back, so there is no hold to release and no attempt stamp to check.
func (disruptivePolicy) Settle(_ *pool.Proxy, _ uint64, _ zerolog.Logger) bool { return false }

// Readmit returns the route to service. The state is chosen from what the
// route already knew — a route whose last rotation did not change its IP goes
// back stale rather than idle.
func (disruptivePolicy) Readmit(p *pool.Proxy, _ zerolog.Logger) { p.AbandonRotation() }
