package pool

import (
	"errors"
	"sync"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
)

func manualSpec(t *testing.T, raw string) config.RouteSpec {
	t.Helper()
	return config.RouteSpec{URL: mustURL(t, raw), Kind: config.EgressV6, Origin: config.RouteOriginManual}
}

func newManualPool(t *testing.T, c *clock, urls ...string) *Pool {
	t.Helper()
	routes := make([]config.RouteSpec, 0, len(urls))
	for _, raw := range urls {
		routes = append(routes, manualSpec(t, raw))
	}
	pl := NewRoutes(routes, 30*time.Second, time.Minute)
	pl.Now = c.NowFunc
	return pl
}

func findStatus(t *testing.T, snap []Status, host string) Status {
	t.Helper()
	for _, s := range snap {
		if s.Proxy == host {
			return s
		}
	}
	t.Fatalf("route %q missing from snapshot %+v", host, snap)
	return Status{}
}

func TestManualOnlyPoolServes(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1", "socks5://m2:2")

	if got := pl.PickFor(nil, nil, "t:443").URL.Host; got != "m1:1" {
		t.Fatalf("pick = %s, want m1:1", got)
	}
	snap := pl.Snapshot()
	a := findStatus(t, snap, "m1:1")
	if a.Origin != "manual" || !a.Available || a.Rotation == nil || a.Rotation.State != "idle" {
		t.Fatalf("manual snapshot = %+v", a)
	}
	b := findStatus(t, snap, "m2:2")
	if b.Rotation == nil || b.Rotation.State != "idle" {
		t.Fatalf("rotation view should exist on every manual route: %+v", b)
	}
}

func TestPickForSkipsRotatingRoute(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1", "socks5://m2:2")
	rotating := pl.entries[0]

	// Prime the LRU so m2 would normally be next; the rotating flag must win.
	pl.PickFor(nil, nil, "t:443")
	rotating.BeginRotation(RotationDraining)

	for range 3 {
		if got := pl.PickFor(nil, nil, "t:443").URL.Host; got != "m2:2" {
			t.Fatalf("pick = %s, want m2:2 while m1 rotates", got)
		}
	}
	snap := pl.Snapshot()
	a := findStatus(t, snap, "m1:1")
	if a.Available || a.Rotation.State != "draining" {
		t.Fatalf("rotating route snapshot = %+v", a)
	}
}

func TestAllCoolingFallbackSkipsRotatingRoute(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1", "socks5://m2:2")

	// m1 cooling, m2 rotating: the fallback must not select m2 even though it
	// recovers "soonest"; it selects the cooling m1 instead.
	pl.ReportFailure(pl.entries[0], nil)
	pl.entries[1].BeginRotation(RotationRotating)

	if got := pl.PickFor(nil, nil, "t:443"); got == nil || got.URL.Host != "m1:1" {
		t.Fatalf("fallback pick = %v, want cooling m1:1", got)
	}

	// m2 back to serving: it wins again over the still-cooling m1? No — m1
	// recovers sooner only when all entries cool; with m2 eligible the LRU
	// main path applies. Either way m2 must be pickable again.
	pl.entries[1].AbandonRotation()
	if got := pl.PickFor(nil, nil, "t:443"); got == nil {
		t.Fatalf("pick = nil after abandoning rotation, want any eligible route")
	}
}

// TestChangeoverHoldSkipsRouteUntilReleased covers the seamless changeover
// hold as the serving path sees it. HoldRotationUntil is the same eligibility
// mechanism BeginRotation raises, so the assertions are the ones
// TestPickForSkipsRotatingRoute makes: the held route leaves ordinary picks,
// and comes back when the hold is released.
//
// The clock is the pool's own, pinned past processStart, because the hold is
// stored through relNanos and read back through the real clock by RotationHeld —
// the same arrangement TestRotationPredicatesAndRoutePointers needs.
func TestChangeoverHoldSkipsRouteUntilReleased(t *testing.T) {
	c := &clock{now: processStart.Add(time.Hour)}
	pl := newManualPool(t, c, "socks5://m1:1", "socks5://m2:2")
	held := pl.entries[0]

	if got := held.RotationHoldUntil(); !got.IsZero() {
		t.Fatalf("fresh route has a hold deadline: %v", got)
	}
	// Prime the LRU so m2 would normally be next; the hold must win.
	pl.PickFor(nil, nil, "t:443")
	held.HoldRotationUntil(c.now.Add(5 * time.Second))
	if !held.RotationHeld() {
		t.Fatal("held route does not report RotationHeld")
	}
	for range 3 {
		if got := pl.PickFor(nil, nil, "t:443").URL.Host; got != "m2:2" {
			t.Fatalf("pick = %s, want m2:2 while m1 is held", got)
		}
	}
	if a := findStatus(t, pl.Snapshot(), "m1:1"); a.Available {
		t.Fatalf("held route reports available: %+v", a)
	}

	// A hold does not claim a rotation is running: the flag stays clear, so the
	// route keeps the display state it had. That is what separates this from
	// BeginRotation, and it is why the phase write the engine makes after the
	// changeover is correctly a no-op here.
	if held.RotatingNow() {
		t.Fatal("held route reports a running rotation")
	}
	if st := findStatus(t, pl.Snapshot(), "m1:1").Rotation; st.State != "idle" {
		t.Fatalf("held route display state = %q, want idle", st.State)
	}

	held.ReleaseRotationHold()
	if held.RotationHeld() || !held.RotationHoldUntil().IsZero() {
		t.Fatal("released route still reports a hold")
	}
	// The released route is pickable again, and the hold left the LRU order
	// alone: m2 was served three times above, so m1 is the fresher route.
	if got := pl.PickFor(nil, nil, "t:443").URL.Host; got != "m1:1" {
		t.Fatalf("pick after release = %s, want m1:1", got)
	}
}

// TestChangeoverHoldExpiresWithoutRelease is the bound that makes the hold safe:
// it is a deadline, not a flag, so a procedure that dies without closing it
// cannot keep the route out of picks past that deadline. This is the property
// that lets the rotation policy open a hold without having to prove, on every
// path out of a procedure, that something releases it.
//
// The deadline is anchored to the real clock rather than the injected one,
// because that is the clock heldAt is read against in production: the bound has
// to hold in wall time, not only in the pool's own. A one-millisecond deadline
// and a real sleep cover both readings.
func TestChangeoverHoldExpiresWithoutRelease(t *testing.T) {
	c := &clock{now: processStart.Add(time.Hour)}
	pl := newManualPool(t, c, "socks5://m1:1", "socks5://m2:2")
	p := pl.entries[0]

	p.HoldRotationUntil(time.Now().Add(time.Millisecond))
	time.Sleep(5 * time.Millisecond)
	if p.RotationHeld() {
		t.Fatal("hold outlived its deadline on the real clock")
	}
	if got := pl.PickFor(nil, nil, "t:443").URL.Host; got != "m1:1" {
		t.Fatalf("pick = %s, want m1:1 after the hold expired", got)
	}

	// A deadline already elapsed opens no hold at all. This is what a changeover
	// looks like when its drain spent the whole budget.
	p.HoldRotationUntil(time.Now().Add(-time.Second))
	if p.RotationHeld() {
		t.Fatal("a hold with an elapsed deadline reports held")
	}
	if got := pl.PickFor(nil, nil, "t:443").URL.Host; got != "m2:2" {
		t.Fatalf("pick = %s, want m2:2; an elapsed hold changed the pick order", got)
	}
}

// TestAllCoolingFallbackSkipsHeldRoute is the all-cooling half of the hold. The
// fallback is the one path that reaches a route with no cooldown to offer, which
// makes it the path a changeover hold has to reach too: a held route must not be
// handed out as the soonest-recovering option while every other route is
// cooling, because the hold is exactly the statement that this route's egress IP
// is mid-swap.
func TestAllCoolingFallbackSkipsHeldRoute(t *testing.T) {
	c := &clock{now: processStart.Add(time.Hour)}
	pl := newManualPool(t, c, "socks5://m1:1", "socks5://m2:2")

	// m1 cooling, m2 held: the fallback must not select m2 even though it has
	// no cooldown at all and so recovers soonest; it selects the cooling m1.
	pl.ReportFailure(pl.entries[0], nil)
	pl.entries[1].HoldRotationUntil(c.now.Add(5 * time.Second))

	if got := pl.PickFor(nil, nil, "t:443"); got == nil || got.URL.Host != "m1:1" {
		t.Fatalf("fallback pick = %v, want cooling m1:1", got)
	}

	pl.entries[1].ReleaseRotationHold()
	if got := pl.PickFor(nil, nil, "t:443"); got == nil || got.URL.Host != "m2:2" {
		t.Fatalf("pick after release = %v, want m2:2", got)
	}
}

// TestChangeoverHoldIsScopedToOneRouteAndEndsWithTheProcedure proves the two
// things a hold must not do: leak onto another route, or outlive the procedure
// that opened it. Both matter because the pool is shared — a cooldown on one
// route is visible to a listener serving another, and so is a hold.
//
// A terminal transition clears the hold as well as the flag. A disruptive
// rotation never opens one, so that only happens if a route carries both; the
// assertion is that whichever transition ends a rotation ends the hold with it,
// so a route the engine returned to service is genuinely serving.
func TestChangeoverHoldIsScopedToOneRouteAndEndsWithTheProcedure(t *testing.T) {
	c := &clock{now: processStart.Add(time.Hour)}
	pl := newManualPool(t, c, "socks5://m1:1", "socks5://m2:2")
	held, other := pl.entries[0], pl.entries[1]

	held.HoldRotationUntil(c.now.Add(5 * time.Second))
	if other.RotationHeld() {
		t.Fatal("a hold on one route leaked onto another")
	}

	// The three terminal transitions of a rotation, each reopening the hold first
	// so it is the transition under test and not the previous case's leftover.
	for _, tc := range []struct {
		name string
		end  func()
	}{
		{"EndRotation", func() { held.EndRotation("203.0.113.9", c.now) }},
		{"MarkStale", func() { pl.MarkStale(held, time.Second, 1) }},
		{"AbandonRotation", held.AbandonRotation},
	} {
		held.HoldRotationUntil(c.now.Add(5 * time.Second))
		tc.end()
		if held.RotationHeld() {
			t.Fatalf("%s left the route held", tc.name)
		}
	}

	// SetRotationPhase and AdmitRotationEpoch are not terminal and must leave a
	// hold exactly where it was: they are the mid-procedure steps, and the engine
	// runs the first of them while the hold is open.
	held.HoldRotationUntil(c.now.Add(5 * time.Second))
	held.SetRotationPhase(RotationVerifying)
	if !held.RotationHeld() {
		t.Fatal("SetRotationPhase released a hold it does not own")
	}
	held.AdmitRotationEpoch()
	if !held.RotationHeld() {
		t.Fatal("AdmitRotationEpoch released a hold it does not own")
	}
	held.ReleaseRotationHold()
	if held.RotationHeld() {
		t.Fatal("ReleaseRotationHold left the route held")
	}
}

// TestChangeoverHoldDoesNotAdvanceEpoch keeps the hold out of the rotation
// epoch's contract. The epoch is the warm pool's generation stamp and advances
// exactly once per procedure, at Admit; a hold that moved it would retire
// connections stamped under the *new* egress IP, which is the opposite of what
// the hold is for. (TestRotationEpochAdvancesOnlyAtBegin pins the same property
// for the disruptive path.)
func TestChangeoverHoldDoesNotAdvanceEpoch(t *testing.T) {
	c := &clock{now: processStart.Add(time.Hour)}
	pl := newManualPool(t, c, "socks5://m1:1")
	p := pl.entries[0]

	p.AdmitRotationEpoch()
	before := p.RotationEpoch()
	p.HoldRotationUntil(c.now.Add(5 * time.Second))
	if got := p.RotationEpoch(); got != before {
		t.Fatalf("epoch moved on HoldRotationUntil: %d, want %d", got, before)
	}
	p.ReleaseRotationHold()
	if got := p.RotationEpoch(); got != before {
		t.Fatalf("epoch moved on ReleaseRotationHold: %d, want %d", got, before)
	}
	if p.RotatingNow() {
		t.Fatal("the seamless hold raised the rotating flag")
	}
}

func TestInFlightAccounting(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1")

	p := pl.PickFor(nil, nil, "t:443")
	if p.InFlight() != 1 {
		t.Fatalf("InFlight after pick = %d, want 1", p.InFlight())
	}
	q := pl.PickFor(nil, nil, "t:443")
	if q != p || p.InFlight() != 2 {
		t.Fatalf("second pick = %v InFlight = %d, want same route at 2", q, p.InFlight())
	}
	p.Release()
	if p.InFlight() != 1 {
		t.Fatalf("InFlight after release = %d, want 1", p.InFlight())
	}
	p.Release()
	p.Release() // over-release is clamped, never negative
	if p.InFlight() != 0 {
		t.Fatalf("InFlight after over-release = %d, want 0", p.InFlight())
	}
	snap := pl.Snapshot()
	if snap[0].InFlight != 0 {
		t.Fatalf("snapshot InFlight = %d, want 0", snap[0].InFlight)
	}
}

func TestRotationLifecycleTransitions(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1")
	p := pl.entries[0]

	p.BeginRotation(RotationDraining)
	p.SetRotationPhase(RotationRotating)
	p.SetRotationPhase(RotationVerifying)
	if s := findStatus(t, pl.Snapshot(), "m1:1"); s.Available || s.Rotation.State != "verifying" {
		t.Fatalf("mid-rotation snapshot = %+v", s)
	}

	rotatedAt := c.now.Add(30 * time.Second)
	p.EndRotation("203.0.113.9", rotatedAt)
	s := findStatus(t, pl.Snapshot(), "m1:1")
	if !s.Available || s.Rotation.State != "idle" || s.Rotation.LastIP != "203.0.113.9" ||
		s.Rotation.LastRotationAt != rotatedAt.UTC().Format(time.RFC3339) ||
		s.Rotation.NextRetryIn != "" || s.Rotation.ConsecutiveSameIP != 0 {
		t.Fatalf("post-rotation snapshot = %+v", s.Rotation)
	}

	// A stale procedure arriving after EndRotation must not resurrect the
	// rotating flag or change the recorded phase.
	p.BeginRotation(RotationDraining)
	p.EndRotation("203.0.113.10", rotatedAt)
	p.SetRotationPhase(RotationRotating)
	if s := findStatus(t, pl.Snapshot(), "m1:1"); !s.Available || s.Rotation.State != "idle" {
		t.Fatalf("phase set after end leaked: %+v", s.Rotation)
	}
}

// TestRotationEpochAdvancesOnlyAtBegin pins the warm-pool isolation contract:
// the epoch moves exactly once per procedure, at BeginRotation, and no
// terminal transition (EndRotation, MarkStale, AbandonRotation) touches it —
// state stamped with the old epoch stays invalid even when the procedure ends
// without changing the egress IP.
func TestRotationEpochAdvancesOnlyAtBegin(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1", "socks5://m2:2")
	p := pl.entries[0]
	other := pl.entries[1]

	if got := p.RotationEpoch(); got != 0 {
		t.Fatalf("fresh route epoch = %d, want 0", got)
	}
	p.BeginRotation(RotationDraining)
	first := p.RotationEpoch()
	if first != 1 {
		t.Fatalf("epoch after first BeginRotation = %d, want 1", first)
	}
	if got := other.RotationEpoch(); got != 0 {
		t.Fatalf("unrelated route epoch moved: %d", got)
	}

	// Phases, terminal transitions, and a later procedure's begin: only the
	// begin advances the counter.
	p.SetRotationPhase(RotationRotating)
	p.EndRotation("203.0.113.9", c.now)
	if got := p.RotationEpoch(); got != first {
		t.Fatalf("epoch after EndRotation = %d, want %d", got, first)
	}
	p.BeginRotation(RotationVerifying)
	pl.MarkStale(p, time.Second, 1)
	if got := p.RotationEpoch(); got != first+1 {
		t.Fatalf("epoch after MarkStale = %d, want %d", got, first+1)
	}
	p.BeginRotation(RotationDraining)
	p.AbandonRotation()
	if got := p.RotationEpoch(); got != first+2 {
		t.Fatalf("epoch after AbandonRotation = %d, want %d", got, first+2)
	}
}

// TestRotationPredicatesAndRoutePointers covers the narrow exported surface
// background consumers read: the rotating/cooldown predicates and the
// pointer-identity route enumeration. The clock is pinned past processStart
// because CooldownActive reads the real clock while cooldown deadlines are
// stored through the pool's injectable one; a future-pinned fake clock keeps
// the two consistent (deadline still in the real future).
func TestRotationPredicatesAndRoutePointers(t *testing.T) {
	c := &clock{now: processStart.Add(time.Hour)}
	pl := newManualPool(t, c, "socks5://m1:1", "socks5://m2:2")

	pts := pl.RoutePointers()
	if len(pts) != 2 || pts[0] != pl.entries[0] || pts[1] != pl.entries[1] {
		t.Fatalf("RoutePointers = %v, want the pool's entries", pts)
	}
	pts[0] = nil // a copy: mutating it must not reach the pool
	if pl.RoutePointers()[0] == nil {
		t.Fatal("RoutePointers leaked the internal slice")
	}

	p := pl.entries[0]
	if p.RotatingNow() || p.AuthBlockedNow() || p.CooldownActive() {
		t.Fatal("fresh route reports rotating/auth-blocked/cooling")
	}
	p.BeginRotation(RotationDraining)
	if !p.RotatingNow() {
		t.Fatal("route mid-rotation does not report rotating")
	}
	p.EndRotation("203.0.113.9", c.now)

	pl.ReportFailure(p, nil)
	if !p.CooldownActive() {
		t.Fatal("route after a reported failure does not report cooling")
	}
	p.MarkRotated()
	if p.CooldownActive() {
		t.Fatal("route after MarkRotated still cooling")
	}
}

func TestMarkStaleRecordsRetryAndDeprioritizes(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1", "socks5://m2:2")
	stale := pl.entries[1]

	// Without the stale bump, m2 (pass 0) would win this LRU pick.
	pl.PickFor(nil, nil, "t:443") // m1
	stale.BeginRotation(RotationVerifying)
	pl.MarkStale(stale, 90*time.Second, 2)

	if got := pl.PickFor(nil, nil, "t:443").URL.Host; got != "m1:1" {
		t.Fatalf("pick = %s, want m1:1 (stale route pushed to LRU back)", got)
	}
	s := findStatus(t, pl.Snapshot(), "m2:2")
	if !s.Available || s.Rotation.State != "stale" || s.Rotation.NextRetryIn != "1m30s" || s.Rotation.ConsecutiveSameIP != 2 {
		t.Fatalf("stale snapshot = %+v", s.Rotation)
	}
}

func TestMarkRotatedClearsDialHealthNotAuth(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1")
	p := pl.entries[0]

	pl.ReportFailure(p, nil)
	pl.ReportFailure(p, nil)
	p.MarkRotated()
	if s := findStatus(t, pl.Snapshot(), "m1:1"); !s.Available || s.ConsecutiveFailures != 0 || s.CooldownFor != "0s" {
		t.Fatalf("post-rotation dial health = %+v", s)
	}

	pl.ReportAuthBlocked(p, errors.New("endpoint rejected credentials"))
	p.MarkRotated()
	if s := findStatus(t, pl.Snapshot(), "m1:1"); !s.AuthBlocked || s.AuthFailures != 1 {
		t.Fatalf("rotation must not clear auth state: %+v", s)
	}
}

// A completed rotation clears the pair-scoped cooldowns earned through the
// old egress IP alongside the route-scoped one: the refusals were answered
// from an address the route no longer serves from, so the pairs come back
// immediately eligible with fresh escalation streaks. Credentials did not
// rotate, so an auth block still survives.
func TestMarkRotatedClearsPairCooldowns(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1", "socks5://m2:2")
	m1 := pl.entries[0]

	// Two refused targets through the old egress IP, one escalated twice.
	pairFail(pl, m1, "refused.test:443")
	pairFail(pl, m1, "refused.test:443")
	pairFail(pl, m1, "other.test:443")
	if s := findStatus(t, pl.Snapshot(), "m1:1"); s.TargetCooldowns != 2 {
		t.Fatalf("pair view before rotation = %+v", s)
	}
	// While the pairs cool, the refused target defers to the peer route.
	if got := pl.PickFor(nil, nil, "refused.test:443"); got == nil || got.URL.Host != "m2:2" {
		t.Fatalf("pick while pair cools = %v, want m2:2", got)
	}

	// Complete a rotation: route-scoped and pair-scoped cooldowns learned
	// against the old IP clear together.
	pl.ReportFailure(m1, nil)
	m1.MarkRotated()
	m1.EndRotation("203.0.113.9", c.now)

	if cd := pl.CoolingFor(m1, "refused.test:443"); cd != 0 {
		t.Fatalf("CoolingFor after rotation = %s, want the pair immediately eligible", cd)
	}
	if cd := pl.CoolingFor(m1, "other.test:443"); cd != 0 {
		t.Fatalf("CoolingFor(sibling pair) after rotation = %s, want 0", cd)
	}
	if s := findStatus(t, pl.Snapshot(), "m1:1"); !s.Available || s.TargetCooldowns != 0 {
		t.Fatalf("pair view after rotation = %+v", s)
	}
	// EndRotation leaves the freshly verified route least recently used, so it
	// absorbs the next pick for the formerly refused target.
	if got := pl.PickFor(nil, nil, "refused.test:443"); got == nil || got.URL.Host != "m1:1" {
		t.Fatalf("pick after rotation = %v, want the rotated m1:1", got)
	}
	// The escalation streaks rotated away too: a fresh refusal starts at the base.
	if cd := pairFail(pl, m1, "refused.test:443"); cd != 30*time.Second {
		t.Fatalf("refusal after rotation = %s, want a fresh 30s streak", cd)
	}

	pl.ReportAuthBlocked(m1, errors.New("endpoint rejected credentials"))
	m1.MarkRotated()
	if !m1.AuthBlockedNow() {
		t.Fatal("rotation cleared an auth block")
	}
}

func TestReconfigureKeepsRotationStateForUnchangedIdentity(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	specs := []config.RouteSpec{manualSpec(t, "socks5://m1:1")}
	pl := NewRoutes(specs, 30*time.Second, time.Minute)
	pl.Now = c.NowFunc

	pl.entries[0].EndRotation("203.0.113.9", c.now)
	next := pl.Reconfigure(specs, 30*time.Second, time.Minute)
	next.Now = c.NowFunc
	if next.entries[0] != pl.entries[0] {
		t.Fatalf("unchanged manual route rebuilt a new state")
	}
	if s := next.Snapshot()[0]; s.Rotation.LastIP != "203.0.113.9" {
		t.Fatalf("rotation state lost across reload: %+v", s.Rotation)
	}

	// Same URL+kind but origin flipped to auto is a new route role: fresh
	// state, no rotation view.
	autoSpecs := []config.RouteSpec{{URL: specs[0].URL, Kind: specs[0].Kind, Origin: config.RouteOriginAuto}}
	next = pl.Reconfigure(autoSpecs, 30*time.Second, time.Minute)
	next.Now = c.NowFunc
	if next.entries[0] == pl.entries[0] {
		t.Fatalf("origin flip reused the manual route state")
	}
	if s := next.Snapshot()[0]; s.Origin != "auto" || s.Rotation != nil {
		t.Fatalf("auto route after origin flip = %+v", s)
	}
}

func TestLastIPsExcludesRouteAndAutoOrigin(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1", "socks5://m2:2")
	pl.entries = append(pl.entries, newProxy(config.RouteSpec{URL: mustURL(t, "socks5://a1:1"), Kind: config.EgressV4, Origin: config.RouteOriginAuto}, 0))

	pl.entries[0].EndRotation("203.0.113.1", c.now)
	pl.entries[1].EndRotation("203.0.113.2", c.now)

	ips := pl.LastIPs(pl.entries[0])
	if len(ips) != 1 || !ips["203.0.113.2"] {
		t.Fatalf("LastIPs(exclude m1) = %v, want only m2's IP", ips)
	}
	ips = pl.LastIPs(nil)
	if len(ips) != 2 {
		t.Fatalf("LastIPs(nil) = %v, want both manual IPs (auto excluded)", ips)
	}
}

// TestCommitRotationIsAtomicWithCollisionCheck reproduces the rotation
// engine's exact check→commit interleave: two procedures screen the collision
// set (both see the shared candidate free), a barrier, then both commit it.
// The scan and the record must behave as one decision made exactly once —
// one commit succeeds, the other is rejected with ErrRotationCollision, and
// only one route ends up holding the address.
func TestCommitRotationIsAtomicWithCollisionCheck(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1", "socks5://m2:2")
	const shared = "198.51.100.9"

	store := storeOver(t, pl)

	var screened, done sync.WaitGroup
	screened.Add(2)
	done.Add(2)
	errs := make([]error, 2)
	for i := range 2 {
		go func(i int) {
			defer done.Done()
			p := pl.entries[i]
			if pl.LastIPs(p)[shared] {
				errs[i] = errors.New("the screen saw a collision before any commit")
				return
			}
			screened.Done()
			screened.Wait() // both screens passed; now both commit
			_, errs[i] = pl.CommitRotation(store, p, shared, c.now)
		}(i)
	}
	done.Wait()

	winner, loser := 0, 1
	for i, err := range errs {
		switch {
		case err == nil:
			winner = i
		case errors.Is(err, ErrRotationCollision):
			loser = i
		default:
			t.Fatalf("procedure %d commit err = %v, want a success or a collision rejection", i, err)
		}
	}
	if errs[winner] != nil || errs[loser] == nil {
		t.Fatalf("commits = %v, want exactly one success and one collision rejection", errs)
	}
	if got := pl.entries[winner].LastIP(); got != shared {
		t.Fatalf("winner lastIP = %q, want the shared candidate", got)
	}
	if got := pl.entries[loser].LastIP(); got != "" {
		t.Fatalf("loser lastIP = %q, want nothing recorded for the rejected candidate", got)
	}
	if ips := pl.LastIPs(nil); len(ips) != 1 || !ips[shared] {
		t.Fatalf("collision set = %v, want the shared candidate held once", ips)
	}

	// The rejected address stays refused on retry, and a distinct one commits.
	if _, err := pl.CommitRotation(store, pl.entries[loser], shared, c.now); !errors.Is(err, ErrRotationCollision) {
		t.Fatalf("re-commit of a held address = %v, want a collision rejection", err)
	}
	if _, err := pl.CommitRotation(store, pl.entries[loser], "198.51.100.10", c.now); err != nil {
		t.Fatalf("commit of a distinct address = %v, want nil", err)
	}
}

func TestAbandonRotationReturnsRouteToServing(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1")
	p := pl.entries[0]

	p.BeginRotation(RotationRotating)
	p.AbandonRotation()
	if s := findStatus(t, pl.Snapshot(), "m1:1"); !s.Available || s.Rotation.State != "idle" {
		t.Fatalf("abandoned rotation snapshot = %+v", s)
	}

	// A stale mark predating the abandoned procedure survives abandonment.
	p.EndRotation("203.0.113.5", c.now)
	p.BeginRotation(RotationDraining)
	pl.MarkStale(p, time.Minute, 1)
	p.BeginRotation(RotationVerifying)
	p.AbandonRotation()
	if s := findStatus(t, pl.Snapshot(), "m1:1"); !s.Available || s.Rotation.State != "stale" {
		t.Fatalf("abandon must keep stale phase: %+v", s.Rotation)
	}
}

// SetBaselineIP exists so the boot precheck can record a starting point; it
// must never overwrite an IP a rotation already recorded, or a slow probe
// would clobber a fresh baseline with a stale observation.
func TestSetBaselineIPDoesNotClobberKnownIP(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1")
	p := pl.entries[0]

	p.SetBaselineIP("203.0.113.7")
	if got := p.LastIP(); got != "203.0.113.7" {
		t.Fatalf("LastIP = %q after the first baseline", got)
	}
	p.SetBaselineIP("198.51.100.9")
	if got := p.LastIP(); got != "203.0.113.7" {
		t.Fatalf("LastIP = %q, want the first observation kept", got)
	}
	// EndRotation, by contrast, always records what it verified.
	p.EndRotation("198.51.100.9", c.now)
	if got := p.LastIP(); got != "198.51.100.9" {
		t.Fatalf("LastIP = %q after EndRotation, want the verified IP", got)
	}
}

// The rotating flag and the rotation state live under one lock: once a
// terminal transition ran, a late phase write — even one a stale procedure
// issues after its route finished — must not resurrect a rotating phase in
// the status view.
func TestSetRotationPhaseAfterTerminalTransitionIsInert(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1")
	p := pl.entries[0]

	p.BeginRotation(RotationDraining)
	p.SetRotationPhase(RotationRotating)
	p.SetRotationPhase(RotationVerifying)
	p.EndRotation("203.0.113.7", c.now)
	p.SetRotationPhase(RotationVerifying) // the stale procedure's late write
	if st := findStatus(t, pl.Snapshot(), "m1:1"); st.Rotation.State != "idle" {
		t.Fatalf("state = %q after EndRotation + late phase write, want idle", st.Rotation.State)
	}

	p.BeginRotation(RotationDraining)
	pl.MarkStale(p, time.Second, 1)
	p.SetRotationPhase(RotationRotating)
	if st := findStatus(t, pl.Snapshot(), "m1:1"); st.Rotation.State != "stale" {
		t.Fatalf("state = %q after MarkStale + late phase write, want stale", st.Rotation.State)
	}
}
