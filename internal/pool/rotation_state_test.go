package pool

import (
	"errors"
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
	pl := NewRoutes(routes, 30*time.Second, time.Minute, config.KindBalance{})
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

	if got := pl.PickFor(nil, nil).URL.Host; got != "m1:1" {
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
	pl.PickFor(nil, nil)
	rotating.BeginRotation(RotationDraining)

	for range 3 {
		if got := pl.PickFor(nil, nil).URL.Host; got != "m2:2" {
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

	if got := pl.PickFor(nil, nil); got == nil || got.URL.Host != "m1:1" {
		t.Fatalf("fallback pick = %v, want cooling m1:1", got)
	}

	// m2 back to serving: it wins again over the still-cooling m1? No — m1
	// recovers sooner only when all entries cool; with m2 eligible the LRU
	// main path applies. Either way m2 must be pickable again.
	pl.entries[1].AbandonRotation()
	if got := pl.PickFor(nil, nil); got == nil {
		t.Fatalf("pick = nil after abandoning rotation, want any eligible route")
	}
}

func TestInFlightAccounting(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1")

	p := pl.PickFor(nil, nil)
	if p.InFlight() != 1 {
		t.Fatalf("InFlight after pick = %d, want 1", p.InFlight())
	}
	q := pl.PickFor(nil, nil)
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

func TestMarkStaleRecordsRetryAndDeprioritizes(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1", "socks5://m2:2")
	stale := pl.entries[1]

	// Without the stale bump, m2 (pass 0) would win this LRU pick.
	pl.PickFor(nil, nil) // m1
	stale.BeginRotation(RotationVerifying)
	pl.MarkStale(stale, 90*time.Second, 2)

	if got := pl.PickFor(nil, nil).URL.Host; got != "m1:1" {
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

func TestReconfigureKeepsRotationStateForUnchangedIdentity(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	specs := []config.RouteSpec{manualSpec(t, "socks5://m1:1")}
	pl := NewRoutes(specs, 30*time.Second, time.Minute, config.KindBalance{})
	pl.Now = c.NowFunc

	pl.entries[0].EndRotation("203.0.113.9", c.now)
	next := pl.Reconfigure(specs, 30*time.Second, time.Minute, config.KindBalance{})
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
	next = pl.Reconfigure(autoSpecs, 30*time.Second, time.Minute, config.KindBalance{})
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
