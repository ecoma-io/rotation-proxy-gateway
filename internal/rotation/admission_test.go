package rotation

import (
	"context"
	"net/http"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
)

// bothModes runs one subtest per traffic-admission mode. Every mode-behavior
// test is written once against this table: the two modes run the same procedure,
// so a behavior that holds for both is a property of the procedure, and the
// table is what makes that visible — a mode added later is covered by
// construction rather than by remembering to write its cases.
func bothModes(t *testing.T, fn func(t *testing.T, mode config.RotationMode)) {
	t.Helper()
	for _, mode := range []config.RotationMode{config.RotationModeDisruptive, config.RotationModeSeamless} {
		t.Run(string(mode), func(t *testing.T) { fn(t, mode) })
	}
}

// modeSettings is fastSettings with the mode under test. The disruptive mode is
// what every pre-existing test runs with by default, so it is named explicitly
// only where a test is about the mode itself.
func modeSettings(mode config.RotationMode) config.RotationSettings {
	settings := fastSettings()
	settings.Mode = mode
	return settings
}

// TestProcedureIsSharedAcrossBothModes drives both modes through the real
// scheduler — scheduling, policy lookup, procedure, commit — with no in-flight
// work to stage, and pins that they produce the same outcome through the same
// commit. What the mode decides is only whether the route takes picks while the
// procedure runs; everything the procedure does is identical.
func TestProcedureIsSharedAcrossBothModes(t *testing.T) {
	bothModes(t, func(t *testing.T, mode config.RotationMode) {
		ips := newIPServer(t, "203.0.113.7")
		api := newAPIServer(t)
		spec := manualRoute(t, "m1.test", time.Hour, apiSpec(api))
		cfg := &config.RuntimeConfig{Rotation: modeSettings(mode), ManualRoutes: []config.ManualRouteSpec{spec}}
		cfg.Rotation.RotateOnStart = true
		pl := testPool(t, cfg)
		// The provider hands out a fresh egress IP per probe: the baseline probe
		// and the verify probe disagree, which is the success condition. The
		// rotate call is counted by the shared apiServer handler, so the
		// assertion below covers the real request.
		ips.unique.Store(true)
		verify := secondUniqueIP()
		e := testEngine(t, ips, pool.NewStore(cfg, pl), nil)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go e.Run(ctx)
		waitFor(t, "one rotation", 5*time.Second, func() bool { return e.Rotations() == 1 })
		cancel()

		// Same procedure, same outcome, same single commit — only admission
		// differed. These are the assertions the pre-existing disruptive tests
		// already make, run against both policies.
		st := snapshotHost(t, pl, "m1.test")
		if st.Rotation.State != "idle" || st.Rotation.LastIP != verify ||
			st.Rotation.LastRotationAt == "" || st.Rotation.RotationCount != 1 {
			t.Fatalf("post-rotation status = %+v", st.Rotation)
		}
		if got := e.IPRevisits(); got != 0 {
			t.Fatalf("IPRevisits = %d, want 0 for a first rotation", got)
		}
		// The route is serving again at the end of either mode.
		if !st.Available {
			t.Fatalf("route unavailable after a completed rotation: %+v", st)
		}
		if api.calls.Load() != 1 {
			t.Fatalf("rotate API calls = %d, want 1", api.calls.Load())
		}
	})
}

// TestDisruptiveHoldsRouteOutOfPicks pins the disruptive mode's defining
// behavior: while its procedure runs, the route is ineligible for new picks, so
// the pool hands requests elsewhere or reports no_route — while the request
// picked before the procedure began is left running untouched.
func TestDisruptiveHoldsRouteOutOfPicks(t *testing.T) {
	ips := newIPServer(t, "203.0.113.7")
	api := newAPIServer(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ips.set("198.51.100.9")
		close(entered)
		<-release
		w.WriteHeader(http.StatusOK)
	})
	spec := manualRoute(t, "m1.test", time.Hour, apiSpec(api))
	cfg := &config.RuntimeConfig{Rotation: modeSettings(config.RotationModeDisruptive),
		ManualRoutes: []config.ManualRouteSpec{spec}}
	cfg.Rotation.DrainTimeout = 300 * time.Millisecond
	s := newSetup(t, cfg, nil, ips)
	p := s.pl.Lookup(routeID(spec.RouteSpec))

	// Staged before the procedure starts, so the drain really waits for it.
	held := s.pl.PickFor(nil, nil, "t:443")
	if held != p {
		t.Fatal("failed to take a pick on the route under test")
	}
	defer held.Release()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.e.runProcedure(context.Background(), s.gen, spec, p, routeID(spec.RouteSpec))
	}()
	// The rotate call is parked, so the assertions below observe the route in
	// the middle of its procedure for as long as the test needs.
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("procedure never reached the rotate API call")
	}

	if !p.RotatingNow() {
		t.Fatal("disruptive route is still pickable mid-procedure")
	}
	if got := s.pl.PickFor(nil, nil, "t:443"); got != nil {
		got.Release()
		t.Fatal("disruptive route was picked while its procedure ran")
	}
	if st := snapshotHost(t, s.pl, "m1.test"); st.Available {
		t.Fatalf("disruptive route reports available mid-procedure: %+v", st)
	}
	// The request picked before the procedure began is untouched: a drain lets
	// in-flight work finish on the tunnel it already has — expiry forces the
	// rotation through without breaking it.
	if got := p.InFlight(); got < 1 {
		t.Fatalf("in-flight holders = %d, want the pre-rotation request intact", got)
	}

	close(release)
	waitFor(t, "rotation committed", 5*time.Second, func() bool { return s.e.Rotations() == 1 })
	if p.RotatingNow() {
		t.Fatal("disruptive route stayed out of picks after a committed rotation")
	}
}

// TestSeamlessServesTrafficAcrossTheRotation pins the seamless mode's defining
// behavior: the route keeps taking picks for the whole procedure — through its
// drain and through the changeover — so in-flight work is never cut.
func TestSeamlessServesTrafficAcrossTheRotation(t *testing.T) {
	ips := newIPServer(t, "203.0.113.7")
	api := newAPIServer(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ips.set("198.51.100.9")
		close(entered) // the changeover is under way
		<-release
		w.WriteHeader(http.StatusOK)
	})
	spec := manualRoute(t, "m1.test", time.Hour, apiSpec(api))
	cfg := &config.RuntimeConfig{Rotation: modeSettings(config.RotationModeSeamless),
		ManualRoutes: []config.ManualRouteSpec{spec}}
	cfg.Rotation.DrainTimeout = 300 * time.Millisecond
	s := newSetup(t, cfg, nil, ips)
	p := s.pl.Lookup(routeID(spec.RouteSpec))

	// Staged before the procedure starts: this is the in-flight work seamless
	// mode exists to protect, and it must survive the whole rotation.
	held := s.pl.PickFor(nil, nil, "t:443")
	if held != p {
		t.Fatal("failed to take a pick on the route under test")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.e.runProcedure(context.Background(), s.gen, spec, p, routeID(spec.RouteSpec))
	}()
	// The rotate call is parked, so the assertions below observe the route in
	// the middle of its procedure for as long as the test needs.
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("procedure never reached the rotate API call")
	}

	// Through the drain and up to the changeover: the policy raised no flag, and
	// it advanced the epoch regardless.
	if got := p.RotationEpoch(); got != 1 {
		t.Fatalf("epoch mid-procedure = %d, want 1", got)
	}
	if p.RotatingNow() {
		t.Fatal("seamless route raised the rotating flag before the changeover")
	}
	for _, target := range []string{"a.test:443", "b.test:443"} {
		if got := s.pl.PickFor(nil, nil, target); got != p {
			if got != nil {
				got.Release()
			}
			t.Fatalf("seamless route was not picked for %s during the rotation", target)
		}
	}
	if st := snapshotHost(t, s.pl, "m1.test"); !st.Available {
		t.Fatalf("seamless route reports unavailable mid-procedure: %+v", st)
	}

	close(release)
	waitFor(t, "rotation committed", 5*time.Second, func() bool { return s.e.Rotations() == 1 })
	// The work held across the rotation was never cut.
	if got := p.InFlight(); got < 1 {
		t.Fatalf("in-flight holders after the rotation = %d, want the pre-rotation request intact", got)
	}
	if st := snapshotHost(t, s.pl, "m1.test"); st.Rotation.LastIP != "198.51.100.9" {
		t.Fatalf("seamless rotation did not commit: %+v", st.Rotation)
	}
	held.Release()
}

// An epoch that moved without the route leaving service is exactly the seamless
// case, and it must be the epoch alone: the rotating flag, which PickFor reads
// on both its paths, must stay clear, or the mode would report a rotation in
// flight and the engine's own phase writes would start landing. The bump also
// retires warm connections established under the old egress IP — the warm pool
// discards a parked connection whose stamp no longer matches, which
// TestAdmitRotationEpochInvalidatesWarmConnections pins in the warm pool itself.
//
// The observation point matters: the rotate call is parked, so these assertions
// run before HoldTraffic. What a pick does *after* the changeover opens is
// TestSeamlessHoldsTheRouteOutOfPicksAcrossTheChangeover's subject.
func TestSeamlessAdvancesEpochWithoutRaisingTheRotatingFlag(t *testing.T) {
	ips := newIPServer(t, "203.0.113.7")
	api := newAPIServer(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ips.set("198.51.100.9")
		close(entered)
		<-release
		w.WriteHeader(http.StatusOK)
	})
	spec := manualRoute(t, "m1.test", time.Hour, apiSpec(api))
	cfg := &config.RuntimeConfig{Rotation: modeSettings(config.RotationModeSeamless),
		ManualRoutes: []config.ManualRouteSpec{spec}}
	cfg.Rotation.DrainTimeout = 300 * time.Millisecond
	s := newSetup(t, cfg, nil, ips)
	p := s.pl.Lookup(routeID(spec.RouteSpec))

	if got := p.RotationEpoch(); got != 0 {
		t.Fatalf("epoch before any procedure = %d, want 0", got)
	}
	held := s.pl.PickFor(nil, nil, "t:443")
	if held != p {
		t.Fatal("failed to take a pick on the route under test")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.e.runProcedure(context.Background(), s.gen, spec, p, routeID(spec.RouteSpec))
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("procedure never reached the rotate API call")
	}

	if got := p.RotationEpoch(); got != 1 {
		t.Fatalf("epoch mid-procedure = %d, want exactly 1", got)
	}
	if p.RotatingNow() {
		t.Fatal("seamless epoch bump raised the rotating flag")
	}
	// In-flight work is untouched: a holder picked before the epoch bump is
	// still counted and still running. The epoch invalidates future borrows,
	// never a tunnel already established.
	if got := p.InFlight(); got < 1 {
		t.Fatalf("in-flight holders = %d, want the pre-rotation holder intact", got)
	}

	close(release)
	waitFor(t, "rotation committed", 5*time.Second, func() bool { return s.e.Rotations() == 1 })
	held.Release()
}

// A verification that never observes a changed IP is the same outcome in both
// modes: the route goes stale and keeps serving. A seamless route must not end
// a failed rotation in a different state from a disruptive one — the failure is
// a property of the provider's answer, not of the admission policy.
func TestFailedVerificationLeavesTheSameSafeStateInBothModes(t *testing.T) {
	bothModes(t, func(t *testing.T, mode config.RotationMode) {
		ips := newIPServer(t, "203.0.113.7") // the IP never changes
		api := newAPIServer(t)
		spec := manualRoute(t, "m1.test", time.Second, apiSpec(api))
		cfg := &config.RuntimeConfig{Rotation: modeSettings(mode), ManualRoutes: []config.ManualRouteSpec{spec}}
		s := newSetup(t, cfg, nil, ips)

		s.runOne(spec)

		if got := s.e.Rotations(); got != 0 {
			t.Fatalf("Rotations = %d, want 0", got)
		}
		st := snapshotHost(t, s.pl, "m1.test")
		// Same safe state in either mode: serving, stale, retried, no counters
		// moved, and no cooldown invented for a transition that simply failed to
		// observe a new address.
		if st.Rotation.State != "stale" || st.Rotation.ConsecutiveSameIP != 1 {
			t.Fatalf("unchanged-IP status = %+v, want stale at one same-IP attempt", st.Rotation)
		}
		if st.Rotation.RotationCount != 0 || st.Rotation.IPRevisitCount != 0 {
			t.Fatalf("unchanged-IP counters = %d/%d, want 0/0",
				st.Rotation.RotationCount, st.Rotation.IPRevisitCount)
		}
		if !st.Available {
			t.Fatalf("route unavailable after a failed verification: %+v", st)
		}
		if st.ConsecutiveFailures != 0 || st.LastDialError != "" {
			t.Fatalf("rotation transition poisoned route health: %+v", st)
		}
		if st.CooldownFor != "0s" {
			t.Fatalf("rotation transition put the route in cooldown: %+v", st)
		}
		// Either mode, the route is pickable again once the attempt is over.
		if got := s.pl.PickFor(nil, nil, "t:443"); got == nil {
			t.Fatal("route is not pickable after a failed verification")
		}
	})
}

// A seamless verification must satisfy exactly the same rule a disruptive one
// does: the egress IP has to have changed and must collide with no other manual
// route. Serving traffic across the rotation buys the route nothing — a
// cross-route collision still rejects the candidate and still ends in stale.
func TestSeamlessVerificationRejectsACrossRouteCollision(t *testing.T) {
	ips := newIPServer(t, "203.0.113.7")
	api := newAPIServer(t)
	spec := manualRoute(t, "m2.test", time.Hour, apiSpec(api))
	other := manualRoute(t, "m1.test", time.Hour, apiSpec(api))
	cfg := &config.RuntimeConfig{Rotation: modeSettings(config.RotationModeSeamless),
		ManualRoutes: []config.ManualRouteSpec{other, spec}}
	s := newSetup(t, cfg, nil, ips)

	const held = "198.51.100.9"
	s.pl.Lookup(routeID(other.RouteSpec)).SetBaselineIP(held)
	// m2's provider hands back m1's current address: the IP changed from m2's
	// baseline, and it still does not count.
	api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ips.set(held)
		w.WriteHeader(http.StatusOK)
	})

	s.runOne(spec)

	if got := s.e.Rotations(); got != 0 {
		t.Fatalf("Rotations = %d, want 0 (collision)", got)
	}
	st := snapshotHost(t, s.pl, "m2.test")
	if st.Rotation.State != "stale" || st.Rotation.LastIP != "" {
		t.Fatalf("collision left the route in %+v, want stale with no committed IP", st.Rotation)
	}
	if !st.Available {
		t.Fatalf("route unavailable after a rejected candidate: %+v", st)
	}
	if got := s.pl.PickFor(nil, nil, "t:443"); got == nil {
		t.Fatal("route is not pickable after a rejected candidate")
	}
}

// The epoch is the warm pool's rotation isolation. It advances exactly once per
// procedure in both modes — that is what makes the invariant "a warm
// connection's epoch must equal the route's current epoch or it is discarded"
// hold for either policy — but only the disruptive mode also stops picks.
func TestEpochAdvancesOncePerProcedureInBothModes(t *testing.T) {
	bothModes(t, func(t *testing.T, mode config.RotationMode) {
		ips := newIPServer(t, "203.0.113.7")
		api := newAPIServer(t)
		spec := manualRoute(t, "m1.test", time.Hour, apiSpec(api))
		cfg := &config.RuntimeConfig{Rotation: modeSettings(mode), ManualRoutes: []config.ManualRouteSpec{spec}}
		s := newSetup(t, cfg, nil, ips)
		p := s.pl.Lookup(routeID(spec.RouteSpec))
		api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			ips.set("198.51.100.9")
			w.WriteHeader(http.StatusOK)
		})

		if got := p.RotationEpoch(); got != 0 {
			t.Fatalf("epoch before any procedure = %d, want 0", got)
		}
		s.runOne(spec)
		if got := p.RotationEpoch(); got != 1 {
			t.Fatalf("epoch after one procedure = %d, want exactly 1", got)
		}
		// A second procedure advances it again, so connections parked under the
		// first rotation's egress IP are retired by the second.
		api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			ips.set("198.51.100.10")
			w.WriteHeader(http.StatusOK)
		})
		s.runOne(spec)
		if got := p.RotationEpoch(); got != 2 {
			t.Fatalf("epoch after two procedures = %d, want 2", got)
		}
		if got := snapshotHost(t, s.pl, "m1.test").Rotation.RotationCount; got != 2 {
			t.Fatalf("rotationCount = %d, want one commit per procedure", got)
		}
	})
}

// A rotation interrupted by shutdown leaves the route safe in both modes:
// serving again, no outcome recorded, no health written, and — for the seamless
// mode — no holdback latched against the route's next changeover. Shutdown
// reaches the engine as a canceled context, which is what the procedure is
// driven with here.
func TestRotationInterruptedByShutdownLeavesRouteSafe(t *testing.T) {
	bothModes(t, func(t *testing.T, mode config.RotationMode) {
		ips := newIPServer(t, "203.0.113.7")
		api := newAPIServer(t)
		entered := make(chan struct{})
		release := make(chan struct{})
		api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			close(entered) // park inside the rotate call
			<-release
			w.WriteHeader(http.StatusOK)
		})
		spec := manualRoute(t, "m1.test", time.Hour, apiSpec(api))
		cfg := &config.RuntimeConfig{Rotation: modeSettings(mode), ManualRoutes: []config.ManualRouteSpec{spec}}
		cfg.Rotation.DrainTimeout = 300 * time.Millisecond
		s := newSetup(t, cfg, nil, ips)
		p := s.pl.Lookup(routeID(spec.RouteSpec))

		held := s.pl.PickFor(nil, nil, "t:443") // in-flight work that must not be cut
		if held != p {
			t.Fatal("failed to take a pick on the route under test")
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			s.e.runProcedure(ctx, s.gen, spec, p, routeID(spec.RouteSpec))
		}()
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("procedure never reached the rotate API call")
		}

		cancel() // shutdown
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("procedure ignored shutdown")
		}
		close(release) // let the parked handler exit
		held.Release()

		if got := s.e.Rotations(); got != 0 {
			t.Fatalf("Rotations = %d, want 0 for an interrupted rotation", got)
		}
		st := snapshotHost(t, s.pl, "m1.test")
		if st.Rotation.State != "idle" || st.Rotation.LastIP != "" || st.Rotation.RotationCount != 0 {
			t.Fatalf("interrupted rotation left an outcome behind: %+v", st.Rotation)
		}
		// Safe means serving: a transition is not a failure, so no transition
		// wrote cooldown, an auth block, or a failure streak into the route.
		if !st.Available || p.RotatingNow() {
			t.Fatalf("route not serving after an interrupted rotation: %+v", st)
		}
		if st.ConsecutiveFailures != 0 || st.CooldownFor != "0s" || st.AuthBlocked {
			t.Fatalf("interrupted rotation poisoned route health: %+v", st)
		}
		// The route takes picks again, and in the seamless mode nothing about
		// the abandoned changeover outlived the procedure.
		if got := s.pl.PickFor(nil, nil, "t:443"); got == nil {
			t.Fatal("route is not pickable after an interrupted rotation")
		}
	})
}

// A successful rotation commits its new egress IP exactly once. A retried or
// duplicated trigger that finds the provider already moved on must not commit a
// second time, in either mode.
func TestSuccessfulRotationCommitsExactlyOnce(t *testing.T) {
	bothModes(t, func(t *testing.T, mode config.RotationMode) {
		ips := newIPServer(t, "203.0.113.7")
		api := newAPIServer(t)
		spec := manualRoute(t, "m1.test", time.Hour, apiSpec(api))
		cfg := &config.RuntimeConfig{Rotation: modeSettings(mode), ManualRoutes: []config.ManualRouteSpec{spec}}
		s := newSetup(t, cfg, nil, ips)

		api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			ips.set("198.51.100.9")
			w.WriteHeader(http.StatusOK)
		})
		s.runOne(spec)
		first := snapshotHost(t, s.pl, "m1.test").Rotation
		if first.RotationCount != 1 || first.LastIP != "198.51.100.9" {
			t.Fatalf("first rotation = %+v, want one commit at 198.51.100.9", first)
		}
		if got := s.e.Rotations(); got != 1 {
			t.Fatalf("Rotations = %d, want 1", got)
		}

		// A duplicated trigger whose provider reports success but changes
		// nothing: no second commit, and the first one is left exactly as it
		// was recorded.
		api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK) // 200, but the IP stays put
		})
		s.runOne(spec)

		after := snapshotHost(t, s.pl, "m1.test").Rotation
		if after.RotationCount != first.RotationCount || after.LastIP != first.LastIP {
			t.Fatalf("an unchanged-IP attempt moved the committed outcome: %+v → %+v", first, after)
		}
		if after.ConsecutiveSameIP != 1 {
			t.Fatalf("unchanged attempt = %+v, want one same-IP attempt recorded", after)
		}
		if got := s.e.Rotations(); got != 1 {
			t.Fatalf("Rotations = %d, want 1 across both attempts", got)
		}
	})
}

// The seamless holdback belongs to the changeover that opened it. A second
// changeover for the same route must not release the first one's hold early,
// and the hold must clear exactly once its own changeover settles — including
// clearing the deadline it left in the pool, not just the bookkeeping.
func TestSeamlessHoldbackBelongsToOneChangeover(t *testing.T) {
	s := newSeamlessPolicy(time.Now)
	p := &pool.Proxy{}

	s.Admit(p, pool.RotationDraining, discardLogger())
	attempt := p.RotationEpoch()
	s.HoldTraffic(p, discardLogger())
	if !p.RotationHeld() {
		t.Fatal("HoldTraffic opened no hold on the route")
	}
	// The bound is the window, not the wall instant: the stored deadline is
	// rebuilt through processStart and so arrives without its monotonic reading,
	// which is why RotationHoldUntil documents that only its duration is exact.
	until := p.RotationHoldUntil()
	if d := time.Until(until); d > ChangeoverTimeout || d < ChangeoverTimeout-2*time.Second {
		t.Fatalf("hold window = %s, want the changeover budget %s", d.Truncate(time.Millisecond), ChangeoverTimeout)
	}

	if s.Settle(p, attempt+1, discardLogger()) {
		t.Fatal("a foreign attempt released a live holdback")
	}
	if !p.RotationHeld() {
		t.Fatal("a foreign attempt closed the hold in the pool")
	}
	if !s.Settle(p, attempt, discardLogger()) {
		t.Fatal("the changeover's own attempt could not release its holdback")
	}
	if p.RotationHeld() {
		t.Fatal("the released holdback is still holding the route out of picks")
	}
	if s.Settle(p, attempt, discardLogger()) {
		t.Fatal("a settled changeover released a holdback twice")
	}
}

// Readmit is the abort path, and Settle does not run on it: a rotation cut short
// by shutdown, or by a reload that dropped the route, must still return the
// route to service rather than leaving it out of picks until the hold's
// deadline.
func TestSeamlessReadmitReleasesAnOpenHold(t *testing.T) {
	s := newSeamlessPolicy(time.Now)
	p := &pool.Proxy{}

	s.Admit(p, pool.RotationDraining, discardLogger())
	s.HoldTraffic(p, discardLogger())
	if !p.RotationHeld() {
		t.Fatal("HoldTraffic opened no hold on the route")
	}

	s.Readmit(p, discardLogger())
	if p.RotationHeld() {
		t.Fatal("Readmit left the route held out of picks")
	}
	if s.Settle(p, p.RotationEpoch(), discardLogger()) {
		t.Fatal("a forgotten changeover reported a hold it no longer has")
	}
}

// The hold ends at the one deadline that bounds the changeover, the same instant
// ShouldContinue bounds the drain to, measured from the moment the procedure was
// admitted. So the drain, the baseline probe, the rotate call and the hold spend
// one budget rather than each getting their own, and a changeover that opens
// after the budget is gone holds for nothing at all.
func TestSeamlessHoldIsBoundedByTheChangeoverBudget(t *testing.T) {
	admitted := time.Now()
	p := &pool.Proxy{}

	s := newSeamlessPolicy(func() time.Time { return admitted })
	s.Admit(p, pool.RotationDraining, discardLogger())
	s.HoldTraffic(p, discardLogger())

	// The deadline is the changeover's, and the hold is open: nothing else in the
	// procedure has a say in it.
	if got, want := p.RotationHoldUntil(), changeoverDeadline(admitted); got.Sub(want) > time.Second || got.Sub(want) < -time.Second {
		t.Fatalf("hold deadline = %v, want the changeover deadline %v", got, want)
	}
	if !p.RotationHeld() {
		t.Fatal("a freshly opened hold does not hold the route")
	}

	// A drain that ran to the deadline leaves the hold with nothing to hold for,
	// and the pool says so rather than the policy second-guessing it: the deadline
	// has already elapsed, so the route serves straight through this changeover.
	spent := newSeamlessPolicy(func() time.Time { return admitted.Add(-ChangeoverTimeout) })
	spent.Admit(p, pool.RotationDraining, discardLogger())
	spent.HoldTraffic(p, discardLogger())
	if p.RotationHeld() {
		t.Fatal("a hold past its deadline still holds the route")
	}
}

// TestSeamlessHoldsTheRouteOutOfPicksAcrossTheChangeover is the serving-path
// half of the mode, observed where it actually happens: after the rotate call
// returns, so HoldTraffic has run and the hold is open.
//
// Before the changeover the route is picked (TestSeamlessServesTrafficAcrossThe
// Rotation). Across it the route is not picked at all — on either of PickFor's
// paths, and no matter what the alternatives are — which is the whole content
// of the documented hold-back. After the changeover settles it is picked again.
func TestSeamlessHoldsTheRouteOutOfPicksAcrossTheChangeover(t *testing.T) {
	ips := newIPServer(t, "203.0.113.7")
	api := newAPIServer(t)
	// The rotate call returns at once and reports the swap, so the changeover
	// opens on its own rather than because a client deadline let a parked call
	// give up: with the call still parked, HoldTraffic has not run and the hold
	// this test observes cannot exist.
	api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ips.set("198.51.100.9")
		w.WriteHeader(http.StatusOK)
	})
	// Verification runs inside the changeover and can only reach a commit once
	// the parked probe is released, so parking it keeps the window open for the
	// assertions below instead of racing the commit.
	verifying := ips.parkArm(1)
	spec := manualRoute(t, "m1.test", time.Hour, apiSpec(api))
	cfg := &config.RuntimeConfig{Rotation: modeSettings(config.RotationModeSeamless),
		ManualRoutes: []config.ManualRouteSpec{spec}}
	cfg.Rotation.DrainTimeout = 300 * time.Millisecond
	s := newSetup(t, cfg, nil, ips)
	p := s.pl.Lookup(routeID(spec.RouteSpec))

	// The work the mode exists to protect: a pick taken before the changeover,
	// still held when it opens and still held when it settles.
	pre := s.pl.PickFor(nil, nil, "t:443")
	if pre != p {
		t.Fatal("failed to take a pick on the route under test")
	}
	defer pre.Release()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.e.runProcedure(context.Background(), s.gen, spec, p, routeID(spec.RouteSpec))
	}()

	// Verification cannot begin before HoldTraffic has run, so arriving there
	// means the changeover is open — and the probe stays parked until the
	// assertions below are done, so what is observed here is the window rather
	// than a race with the commit.
	select {
	case <-verifying:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the procedure to enter verification")
	}
	if !p.RotationHeld() {
		t.Fatal("the changeover did not open a hold by the time verification began")
	}

	// Held, on both of PickFor's paths: the ordinary candidate scan finds nothing,
	// and the all-cooling fallback cannot reach the route either. There is no
	// alternative route here, which is the honest shape of the case — during a
	// seamless changeover a pick is answered 503, never handed to a route whose
	// egress IP is mid-swap. (The fallback's exclusion of a held route, with a
	// cooling alternative in play, is TestAllCoolingFallbackSkipsHeldRoute in the
	// pool package.)
	if got := s.pl.PickFor(nil, nil, "t:443"); got != nil {
		got.Release()
		t.Fatalf("held route was picked across the changeover: %s", got.URL.Host)
	}
	if st := snapshotHost(t, s.pl, "m1.test"); st.Available {
		t.Fatalf("held route reports available mid-changeover: %+v", st)
	}
	// The hold is not a rotation in flight: the flag stays clear, so the route
	// keeps the display state it had and the engine's post-changeover phase write
	// is correctly inert.
	if p.RotatingNow() {
		t.Fatal("the seamless hold raised the rotating flag")
	}
	// In-flight work is untouched by the hold. That is the property the mode
	// exists for: a tunnel opened before the changeover finishes on the egress IP
	// it began with, and nothing about the hold touches it.
	if got := p.InFlight(); got != 1 {
		t.Fatalf("in-flight holders across the changeover = %d, want the pre-changeover request intact", got)
	}

	// Releasing the parked probe lets verification finish and the changeover
	// settle; the commit then closes it.
	ips.releasePark()
	waitFor(t, "rotation committed", 5*time.Second, func() bool { return s.e.Rotations() == 1 })
	<-done

	// Settle put the route back: the hold is gone, not merely expired.
	if p.RotationHeld() || !p.RotationHoldUntil().IsZero() {
		t.Fatalf("settled changeover left the route held: %v", p.RotationHoldUntil())
	}
	// The work the hold protected was never cut: the holder taken before the
	// changeover is still counted after it.
	if got := p.InFlight(); got != 1 {
		t.Fatalf("in-flight holders after the rotation = %d, want the pre-changeover request intact", got)
	}
	after := s.pl.PickFor(nil, nil, "t:443")
	if after != p {
		if after != nil {
			after.Release()
		}
		t.Fatalf("pick after the changeover settled = %v, want the seamless route back", after)
	}
	after.Release()
	if st := snapshotHost(t, s.pl, "m1.test"); st.Rotation.LastIP != "198.51.100.9" {
		t.Fatalf("seamless rotation did not commit: %+v", st.Rotation)
	}
}

// A hold never outlives its own procedure, including the one path that ends a
// rotation without settling the changeover: shutdown cancels the context between
// steps and the route must be serving when the process stops rotating it.
// Without a release on that path the route would sit out of picks until the
// hold's deadline — up to ChangeoverTimeout — after the rotation was already
// abandoned.
//
// What this pins is the abort outcome, not which call performs the release:
// Settle closes a changeover the procedure reached, and Readmit covers the ones
// it never reached, so a cancellation landing between them is released either
// way. Readmit's own release is covered by TestSeamlessReadmitReleasesAnOpenHold.
func TestSeamlessHoldIsReleasedWhenTheProcedureIsInterrupted(t *testing.T) {
	ips := newIPServer(t, "203.0.113.7")
	api := newAPIServer(t)
	// The rotate call returns at once and reports the swap. It runs before
	// HoldTraffic, so a procedure waiting to enter verification is waiting for a
	// changeover that has already opened — which is the state under test, and is
	// exactly why the wait is on the probe rather than on this call.
	api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ips.set("198.51.100.9")
		w.WriteHeader(http.StatusOK)
	})
	// The first probe after the rotate call is the baseline probe, which runs
	// before the changeover opens; the second is verification, which runs after
	// it. Parking that second one holds the procedure inside the changeover, and
	// the route's own 600ms ip-check budget is then the only thing that could end
	// it — so the wait below reads a barrier, not a deadline.
	verifying := ips.parkArm(1)
	spec := manualRoute(t, "m1.test", time.Hour, apiSpec(api))
	cfg := &config.RuntimeConfig{Rotation: modeSettings(config.RotationModeSeamless),
		ManualRoutes: []config.ManualRouteSpec{spec}}
	cfg.Rotation.DrainTimeout = 300 * time.Millisecond
	s := newSetup(t, cfg, nil, ips)
	p := s.pl.Lookup(routeID(spec.RouteSpec))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.e.runProcedure(ctx, s.gen, spec, p, routeID(spec.RouteSpec))
	}()
	// Verification cannot begin before the changeover opens, so this returns with
	// the hold open. The probe is never released before the cancel, so nothing can
	// settle this changeover: the unwind has to return the route to picks or it
	// stays held.
	select {
	case <-verifying:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the procedure to enter verification")
	}
	if !p.RotationHeld() {
		t.Fatal("the changeover did not open a hold by the time verification began")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("procedure did not unwind after cancellation")
	}

	if p.RotationHeld() || !p.RotationHoldUntil().IsZero() {
		t.Fatalf("an interrupted seamless rotation left the route held: %v", p.RotationHoldUntil())
	}
	if got := s.pl.PickFor(nil, nil, "t:443"); got != p {
		if got != nil {
			got.Release()
		}
		t.Fatalf("pick after an interrupted rotation = %v, want the route serving", got)
	}
	// The cancellation did not commit: an abandoned rotation records nothing, and
	// in particular the epoch stays advanced so a warm connection parked under the
	// old egress IP is still retired.
	if got := s.e.Rotations(); got != 0 {
		t.Fatalf("Rotations = %d after a cancelled rotation, want 0", got)
	}
}

// The seamless drain is bounded, so continuous load can never hold a changeover
// open indefinitely; the disruptive drain is bounded by the configured drain
// timeout alone. ShouldContinue reports the effective deadline it is willing to
// wait to — the earlier of the two budgets — and the seamless budget is anchored
// to the moment the procedure was admitted, so a route polled over many
// intervals still reaches it.
func TestDrainIsBoundedInBothModes(t *testing.T) {
	now := time.Now()
	deadline := now.Add(55 * time.Second)
	p := &pool.Proxy{}

	keep, until := disruptivePolicy{}.ShouldContinue(p, now, deadline)
	if !keep || !until.Equal(deadline) {
		t.Fatalf("disruptive drain: keep=%v until=%s, want the configured timeout alone", keep, until)
	}

	policy := newSeamlessPolicy(func() time.Time { return now })
	policy.Admit(p, pool.RotationDraining, discardLogger()) // anchors the budget
	keep, until = policy.ShouldContinue(p, now, deadline)
	if !keep {
		t.Fatal("seamless drain stopped waiting inside the drain timeout")
	}
	if want := now.Add(ChangeoverTimeout); !until.Equal(want) {
		t.Fatalf("seamless drain bound = %s, want the changeover budget %s", until.Sub(now), want.Sub(now))
	}
	// Polling again later does not extend the bound: it is anchored to the
	// admission, so a route under continuous load still stops waiting on time.
	later := now.Add(ChangeoverTimeout - time.Second)
	if keep, until := policy.ShouldContinue(p, later, deadline); !keep {
		t.Fatalf("seamless drain stopped waiting %s early: bound %s", time.Second, until.Sub(later))
	}
	if keep, _ := policy.ShouldContinue(p, now.Add(ChangeoverTimeout), deadline); keep {
		t.Fatal("seamless drain kept waiting past the changeover timeout")
	}
	// A drain timeout shorter than the changeover budget stays the binding
	// constraint: the effective deadline is the earlier of the two.
	short := now.Add(time.Second)
	if _, until := policy.ShouldContinue(p, now, short); !until.Equal(short) {
		t.Fatalf("seamless drain bound = %s, want the shorter drain timeout %s", until.Sub(now), time.Second)
	}
}

// waitFor polls cond until it holds or the budget runs out.
func waitFor(t *testing.T, what string, budget time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// secondUniqueIP is the egress IP the unique-IP fixture hands to the verify
// probe, i.e. the second request it serves.
func secondUniqueIP() string { return "10.0.0.2" }
