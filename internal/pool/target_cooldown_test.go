package pool

import (
	"errors"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
)

// pairFail records one explicit CONNECT refusal of target on p, the
// target-scoped health event.
func pairFail(pl *Pool, p *Proxy, target string) time.Duration {
	return pl.ReportTargetFailure(p, target, errors.New("SOCKS reply 0x05 (TEST)"))
}

// A refusal cools only the (route, target) pair: the same route stays
// eligible for every other target, and its route-level view stays healthy.
func TestTargetCooldownScopesToPair(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1", "socks5://b:2")

	a := pl.PickFor(nil, nil, "blocked.test:443")
	if a == nil || a.URL.Host != "a:1" {
		t.Fatalf("pick = %v, want a:1", a)
	}
	if cd := pairFail(pl, a, "blocked.test:443"); cd != 30*time.Second {
		t.Fatalf("pair cooldown = %s, want the 30s base", cd)
	}

	// The refused target defers to the other route.
	if got := pl.PickFor(nil, nil, "blocked.test:443"); got == nil || got.URL.Host == "a:1" {
		t.Fatalf("pick for refused target = %v, want the peer route", got)
	}
	// The same route still serves a different target, in ordinary LRU order.
	if got := pl.PickFor(nil, nil, "other.test:443"); got == nil || got.URL.Host != "a:1" {
		t.Fatalf("pick for another target = %v, want a:1 still eligible", got)
	}

	snap := pl.Snapshot()
	if snap[0].Available != true || snap[0].Failures != 0 || snap[0].CooldownFor != "0s" {
		t.Fatalf("route-level state moved on a target-scoped refusal: %+v", snap[0])
	}
	if snap[0].TargetCooldowns != 1 || snap[0].TargetFailures != 1 {
		t.Fatalf("pair view = %+v, want one cooled pair and one failure", snap[0])
	}
}

// Each pair escalates on its own streak with the same saturating curve as
// route cooldowns; a sibling pair on the same route starts at the base.
func TestTargetCooldownEscalatesPerPair(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := &Pool{entries: []*Proxy{newProxy(config.RouteSpec{URL: mustURL(t, "socks5://a:1"), Kind: config.EgressV4}, 0)}, base: 30 * time.Second, max: 2 * time.Minute}
	pl.Now = c.NowFunc

	a := pl.PickFor(nil, nil, "x:1")
	for i, want := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 2 * time.Minute} {
		if cd := pairFail(pl, a, "x:1"); cd != want {
			t.Fatalf("refusal %d cooldown = %s, want %s", i+1, cd, want)
		}
	}
	// A second pair on the same route starts its own streak at the base.
	if cd := pairFail(pl, a, "y:2"); cd != 30*time.Second {
		t.Fatalf("second pair cooldown = %s, want the 30s base", cd)
	}
}

// A route-level dial failure cools the route for every target, exactly as
// before pair scoping existed.
func TestRouteCooldownStillCoolsAllTargets(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1", "socks5://b:2")

	a := pl.PickFor(nil, nil, "any.test:443")
	pl.ReportFailure(a, errors.New("dial refused (TEST)"))
	for _, target := range []string{"any.test:443", "other.test:443"} {
		if got := pl.PickFor(nil, nil, target); got == nil || got.URL.Host == "a:1" {
			t.Fatalf("pick for %s = %v, want the peer route", target, got)
		}
	}
	snap := pl.Snapshot()[0]
	if snap.Available || snap.Failures != 1 || snap.CooldownFor == "0s" {
		t.Fatalf("route cooldown state = %+v", snap)
	}
}

// With every route pair-cooling for the request's target, the all-cooling
// fallback still hands out the soonest-recovering route, and CoolingFor names
// the pair's bet — while a different target sees the route as plain healthy.
func TestAllCoolingFallbackConsidersPairScope(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := &Pool{entries: []*Proxy{newProxy(config.RouteSpec{URL: mustURL(t, "socks5://a:1"), Kind: config.EgressV4}, 0)}, base: 30 * time.Second, max: 2 * time.Minute}
	pl.Now = c.NowFunc

	a := pl.PickFor(nil, nil, "blocked.test:443")
	pairFail(pl, a, "blocked.test:443")

	got := pl.PickFor(nil, nil, "blocked.test:443")
	if got != a {
		t.Fatalf("fallback pick = %v, want the soonest-recovering route", got)
	}
	if cd := pl.CoolingFor(a, "blocked.test:443"); cd != 30*time.Second {
		t.Fatalf("CoolingFor(refused pair) = %s, want the pair's 30s", cd)
	}
	if cd := pl.CoolingFor(a, "other.test:443"); cd != 0 {
		t.Fatalf("CoolingFor(other target) = %s, want 0", cd)
	}
	got.Release()

	// A mixed route+pair deadline reports the later of the two.
	pl.ReportFailure(a, errors.New("dial refused (TEST)"))
	if cd := pl.CoolingFor(a, "blocked.test:443"); cd != 30*time.Second {
		t.Fatalf("CoolingFor after both scopes failed = %s, want the later deadline", cd)
	}
	c.advance(31 * time.Second)
	if cd := pl.CoolingFor(a, "blocked.test:443"); cd != 0 {
		t.Fatalf("CoolingFor after expiry = %s, want 0", cd)
	}
}

// A success through the pair clears its cooldown and escalation streak: the
// next refusal starts over at the base, and sibling pairs are untouched.
func TestTargetSuccessClearsPair(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1", "socks5://b:2")

	a := pl.PickFor(nil, nil, "x:1")
	pairFail(pl, a, "x:1")
	pairFail(pl, a, "y:2")

	pl.ReportSuccess(a, "x:1")
	if cd := pl.CoolingFor(a, "x:1"); cd != 0 {
		t.Fatalf("CoolingFor after pair success = %s, want the pair immediately eligible", cd)
	}
	snap := pl.Snapshot()[0]
	if snap.TargetCooldowns != 1 || snap.TargetFailures != 2 {
		t.Fatalf("pair view after success = %+v, want y:2 still cooling", snap)
	}
	if cd := pairFail(pl, a, "x:1"); cd != 30*time.Second {
		t.Fatalf("refusal after success = %s, want a fresh 30s streak", cd)
	}
}

// The pair map stays bounded: inserting past the cap first reclaims expired
// entries, then evicts the soonest-recovering pair.
func TestTargetCooldownMapStaysBounded(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := &Pool{entries: []*Proxy{newProxy(config.RouteSpec{URL: mustURL(t, "socks5://a:1"), Kind: config.EgressV4}, 0)}, base: time.Hour, max: time.Hour}
	pl.Now = c.NowFunc
	a := pl.entries[0]

	mapSize := func() int {
		a.targetMu.RLock()
		defer a.targetMu.RUnlock()
		return len(a.targetCool)
	}
	pairName := func(i int) string {
		return string(rune('a'+i%26)) + string(rune('a'+i/26)) + ":1"
	}

	// Stagger the insertions by one nanosecond so the first-inserted pair has
	// the strictly soonest deadline and eviction is deterministic.
	for i := range maxTrackedTargetPairs {
		pairFail(pl, a, pairName(i))
		c.advance(time.Nanosecond)
	}
	if got := mapSize(); got != maxTrackedTargetPairs {
		t.Fatalf("map size = %d, want the cap", got)
	}

	// One more refusal with nothing expired evicts the soonest-recovering
	// pair, keeping the map at the cap.
	pairFail(pl, a, "overflow:1")
	if got := mapSize(); got != maxTrackedTargetPairs {
		t.Fatalf("map size after eviction = %d, want the cap", got)
	}
	a.targetMu.RLock()
	_, soonestAlive := a.targetCool[pairName(0)]
	_, overflowAlive := a.targetCool["overflow:1"]
	a.targetMu.RUnlock()
	if soonestAlive {
		t.Fatal("soonest-recovering pair survived eviction")
	}
	if !overflowAlive {
		t.Fatal("the newly inserted pair is missing")
	}

	// Expired entries are reclaimed before live ones; which expired entry
	// goes first is map-order, so only the bound is pinned here.
	c.advance(2 * time.Hour)
	pairFail(pl, a, "fresh:1")
	if size := mapSize(); size > maxTrackedTargetPairs {
		t.Fatalf("map size = %d, exceeds the cap", size)
	}
	a.targetMu.RLock()
	_, freshAlive := a.targetCool["fresh:1"]
	a.targetMu.RUnlock()
	if !freshAlive {
		t.Fatal("the freshly inserted pair is missing")
	}
}

// A reload that keeps the route keeps its pair cooldowns; rebuilding the
// route (changed kind) starts it clean.
func TestReconfigureRetainsTargetCooldowns(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1", "socks5://b:2")
	a := pl.PickFor(nil, nil, "blocked.test:443")
	pairFail(pl, a, "blocked.test:443")

	next := pl.Reconfigure([]config.RouteSpec{
		{URL: mustURL(t, "socks5://a:1"), Kind: config.EgressV4, Weight: 3},
		{URL: mustURL(t, "socks5://b:2"), Kind: config.EgressV4},
	}, 30*time.Second, time.Minute, config.KindBalance{})

	if got := next.PickFor(nil, nil, "blocked.test:443"); got == nil || got.URL.Host == "a:1" {
		t.Fatalf("pick after reload = %v, want the retained pair cooldown honored", got)
	}
	if got := next.PickFor(nil, nil, "other.test:443"); got == nil || got.URL.Host != "a:1" {
		t.Fatalf("pick for another target after reload = %v, want a:1 still eligible", got)
	}
	if snap := next.Snapshot()[0]; snap.TargetCooldowns != 1 || snap.TargetFailures != 1 {
		t.Fatalf("retained pair view = %+v", snap)
	}

	rebuilt := pl.Reconfigure([]config.RouteSpec{
		{URL: mustURL(t, "socks5://a:1"), Kind: config.EgressV6},
		{URL: mustURL(t, "socks5://b:2"), Kind: config.EgressV4},
	}, 30*time.Second, time.Minute, config.KindBalance{})
	if snap := rebuilt.Snapshot()[0]; snap.TargetCooldowns != 0 || snap.TargetFailures != 0 {
		t.Fatalf("rebuilt route carried pair state: %+v", snap)
	}
}

// The kind filter composes with the pair filter: a pair-cooled v4 route
// leaves the mixed pick to the healthy v6 route.
func TestBalancedPickRespectsPairScope(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := NewRoutes([]config.RouteSpec{
		{URL: mustURL(t, "socks5://a:1"), Kind: config.EgressV4},
		{URL: mustURL(t, "socks5://b:2"), Kind: config.EgressV6},
	}, 30*time.Second, time.Minute, config.KindBalance{V4: 1, V6: 1})
	pl.Now = c.NowFunc

	a := pl.PickFor(nil, nil, "blocked.test:443")
	if a == nil || a.Kind != config.EgressV4 {
		t.Fatalf("first pick = %v, want the v4 route", a)
	}
	pairFail(pl, a, "blocked.test:443")

	for range 3 {
		got := pl.PickFor(nil, nil, "blocked.test:443")
		if got == nil || got.Kind != config.EgressV6 {
			t.Fatalf("pick = %v, want the v6 route while the v4 pair cools", got)
		}
		got.Release()
	}
}
