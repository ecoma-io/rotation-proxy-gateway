package pool

import (
	"errors"
	"net/url"
	"reflect"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

// clock replaces Pool.Now so cooldown tests are deterministic.
type clock struct{ now time.Time }

func (c *clock) NowFunc() time.Time      { return c.now }
func (c *clock) advance(d time.Duration) { c.now = c.now.Add(d) }

func newTestPool(t *testing.T, c *clock, urls ...string) *Pool {
	t.Helper()
	routes := make([]config.RouteSpec, 0, len(urls))
	for _, raw := range urls {
		routes = append(routes, config.RouteSpec{URL: mustURL(t, raw), Kind: config.EgressV4})
	}
	pl := NewRoutes(routes, 30*time.Second, time.Minute)
	pl.Now = c.NowFunc
	return pl
}

func TestRoundRobinCyclesAll(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1", "socks5://b:2", "socks5://c:3")
	var got []string
	for range 6 {
		got = append(got, pl.PickFor(nil, nil, "t:443").URL.Host)
	}
	want := []string{"a:1", "b:2", "c:3", "a:1", "b:2", "c:3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pick order = %v, want %v", got, want)
	}
}

// A completed request demotes the route one extra step: the route that just
// served absorbs ReportSuccess's advance, so its peers take the next picks.
func TestReportSuccessAdvancesOneStep(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1", "socks5://b:2")
	var got []string
	a := pl.PickFor(nil, nil, "t:443")
	got = append(got, a.URL.Host)
	pl.ReportSuccess(a, "t:443")
	for range 3 {
		got = append(got, pl.PickFor(nil, nil, "t:443").URL.Host)
	}
	want := []string{"a:1", "b:2", "b:2", "a:1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pick order = %v, want %v", got, want)
	}
}

// A route added by reload joins at the recency front: it is picked on the
// next lap rather than absorbing a catch-up burst against accumulated passes.
func TestReconfigureAnchorsNewRouteAtRecencyFront(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1", "socks5://b:2")
	pl.PickFor(nil, nil, "t:443")
	pl.PickFor(nil, nil, "t:443")

	next := pl.Reconfigure([]config.RouteSpec{
		{URL: mustURL(t, "socks5://a:1"), Kind: config.EgressV4},
		{URL: mustURL(t, "socks5://b:2"), Kind: config.EgressV4},
		{URL: mustURL(t, "socks5://c:3"), Kind: config.EgressV4},
	}, 30*time.Second, time.Minute)

	var got []string
	for range 3 {
		got = append(got, next.PickFor(nil, nil, "t:443").URL.Host)
	}
	want := []string{"a:1", "b:2", "c:3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pick order = %v, want %v", got, want)
	}
}

func TestFailureCooldownSkipAndRevive(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1", "socks5://b:2")

	first := pl.PickFor(nil, nil, "t:443")
	if first.URL.Host != "a:1" {
		t.Fatalf("first pick = %s, want a:1", first.URL.Host)
	}
	pl.ReportFailure(first, errors.New("dial refused"))

	if got := pl.PickFor(nil, nil, "t:443").URL.Host; got != "b:2" {
		t.Fatalf("pick after failure = %s, want b:2 (a cooling)", got)
	}
	c.advance(31 * time.Second)
	if got := pl.PickFor(nil, nil, "t:443").URL.Host; got != "a:1" {
		t.Fatalf("pick after cooldown = %s, want a:1 revived", got)
	}
}

// A route-scope dial cooldown survives an identity-preserving reload — the
// retained deadline still holds the route out for every target — while an
// identity change rebuilds the route clean. The pair-scoped half of the
// reload matrix is pinned by TestReconfigureRetainsTargetCooldowns.
func TestReconfigureRetainsRouteCooldown(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://TEST-user:TEST-pass@a.test:1080", "socks5://b.test:1080")
	cooling := pl.entries[0]
	pl.ReportFailure(cooling, errors.New("dial refused (TEST)"))

	kept := pl.Reconfigure([]config.RouteSpec{
		{URL: mustURL(t, "socks5://TEST-user:TEST-pass@a.test:1080"), Kind: config.EgressV4},
		{URL: mustURL(t, "socks5://b.test:1080"), Kind: config.EgressV4},
	}, 30*time.Second, time.Minute)
	if kept.entries[0] != cooling {
		t.Fatal("identity-preserving reload rebuilt the cooling route")
	}
	snap := kept.Snapshot()[0]
	if snap.Available || snap.CooldownFor == "0s" || snap.ConsecutiveFailures != 1 {
		t.Fatalf("route cooldown lost across an identity-preserving reload: %+v", snap)
	}
	for _, target := range []string{"x.test:443", "y.test:443"} {
		if got := kept.PickFor(nil, nil, target); got == nil || got.URL.Host != "b.test:1080" {
			t.Fatalf("pick for %s after reload = %v, want the peer while the route cools", target, got)
		}
	}
	c.advance(31 * time.Second)
	if got := kept.PickFor(nil, nil, "x.test:443"); got == nil || got != cooling {
		t.Fatalf("pick after the retained deadline passed = %v, want the recovered route", got)
	}

	// An identity change rebuilds the route: no cooldown, no streak, fresh
	// counters — the route is eligible immediately.
	rebuilt := pl.Reconfigure([]config.RouteSpec{
		{URL: mustURL(t, "socks5://TEST-user:TEST-other@a.test:1080"), Kind: config.EgressV4},
		{URL: mustURL(t, "socks5://b.test:1080"), Kind: config.EgressV4},
	}, 30*time.Second, time.Minute)
	if rebuilt.entries[0] == cooling {
		t.Fatal("userinfo change reused the cooling route object")
	}
	s := rebuilt.Snapshot()[0]
	if !s.Available || s.CooldownFor != "0s" || s.ConsecutiveFailures != 0 || s.Failures != 0 {
		t.Fatalf("identity change carried the route cooldown: %+v", s)
	}
	if got := rebuilt.PickFor(nil, nil, "x.test:443"); got == nil || got != rebuilt.entries[0] {
		t.Fatalf("pick on the rebuilt route = %v, want it eligible immediately", got)
	}
}

func TestCooldownExponentialCap(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1")
	p := pl.PickFor(nil, nil, "t:443")

	if cd := pl.ReportFailure(p, nil); cd != 30*time.Second {
		t.Fatalf("first cooldown = %s, want 30s", cd)
	}
	c.advance(30 * time.Second)
	if cd := pl.ReportFailure(p, nil); cd != time.Minute {
		t.Fatalf("second cooldown = %s, want 1m", cd)
	}
	c.advance(time.Minute)
	if cd := pl.ReportFailure(p, nil); cd != time.Minute {
		t.Fatalf("third cooldown = %s, want capped 1m", cd)
	}
}

func TestExhaustedReturnsNil(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1")
	p := pl.PickFor(nil, nil, "t:443")
	if got := pl.PickFor(map[*Proxy]bool{p: true}, nil, "t:443"); got != nil {
		t.Fatalf("Pick(all excluded) = %v, want nil", got)
	}
}

func TestAllCoolingPicksSoonestRecovery(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1", "socks5://b:2")

	pl.ReportFailure(pl.entries[0], nil) // a: cooldown until +30s
	pl.ReportFailure(pl.entries[1], nil)
	pl.ReportFailure(pl.entries[1], nil) // b: two failures -> until +60s

	got := pl.PickFor(nil, nil, "t:443")
	if got.URL.Host != "a:1" {
		t.Fatalf("pick with all cooling = %s, want a:1 (soonest recovery)", got.URL.Host)
	}
}

// The all-cooling fallback honors the per-request exclude set: a route
// already tried this turn is never handed back by the fallback, and excluding
// the whole cooling set yields nil — the same never-same-route-twice rule the
// ordinary path has.
func TestAllCoolingFallbackRespectsExclude(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1", "socks5://b:2")
	a, b := pl.entries[0], pl.entries[1]
	pl.ReportFailure(a, nil) // a: cooldown until +30s
	pl.ReportFailure(b, nil)
	pl.ReportFailure(b, nil) // b: until +60s

	// Excluding the soonest-recovering route must not bend the fallback back
	// to it: the later-recovering b serves instead.
	if got := pl.PickFor(map[*Proxy]bool{a: true}, nil, "t:443"); got == nil || got != b {
		t.Fatalf("fallback pick with a excluded = %v, want the other cooling route", got)
	}
	// Symmetrically, excluding b leaves the soonest-recovering a.
	if got := pl.PickFor(map[*Proxy]bool{b: true}, nil, "t:443"); got == nil || got != a {
		t.Fatalf("fallback pick with b excluded = %v, want a", got)
	}
	// Excluding both leaves nothing to fall back to.
	if got := pl.PickFor(map[*Proxy]bool{a: true, b: true}, nil, "t:443"); got != nil {
		t.Fatalf("fallback pick with every route excluded = %v, want nil", got)
	}
}

// A fallback pick takes the same in-flight hold as an ordinary pick: the
// rotation drain counts every holder of a route, whatever path served it.
func TestAllCoolingFallbackHoldsInFlight(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1")
	a := pl.entries[0]
	pl.ReportFailure(a, nil)

	if got := pl.PickFor(nil, nil, "t:443"); got != a {
		t.Fatalf("fallback pick = %v, want the cooling route", got)
	}
	if n := a.InFlight(); n != 1 {
		t.Fatalf("InFlight after one fallback pick = %d, want 1", n)
	}
	if again := pl.PickFor(nil, nil, "t:443"); again != a || a.InFlight() != 2 {
		t.Fatalf("second fallback pick = %v, InFlight = %d, want the same route at 2", again, a.InFlight())
	}
	a.Release()
	if n := a.InFlight(); n != 1 {
		t.Fatalf("InFlight after release = %d, want 1", n)
	}
	if snap := pl.Snapshot(); snap[0].InFlight != 1 {
		t.Fatalf("snapshot InFlight = %d, want 1", snap[0].InFlight)
	}
}

func TestAuthBlockedDoesNotCreateCooldown(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1", "socks5://b:2")
	pl.ReportAuthBlocked(pl.entries[0], errors.New("socks5: auth rejected"))

	snap := pl.Snapshot()
	if snap[0].Available || !snap[0].AuthBlocked || snap[0].AuthFailures != 1 ||
		snap[0].Failures != 0 || snap[0].ConsecutiveFailures != 0 || snap[0].CooldownFor != "0s" {
		t.Fatalf("blocked route snapshot = %+v", snap[0])
	}
	if got := pl.PickFor(nil, nil, "t:443"); got.URL.Host != "b:2" {
		t.Fatalf("Pick() = %s, want unblocked b:2", got.URL.Host)
	}
}

func TestAllAuthBlockedReturnsNil(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1")
	pl.ReportAuthBlocked(pl.entries[0], errors.New("auth rejected"))
	if got := pl.PickFor(nil, nil, "t:443"); got != nil {
		t.Fatalf("Pick() = %v, want nil when all routes auth-blocked", got)
	}
}

// ReportSuccess resets dial health (cooldown, consecutive failures, last
// error) but deliberately leaves an authentication block in place: unchanged
// credentials cannot recover without a reload that changes route identity.
func TestReportSuccessClearsDialCooldownButKeepsAuthBlock(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1", "socks5://b:2")

	a := pl.entries[0]
	pl.ReportFailure(a, errors.New("dial refused"))
	pl.ReportFailure(a, errors.New("dial refused"))
	if snap := pl.Snapshot()[0]; snap.Available || snap.ConsecutiveFailures != 2 {
		t.Fatalf("cooling route snapshot = %+v", pl.Snapshot()[0])
	}
	pl.ReportSuccess(a, "t:443")
	snap := pl.Snapshot()[0]
	if !snap.Available || snap.ConsecutiveFailures != 0 || snap.CooldownFor != "0s" || snap.LastDialError != "" {
		t.Fatalf("success did not clear dial health: %+v", snap)
	}
	if snap.Failures != 2 {
		t.Fatalf("cumulative failures = %d, want retained 2", snap.Failures)
	}

	b := pl.entries[1]
	pl.ReportAuthBlocked(b, errors.New("endpoint rejected credentials"))
	pl.ReportSuccess(b, "t:443")
	snapB := pl.Snapshot()[1]
	if !snapB.AuthBlocked || snapB.Available {
		t.Fatalf("success cleared an authentication block: %+v", snapB)
	}
	if got := pl.PickFor(nil, nil, "t:443"); got == nil || got.URL.Host != "a:1" {
		t.Fatalf("auth-blocked route re-entered rotation: got %v", got)
	}
}

// An authentication block survives an identity-preserving reload: unchanged
// URL+kind+origin keeps the blocked state (and its failure count) on the same
// route object, while any identity change — userinfo, kind, or origin —
// rebuilds the route with the block cleared. Reload preserves runtime pool
// state only for unchanged URL+kind, and an auth block lifts on nothing less.
func TestReconfigureAuthBlockLifecycle(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://TEST-user:TEST-pass@a.test:1080", "socks5://b.test:1080")
	blocked := pl.entries[0]
	pl.ReportAuthBlocked(blocked, errors.New("endpoint rejected credentials"))

	kept := pl.Reconfigure([]config.RouteSpec{
		{URL: mustURL(t, "socks5://TEST-user:TEST-pass@a.test:1080"), Kind: config.EgressV4},
		{URL: mustURL(t, "socks5://b.test:1080"), Kind: config.EgressV4},
	}, 30*time.Second, time.Minute)
	if kept.entries[0] != blocked {
		t.Fatal("identity-preserving reload rebuilt the auth-blocked route")
	}
	snap := kept.Snapshot()[0]
	if !snap.AuthBlocked || snap.Available || snap.AuthFailures != 1 {
		t.Fatalf("auth block lost across an identity-preserving reload: %+v", snap)
	}
	if got := kept.PickFor(nil, nil, "t:443"); got == nil || got.URL.Host != "b.test:1080" {
		t.Fatalf("pick after reload = %v, want the unblocked peer", got)
	}

	// Every identity change rebuilds the route with the block cleared.
	changes := []struct {
		name string
		spec config.RouteSpec
	}{
		{"userinfo", config.RouteSpec{URL: mustURL(t, "socks5://TEST-user:TEST-other@a.test:1080"), Kind: config.EgressV4}},
		{"kind", config.RouteSpec{URL: mustURL(t, "socks5://TEST-user:TEST-pass@a.test:1080"), Kind: config.EgressV6}},
		{"origin", config.RouteSpec{URL: mustURL(t, "socks5://TEST-user:TEST-pass@a.test:1080"), Kind: config.EgressV4, Origin: config.RouteOriginManual}},
	}
	for _, ch := range changes {
		rebuilt := pl.Reconfigure([]config.RouteSpec{
			ch.spec,
			{URL: mustURL(t, "socks5://b.test:1080"), Kind: config.EgressV4},
		}, 30*time.Second, time.Minute)
		if rebuilt.entries[0] == blocked {
			t.Fatalf("%s change reused the blocked route object", ch.name)
		}
		s := rebuilt.Snapshot()[0]
		if s.AuthBlocked || !s.Available || s.AuthFailures != 0 {
			t.Fatalf("%s change kept the auth block: %+v", ch.name, s)
		}
		if got := rebuilt.PickFor(nil, nil, "t:443"); got == nil || got != rebuilt.entries[0] {
			t.Fatalf("%s change: pick = %v, want the rebuilt route chosen first", ch.name, got)
		}
	}
}

func TestSnapshotFields(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1", "socks5://b:2")
	pl.ReportFailure(pl.entries[0], errors.New("dial refused"))

	snap := pl.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot len = %d, want 2", len(snap))
	}
	a := snap[0]
	if a.Proxy != "a:1" || a.Available || a.ConsecutiveFailures != 1 || a.Failures != 1 || a.LastDialError != "dial refused" {
		t.Fatalf("status a = %+v", a)
	}
	if a.CooldownFor == "" || a.CooldownFor == "0s" {
		t.Fatalf("status a cooldown = %q, want positive", a.CooldownFor)
	}
	b := snap[1]
	if b.Proxy != "b:2" || !b.Available || b.CooldownFor != "0s" || b.LastDialError != "" {
		t.Fatalf("status b = %+v", b)
	}
}
