package pool

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
)

// balancedPool builds a pool with one route per given kind in order. Route i
// answers to host k<i>.
func balancedPool(t *testing.T, c *clock, balance config.KindBalance, kinds ...config.EgressKind) *Pool {
	t.Helper()
	routes := make([]config.RouteSpec, 0, len(kinds))
	for i, kind := range kinds {
		routes = append(routes, config.RouteSpec{
			URL:  mustURL(t, fmt.Sprintf("socks5://k%d.test:1080", i)),
			Kind: kind,
		})
	}
	pl := NewRoutes(routes, 30*time.Second, time.Minute, balance)
	pl.Now = c.NowFunc
	return pl
}

func countKinds(picks []*Proxy) map[config.EgressKind]int {
	counts := map[config.EgressKind]int{}
	for _, p := range picks {
		counts[p.Kind]++
	}
	return counts
}

// Equal shares alternate the families strictly: the family clocks tick in
// lockstep, so mixed picks hand off v4 -> v6 forever.
func TestBalancedFamiliesAlternateOneToOne(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := balancedPool(t, c, config.KindBalance{V4: 1, V6: 1}, config.EgressV4, config.EgressV6)

	var got []config.EgressKind
	for _, p := range pickN(t, pl, 6) {
		got = append(got, p.Kind)
	}
	want := []config.EgressKind{
		config.EgressV4, config.EgressV6,
		config.EgressV4, config.EgressV6,
		config.EgressV4, config.EgressV6,
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("balanced pick order = %v, want strict alternation", got)
		}
	}
}

// The split is two-level: the family clock picks the family, then the
// weighted recency order picks inside it. Two same-family routes therefore
// alternate while the families interleave.
func TestBalancedTwoLevelOrderWithinFamily(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := balancedPool(t, c, config.KindBalance{V4: 1, V6: 1},
		config.EgressV4, config.EgressV4, config.EgressV6)

	got := hosts(pickN(t, pl, 8))
	want := []string{
		"k0.test:1080", "k2.test:1080",
		"k1.test:1080", "k2.test:1080",
		"k0.test:1080", "k2.test:1080",
		"k1.test:1080", "k2.test:1080",
	}
	if !equalHosts(got, want...) {
		t.Fatalf("two-level pick order = %v, want v4 routes alternating inside the family split", got)
	}
}

// Shares 2:1 divide evenly on power-of-two strides, so the split is exact:
// 60 picks land 40/20.
func TestBalancedSplitsProportionallyExact(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := balancedPool(t, c, config.KindBalance{V4: 2, V6: 1}, config.EgressV4, config.EgressV6)

	counts := countKinds(pickN(t, pl, 60))
	if counts[config.EgressV4] != 40 || counts[config.EgressV6] != 20 {
		t.Fatalf("shares over 60 picks = %v, want exact 40/20 for 2:1", counts)
	}
}

// Shares 7:3 hold the ratio long-run; flooring the strides may wobble a few
// picks around the target, so allow a small band.
func TestBalancedSplitsProportionallyLongRun(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := balancedPool(t, c, config.KindBalance{V4: 7, V6: 3}, config.EgressV4, config.EgressV6)

	counts := countKinds(pickN(t, pl, 200))
	if abs(counts[config.EgressV4]-140) > 6 || abs(counts[config.EgressV6]-60) > 6 {
		t.Fatalf("shares over 200 picks = %v, want ~140/60 for 7:3", counts)
	}
}

// A family without a share never wins while the shared family is live, but it
// stays available as standby: cooldown the shared family and the standby
// serves, then hands back once the shared family recovers.
func TestBalancedZeroShareFamilyIsStandby(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := balancedPool(t, c, config.KindBalance{V4: 1}, config.EgressV4, config.EgressV6)

	for _, p := range pickN(t, pl, 6) {
		if p.Kind != config.EgressV4 {
			t.Fatalf("pick = %s, want v4 only while it is live", p.Kind)
		}
	}

	pl.ReportFailure(pl.entries[0], errors.New("TEST dial refused"))
	if got := pl.PickFor(nil, nil, "t:443"); got.Kind != config.EgressV6 {
		t.Fatalf("standby pick = %s, want v6 while v4 cools down", got.Kind)
	}

	c.advance(time.Minute)
	for _, p := range pickN(t, pl, 4) {
		if p.Kind != config.EgressV4 {
			t.Fatalf("pick after cooldown = %s, want v4 serving again", p.Kind)
		}
	}
}

// The dedicated listeners ignore the ratio: their kind filter leaves one
// family, and the dedicated pick path then degenerates to the plain weighted
// order — the balance layer is not consulted at all.
func TestBalancedDedicatedKindIgnoresRatio(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := balancedPool(t, c, config.KindBalance{V4: 7, V6: 3}, config.EgressV4, config.EgressV6)

	for i, kind := range []config.EgressKind{config.EgressV6, config.EgressV4} {
		var got []config.EgressKind
		for range 4 {
			p := pl.PickForDedicated(nil, only(kind), "t:443")
			if p == nil {
				t.Fatalf("dedicated %s pick ran dry", kind)
			}
			got = append(got, p.Kind)
		}
		if got[0] != kind || got[3] != kind {
			t.Fatalf("dedicated picks %d = %v, want only %s", i, got, kind)
		}
	}
}

// Dedicated picks never touch the family clocks, not even the all-cooling
// fallback: a burst of v4-listener traffic leaves the mixed split's phase
// exactly where it was, and the next mixed pick continues as if the burst
// never happened.
func TestDedicatedPickNeverAdvancesFamilyClocks(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := balancedPool(t, c, config.KindBalance{V4: 1, V6: 1}, config.EgressV4, config.EgressV6)
	before := pl.kindPass

	for range 10 {
		p := pl.PickForDedicated(nil, only(config.EgressV4), "t:443")
		if p == nil || p.Kind != config.EgressV4 {
			t.Fatalf("dedicated pick = %v, want the v4 route", p)
		}
	}
	if pl.kindPass != before {
		t.Fatalf("family clocks = %v after the dedicated burst, want untouched %v", pl.kindPass, before)
	}

	// The mixed split is unaffected: with untouched clocks v4 wins the next
	// mixed pick, and that pick does advance the clocks — proving the
	// assertion above has teeth.
	if got := pl.PickFor(nil, nil, "t:443"); got.Kind != config.EgressV4 {
		t.Fatalf("first mixed pick after the dedicated burst = %s, want v4 (clocks untouched)", got.Kind)
	}
	afterMixed := pl.kindPass
	if afterMixed == before {
		t.Fatal("mixed pick did not advance the family clocks; the dedicated assertion proves nothing")
	}

	// The all-cooling fallback on the dedicated path keeps the same
	// discipline: the cooling v4 route serves without touching the clocks.
	pl.ReportFailure(pl.entries[0], errors.New("TEST dial refused"))
	if p := pl.PickForDedicated(nil, only(config.EgressV4), "t:443"); p == nil {
		t.Fatal("dedicated cooling fallback ran dry")
	}
	if pl.kindPass != afterMixed {
		t.Fatalf("family clocks = %v after the dedicated fallback, want untouched %v", pl.kindPass, afterMixed)
	}
}

// Reloading carries the family clocks, so the split's phase survives: after a
// v4 pick, the post-reload pick continues with v6 instead of restarting at v4.
func TestReconfigureCarriesFamilyClocks(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	kinds := []config.EgressKind{config.EgressV4, config.EgressV6}
	pl := balancedPool(t, c, config.KindBalance{V4: 1, V6: 1}, kinds...)

	if got := pl.PickFor(nil, nil, "t:443"); got.Kind != config.EgressV4 {
		t.Fatalf("first pick = %s, want v4", got.Kind)
	}

	next := pl.Reconfigure([]config.RouteSpec{
		{URL: mustURL(t, "socks5://k0.test:1080"), Kind: config.EgressV4},
		{URL: mustURL(t, "socks5://k1.test:1080"), Kind: config.EgressV6},
	}, 30*time.Second, time.Minute, config.KindBalance{V4: 1, V6: 1})
	if got := next.PickFor(nil, nil, "t:443"); got.Kind != config.EgressV6 {
		t.Fatalf("first pick after reload = %s, want v6 (family clocks carried over)", got.Kind)
	}
}
