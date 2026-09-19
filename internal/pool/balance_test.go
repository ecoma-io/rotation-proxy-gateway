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
	if got := pl.PickFor(nil, nil); got.Kind != config.EgressV6 {
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
// family, and the balance layer then degenerates to the plain weighted order.
func TestBalancedDedicatedKindIgnoresRatio(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := balancedPool(t, c, config.KindBalance{V4: 7, V6: 3}, config.EgressV4, config.EgressV6)

	for i, kind := range []config.EgressKind{config.EgressV6, config.EgressV4} {
		var got []config.EgressKind
		for range 4 {
			p := pl.PickFor(nil, only(kind))
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

// Reloading carries the family clocks, so the split's phase survives: after a
// v4 pick, the post-reload pick continues with v6 instead of restarting at v4.
func TestReconfigureCarriesFamilyClocks(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	kinds := []config.EgressKind{config.EgressV4, config.EgressV6}
	pl := balancedPool(t, c, config.KindBalance{V4: 1, V6: 1}, kinds...)

	if got := pl.PickFor(nil, nil); got.Kind != config.EgressV4 {
		t.Fatalf("first pick = %s, want v4", got.Kind)
	}

	next := pl.Reconfigure([]config.RouteSpec{
		{URL: mustURL(t, "socks5://k0.test:1080"), Kind: config.EgressV4},
		{URL: mustURL(t, "socks5://k1.test:1080"), Kind: config.EgressV6},
	}, 30*time.Second, time.Minute, config.KindBalance{V4: 1, V6: 1})
	if got := next.PickFor(nil, nil); got.Kind != config.EgressV6 {
		t.Fatalf("first pick after reload = %s, want v6 (family clocks carried over)", got.Kind)
	}
}
