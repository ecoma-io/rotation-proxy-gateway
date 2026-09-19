package pool

import (
	"fmt"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
)

// weightedPool builds a same-kind pool whose routes carry the given weights.
// Route i is reachable as pl.entries[i] and answers to host w<i>.
func weightedPool(t *testing.T, c *clock, weights ...int) *Pool {
	t.Helper()
	routes := make([]config.RouteSpec, 0, len(weights))
	for i, w := range weights {
		routes = append(routes, config.RouteSpec{
			URL:    mustURL(t, fmt.Sprintf("socks5://w%d.test:1080", i)),
			Kind:   config.EgressV4,
			Weight: w,
		})
	}
	pl := NewRoutes(routes, 30*time.Second, time.Minute)
	pl.Now = c.NowFunc
	return pl
}

// hosts maps a pick sequence to the w<i> host labels the tests assert on.
func hosts(picks []*Proxy) []string {
	out := make([]string, len(picks))
	for i, p := range picks {
		out[i] = p.URL.Host
	}
	return out
}

func pickN(t *testing.T, pl *Pool, n int) []*Proxy {
	t.Helper()
	picks := make([]*Proxy, 0, n)
	for range n {
		p := pl.PickFor(nil, nil)
		if p == nil {
			t.Fatalf("pick ran dry after %d picks", len(picks))
		}
		picks = append(picks, p)
	}
	return picks
}

func equalHosts(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// The weighted pass clock is deterministic. Weights 4:2:1 advance their
// passes by strides 1:2:4 (scaled): the opening picks hand every route one
// free lap pick, then the heavy route re-enters proportionally more often.
func TestWeightedPickOrderExact(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := weightedPool(t, c, 4, 2, 1)

	got := hosts(pickN(t, pl, 15))
	want := []string{
		"w0.test:1080", "w1.test:1080", "w2.test:1080",
		"w0.test:1080", "w0.test:1080", "w1.test:1080",
		"w0.test:1080", "w0.test:1080", "w1.test:1080",
		"w2.test:1080", "w0.test:1080", "w0.test:1080",
		"w1.test:1080", "w0.test:1080", "w0.test:1080",
	}
	if !equalHosts(got, want...) {
		t.Fatalf("weighted pick order = %v", got)
	}
}

// Weights 1:2 give the textbook two-step cycle: heavy route picked twice per
// light pick.
func TestWeightedPickOrderTwoRoutes(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := weightedPool(t, c, 1, 2)

	got := hosts(pickN(t, pl, 7))
	want := []string{
		"w0.test:1080", "w1.test:1080", "w1.test:1080",
		"w0.test:1080", "w1.test:1080", "w1.test:1080",
		"w0.test:1080",
	}
	if !equalHosts(got, want...) {
		t.Fatalf("weighted pick order = %v", got)
	}
}

// Long-run pick shares converge to the configured weight ratios.
func TestWeightedPickSharesLongRun(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := weightedPool(t, c, 3, 1)

	picks := pickN(t, pl, 200)
	counts := map[string]int{}
	for _, p := range picks {
		counts[p.URL.Host]++
	}
	// 200 picks split 3:1 -> 150/50; the deterministic sequence may wobble a
	// few picks around the ratio while the passes align, so allow 5%.
	if abs(counts["w0.test:1080"]-150) > 10 || abs(counts["w1.test:1080"]-50) > 10 {
		t.Fatalf("shares over 200 picks = %v, want ~150/50", counts)
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// The all-cooling fallback stays weight-blind: soonest recovery is the only
// criterion that matters once nothing is immediately usable.
func TestWeightedFallbackIgnoresWeights(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := weightedPool(t, c, 1000, 1)

	pl.ReportFailure(pl.entries[0], nil) // heavy route: until +30s
	pl.ReportFailure(pl.entries[1], nil)
	pl.ReportFailure(pl.entries[1], nil) // light route: until +60s

	if got := pl.PickFor(nil, nil).URL.Host; got != "w0.test:1080" {
		t.Fatalf("all-cooling pick = %s, want w0 (soonest recovery, not heaviest)", got)
	}
}

// ReportSuccess advances the route one extra weighted step: a route that just
// served waits for its peers before absorbing traffic again.
func TestReportSuccessAdvancesWeightedStep(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := weightedPool(t, c, 1, 1)

	first := pl.PickFor(nil, nil)
	pl.ReportSuccess(first)
	pl.PickFor(nil, nil) // the other route

	got := hosts(pickN(t, pl, 2))
	if !equalHosts(got, "w1.test:1080", "w0.test:1080") {
		t.Fatalf("picks after success = %v, want w1 then w0 (served route demoted one step)", got)
	}
}

// MarkStale jumps the stale route behind the whole pool by its weighted step.
func TestMarkStaleJumpsWeightedBack(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := weightedPool(t, c, 1, 1, 5)

	pl.PickFor(nil, nil) // w0
	pl.PickFor(nil, nil) // w1
	heavy := pl.entries[2]
	heavy.BeginRotation(RotationVerifying)
	pl.MarkStale(heavy, 90*time.Second, 1)

	got := hosts(pickN(t, pl, 3))
	if !equalHosts(got, "w0.test:1080", "w1.test:1080", "w2.test:1080") {
		t.Fatalf("picks after stale = %v, want fresh routes first, stale route last in lap", got)
	}
}

// Reload applies a new weight to the retained route without touching its
// health state, and the new weight drives subsequent picks.
func TestReconfigureRetunesWeightKeepingState(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	specs := []config.RouteSpec{
		{URL: mustURL(t, "socks5://w0.test:1080"), Kind: config.EgressV4, Weight: 1},
		{URL: mustURL(t, "socks5://w1.test:1080"), Kind: config.EgressV4, Weight: 1},
	}
	pl := NewRoutes(specs, 30*time.Second, time.Minute)
	pl.Now = c.NowFunc

	a := pl.PickFor(nil, nil)
	pl.ReportSuccess(a)
	if snap := pl.Snapshot()[0]; snap.Successes != 1 {
		t.Fatalf("pre-reload successes = %d, want 1", snap.Successes)
	}

	retuned := []config.RouteSpec{
		{URL: specs[0].URL, Kind: config.EgressV4, Weight: 3},
		{URL: specs[1].URL, Kind: config.EgressV4, Weight: 1},
	}
	next := pl.Reconfigure(retuned, 30*time.Second, time.Minute)
	if next.entries[0] != a {
		t.Fatalf("weight retune rebuilt the retained route")
	}
	snap := next.Snapshot()
	if snap[0].Weight != 3 || snap[1].Weight != 1 {
		t.Fatalf("status weights = %d/%d, want 3/1", snap[0].Weight, snap[1].Weight)
	}
	if snap[0].Successes != 1 {
		t.Fatalf("weight retune reset successes: %+v", snap[0])
	}

	counts := map[string]int{}
	for _, p := range pickN(t, next, 40) {
		counts[p.URL.Host]++
	}
	if abs(counts["w0.test:1080"]-30) > 4 || abs(counts["w1.test:1080"]-10) > 4 {
		t.Fatalf("shares after retune = %v, want ~30/10 for weights 3:1", counts)
	}
}

// A route added by reload joins the rotation within the first lap — it must
// not burst against accumulated passes.
func TestReconfigureAnchorsNewRouteAtRecencyFront(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	specs := []config.RouteSpec{
		{URL: mustURL(t, "socks5://w0.test:1080"), Kind: config.EgressV4, Weight: 1},
		{URL: mustURL(t, "socks5://w1.test:1080"), Kind: config.EgressV4, Weight: 1},
	}
	pl := NewRoutes(specs, 30*time.Second, time.Minute)
	pl.Now = c.NowFunc
	pl.PickFor(nil, nil)
	pl.PickFor(nil, nil)

	grown := []config.RouteSpec{
		specs[0],
		specs[1],
		{URL: mustURL(t, "socks5://w2.test:1080"), Kind: config.EgressV4, Weight: 1},
	}
	next := pl.Reconfigure(grown, 30*time.Second, time.Minute)

	got := hosts(pickN(t, next, 3))
	if !equalHosts(got, "w0.test:1080", "w1.test:1080", "w2.test:1080") {
		t.Fatalf("picks after growth = %v, want the new route integrated within one lap", got)
	}
}

// Hand-built specs that bypass YAML validation treat a weight below the
// default as the default.
func TestZeroWeightSpecBehavesAsDefault(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	specs := []config.RouteSpec{
		{URL: mustURL(t, "socks5://w0.test:1080"), Kind: config.EgressV4, Weight: 0},
		{URL: mustURL(t, "socks5://w1.test:1080"), Kind: config.EgressV4, Weight: -3},
	}
	pl := NewRoutes(specs, 30*time.Second, time.Minute)
	pl.Now = c.NowFunc

	snap := pl.Snapshot()
	if snap[0].Weight != 1 || snap[1].Weight != 1 {
		t.Fatalf("status weights = %d/%d, want defaults 1/1", snap[0].Weight, snap[1].Weight)
	}
	got := hosts(pickN(t, pl, 4))
	if !equalHosts(got, "w0.test:1080", "w1.test:1080", "w0.test:1080", "w1.test:1080") {
		t.Fatalf("pick order = %v, want plain round-robin", got)
	}
}

// Equal configured weights and no weight configuration are the same thing:
// both reproduce plain round-robin (mirrors TestRoundRobinCyclesAll).
func TestEqualWeightsReproduceRoundRobin(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := weightedPool(t, c, 1, 1, 1)

	got := hosts(pickN(t, pl, 6))
	if !equalHosts(got, "w0.test:1080", "w1.test:1080", "w2.test:1080",
		"w0.test:1080", "w1.test:1080", "w2.test:1080") {
		t.Fatalf("equal-weight pick order = %v", got)
	}
}
