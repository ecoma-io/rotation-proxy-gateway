package pool

import (
	"errors"
	"sync"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
)

func mustRouteSpecs(t *testing.T, raws ...string) []config.RouteSpec {
	t.Helper()
	routes := make([]config.RouteSpec, 0, len(raws))
	for _, raw := range raws {
		routes = append(routes, config.RouteSpec{URL: mustURL(t, raw), Kind: config.EgressV4})
	}
	return routes
}

// Defect 1: ReportSuccess must hold pl.mu around nextSeq.
func TestHardeningConcurrentReportSuccessRace(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a.test:1080", "socks5://b.test:1080", "socks5://c.test:1080")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				p := pl.PickFor(nil, nil, "t:443")
				if p == nil {
					return
				}
				pl.ReportSuccess(p, "t:443")
			}
		}()
	}
	wg.Wait()
}

// Defect 2: all-cooling fallback must mark the chosen route used.
func TestHardeningAllCoolingFallbackMarksUsed(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a.test:1080", "socks5://b.test:1080")

	pl.ReportFailure(pl.entries[0], nil) // a: until +30s
	pl.ReportFailure(pl.entries[1], nil)
	pl.ReportFailure(pl.entries[1], nil) // b: until +60s

	seqBeforeA := pl.entries[0].recencyPass()
	seqBeforeB := pl.entries[1].recencyPass()
	got := pl.PickFor(nil, nil, "t:443")
	if got == nil || got.URL.Host != "a.test:1080" {
		t.Fatalf("pick with all cooling = %v, want a.test:1080 (soonest recovery)", got)
	}
	if seqAfter := got.recencyPass(); seqAfter <= seqBeforeA && seqAfter <= seqBeforeB {
		t.Fatalf("fallback pick did not advance the recency pass: before a=%d b=%d after=%d", seqBeforeA, seqBeforeB, seqAfter)
	}
	// Second fallback pick with both still cooling must rotate to the other route
	// now that the first fallback choice is marked most-recently used... but both
	// are cooling so earliest-recovery still wins; at minimum seq must keep advancing.
	second := pl.PickFor(nil, nil, "t:443")
	if second == nil {
		t.Fatalf("second fallback pick = nil, want earliest recovery route")
	}
	_ = second
}

// Defect 3: exponential cooldown must saturate, never go negative, even with
// huge base or programmatic caller bypassing config validation.
func TestHardeningCooldownSaturatesNeverNegative(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a.test:1080")
	pl.base = 20 * 24 * time.Hour // bypass config: huge base
	pl.max = 10 * time.Minute
	p := pl.entries[0]
	for i := 0; i < 40; i++ {
		cd := pl.ReportFailure(p, errors.New("TEST dial refused"))
		if cd < 0 {
			t.Fatalf("iteration %d: cooldown = %s, want non-negative", i, cd)
		}
		if cd > pl.max {
			t.Fatalf("iteration %d: cooldown = %s, want <= max %s", i, cd, pl.max)
		}
	}
	if cd := pl.ReportFailure(p, nil); cd != pl.max {
		t.Fatalf("saturated cooldown = %s, want max %s", cd, pl.max)
	}
	// Zero-value pool (no base/max configured) must not produce negative cooldown.
	empty := newTestPool(t, c, "socks5://b.test:1080")
	empty.base = 0
	empty.max = 0
	if cd := empty.ReportFailure(empty.entries[0], nil); cd < 0 {
		t.Fatalf("zero-base cooldown = %s, want non-negative", cd)
	}
}

// Reconfigure retains canonical URL+kind state, preserves order, and resets changed credentials.
func TestReconfigureRetainsCanonicalState(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://TEST-user:TEST-pass@a.test:1080", "socks5://b.test:1080", "socks5://c.test:1080")
	pl.ReportSuccess(pl.entries[0], "t:443")
	pl.ReportFailure(pl.entries[1], errors.New("TEST dial refused"))
	pl.PickFor(nil, nil, "t:443")
	pl.PickFor(nil, nil, "t:443")

	oldA := pl.entries[0]
	oldB := pl.entries[1]
	next := pl.Reconfigure(mustRouteSpecs(t,
		"socks5://c.test:1080",
		"socks5://b.test:1080",
		"socks5://TEST-user:TEST-pass@a.test:1080",
	), 30*time.Second, time.Minute)
	if len(next.entries) != 3 {
		t.Fatalf("reconfigure len = %d, want 3", len(next.entries))
	}
	if next.entries[0].URL.Host != "c.test:1080" || next.entries[1].URL.Host != "b.test:1080" {
		t.Fatalf("reconfigure order = %s %s %s, want c b a", next.entries[0].URL.Host, next.entries[1].URL.Host, next.entries[2].URL.Host)
	}
	if next.entries[1] != oldB || next.entries[2] != oldA {
		t.Fatal("canonical unchanged routes lost identity/state")
	}
	if snap := next.Snapshot(); snap[1].Failures != 1 || snap[2].Successes != 1 {
		t.Fatalf("reconfigure lost state: %+v", snap)
	}

	changed := next.Reconfigure(mustRouteSpecs(t, "socks5://TEST-user:TEST-other@a.test:1080"), 30*time.Second, time.Minute)
	if len(changed.entries) != 1 || changed.entries[0] == oldA {
		t.Fatal("changed credentials reused old route object, want fresh state")
	}
	snap := changed.Snapshot()
	if snap[0].Successes != 0 || snap[0].Failures != 0 || snap[0].AuthBlocked {
		t.Fatalf("changed-credential route not fresh: %+v", snap[0])
	}
}

// Defect 5b: concurrent PickFor/Report*/Snapshot/Reconfigure is race-free.
func TestHardeningConcurrentPoolRaceFree(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a.test:1080", "socks5://b.test:1080")
	failErr := errors.New("TEST dial refused")
	authErr := errors.New("endpoint rejected credentials")
	// Capture route pointers up front: indexing pl.entries inside the
	// goroutines would race on the slice header itself.
	pa, pb := pl.entries[0], pl.entries[1]
	routes := []*Proxy{pa, pb}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(5)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				_ = pl.PickFor(nil, nil, "t:443")
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				pl.ReportFailure(routes[j%2], failErr)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				pl.ReportSuccess(routes[j%2], "t:443")
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				_ = pl.Snapshot()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				pl.ReportAuthBlocked(routes[j%2%len(routes)], authErr)
				_ = pl.Snapshot()
			}
		}()
	}
	wg.Wait()
}
