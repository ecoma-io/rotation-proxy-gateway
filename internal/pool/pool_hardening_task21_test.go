package pool

import (
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"
)

func mustParseAll(t *testing.T, raws ...string) []*url.URL {
	t.Helper()
	out := make([]*url.URL, 0, len(raws))
	for _, r := range raws {
		out = append(out, mustURL(t, r))
	}
	return out
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
				p := pl.Pick(nil)
				if p == nil {
					return
				}
				pl.ReportSuccess(p)
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

	seqBeforeA := pl.entries[0].lastUsedSequence()
	seqBeforeB := pl.entries[1].lastUsedSequence()
	got := pl.Pick(nil)
	if got == nil || got.URL.Host != "a.test:1080" {
		t.Fatalf("pick with all cooling = %v, want a.test:1080 (soonest recovery)", got)
	}
	if seqAfter := got.lastUsedSequence(); seqAfter <= seqBeforeA && seqAfter <= seqBeforeB {
		t.Fatalf("fallback pick did not advance usedSeq: before a=%d b=%d after=%d", seqBeforeA, seqBeforeB, seqAfter)
	}
	// Second fallback pick with both still cooling must rotate to the other route
	// now that the first fallback choice is marked most-recently used... but both
	// are cooling so earliest-recovery still wins; at minimum seq must keep advancing.
	second := pl.Pick(nil)
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

// Defect 5a: reload retains exact canonical URLs with state, reorders, resets changed creds.
func TestHardeningReloadRetainsCanonicalState(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://TEST-user:TEST-pass@a.test:1080", "socks5://b.test:1080", "socks5://c.test:1080")
	pl.ReportSuccess(pl.entries[0])
	pl.ReportFailure(pl.entries[1], errors.New("TEST dial refused"))
	// Advance pick sequence so entries have distinct usedSeq.
	pl.Pick(nil)
	pl.Pick(nil)

	oldA := pl.entries[0]
	oldB := pl.entries[1]
	pl.Reload(mustParseAll(t,
		"socks5://c.test:1080",
		"socks5://b.test:1080",
		"socks5://TEST-user:TEST-pass@a.test:1080",
	))
	if len(pl.entries) != 3 {
		t.Fatalf("reload len = %d, want 3", len(pl.entries))
	}
	// Reordering: c first, then b, then a — pointers preserved.
	if pl.entries[0].URL.Host != "c.test:1080" || pl.entries[1].URL.Host != "b.test:1080" {
		t.Fatalf("reload order = %s %s %s, want c b a",
			pl.entries[0].URL.Host, pl.entries[1].URL.Host, pl.entries[2].URL.Host)
	}
	if pl.entries[1] != oldB {
		t.Fatalf("reordered b.test:1080 lost identity/state")
	}
	if pl.entries[2] != oldA {
		t.Fatalf("reordered a.test:1080 lost identity/state")
	}
	if snap := pl.Snapshot(); snap[1].Failures != 1 || snap[2].Successes != 1 {
		t.Fatalf("reload lost state: %+v", snap)
	}

	// Changed credentials reset.
	pl.Reload(mustParseAll(t, "socks5://TEST-user:TEST-other@a.test:1080"))
	if len(pl.entries) != 1 {
		t.Fatalf("reload len = %d, want 1", len(pl.entries))
	}
	if pl.entries[0] == oldA {
		t.Fatalf("changed credentials reused old route object, want fresh state")
	}
	snap := pl.Snapshot()
	if snap[0].Successes != 0 || snap[0].Failures != 0 || snap[0].AuthBlocked {
		t.Fatalf("changed-credential route not fresh: %+v", snap[0])
	}
}

// Defect 5b: concurrent Pick/Report*/Snapshot/Reload is race-free.
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
				_ = pl.Pick(nil)
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
				pl.ReportSuccess(routes[j%2])
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
	// Reload racing with readers.
	ra, rb := mustURL(t, "socks5://a.test:1080"), mustURL(t, "socks5://b.test:1080")
	for i := 0; i < 2; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				pl.Reload([]*url.URL{ra, rb})
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = pl.Pick(nil)
			}
		}()
	}
	wg.Wait()
}
