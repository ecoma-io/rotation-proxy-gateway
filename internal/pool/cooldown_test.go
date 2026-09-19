package pool

import (
	"errors"
	"sync"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
)

// relNanos anchors cooldown deadlines to processStart so that, with the real
// clock (both endpoints carry monotonic readings), Time.Sub measures real
// elapsed time and wall-clock steps — NTP corrections, a corrected system
// date — can neither expire nor extend a running cooldown. A wall step with a
// continuing monotonic clock is not constructible through the exported Now
// seam (Time.Add strips the monotonic reading, and any clock lacking one
// exercises the wall fallback instead), so these tests pin the two halves of
// the contract that are observable: the helper's semantics, and the
// real-clock cooldown lifecycle.
func TestRelNanosSemantics(t *testing.T) {
	a := time.Now()
	time.Sleep(2 * time.Millisecond)
	b := time.Now()

	// Two real readings: the difference is real elapsed time (monotonic),
	// with a generous slop for scheduler noise.
	if diff := relNanos(b) - relNanos(a); diff < int64(time.Millisecond) || diff > int64(time.Second) {
		t.Fatalf("relNanos advanced by %v across a 2ms sleep, want real elapsed time", time.Duration(diff))
	}

	// A clock without a monotonic reading falls back to wall arithmetic
	// against the same anchor: consistent ordering and deltas.
	fake := time.Unix(10_000, 0)
	if relNanos(fake) >= relNanos(b) {
		t.Fatalf("relNanos(fake clock) = %v must predate relNanos(real now) = %v",
			time.Duration(relNanos(fake)), time.Duration(relNanos(b)))
	}
	if relNanos(fake.Add(time.Second))-relNanos(fake) != int64(time.Second) {
		t.Fatal("relNanos(fake.Add(1s)) - relNanos(fake) != 1s; wall fallback drifted")
	}

	// The zero-time sentinel is load-bearing: a never-cooled route stores 0,
	// which availableAt treats as always-available even though every real
	// relNanos value is positive and every pre-boot fake value is negative.
	if relNanos(fake) == 0 {
		t.Fatal("relNanos(fake) unexpectedly hit the sentinel value 0")
	}
}

func TestCooldownRealClockLifecycle(t *testing.T) {
	pl := NewRoutes([]config.RouteSpec{
		{URL: mustURL(t, "socks5://a:1"), Kind: config.EgressV4},
		{URL: mustURL(t, "socks5://b:2"), Kind: config.EgressV4},
	}, 300*time.Millisecond, 10*time.Second, config.KindBalance{})
	p := pl.PickFor(nil, nil)
	if p == nil {
		t.Fatal("pick = nil, want the first route")
	}
	if cd := pl.ReportFailure(p, errors.New("dial refused (TEST)")); cd != 300*time.Millisecond {
		t.Fatalf("applied cooldown = %s, want the 300ms base", cd)
	}

	// Immediately after the failure the route is cooling with the base left.
	snap := pl.Snapshot()[0]
	if snap.Proxy != p.URL.Host {
		t.Fatalf("snapshot[0] = %s, want the failed route", snap.Proxy)
	}
	if snap.Available {
		t.Fatalf("route available immediately after failure: %+v", snap)
	}
	remaining, err := time.ParseDuration(snap.CooldownFor)
	if err != nil || remaining <= 150*time.Millisecond || remaining > 300*time.Millisecond {
		t.Fatalf("CooldownFor = %q (err=%v), want (150ms, 300ms]", snap.CooldownFor, err)
	}

	// The next pick uses the healthy peer, not the cooling route.
	if got := pl.PickFor(nil, nil); got == nil || got.URL.Host == p.URL.Host {
		t.Fatalf("pick = %v, want the healthy peer b:2", got)
	}

	// After the real elapsed time the route recovers on its own.
	time.Sleep(320 * time.Millisecond)
	snap = pl.Snapshot()[0]
	if !snap.Available || snap.CooldownFor != "0s" {
		t.Fatalf("route did not recover after real elapsed time: %+v", snap)
	}
	if got := pl.PickFor(nil, nil); got != p {
		t.Fatalf("pick = %v, want the recovered route", got)
	}
}

// Cooldown writes are last-writer-wins under p.mu: whatever report lands
// last, the cooldown and the failure streak must agree. The concurrent storm
// before the final report is deliberately unordered — the assertions hold
// only because each report writes both fields as one critical section.
func TestCooldownAndStreakWriteAsOneUnit(t *testing.T) {
	pl := NewRoutes([]config.RouteSpec{{URL: mustURL(t, "socks5://a:1"), Kind: config.EgressV4}},
		30*time.Second, time.Minute, config.KindBalance{})
	p := pl.PickFor(nil, nil)
	if p == nil {
		t.Fatal("pick = nil, want the single route")
	}

	const workers, rounds = 8, 50
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for range rounds {
				pl.ReportFailure(p, errors.New("dial refused (TEST)"))
				pl.ReportSuccess(p)
			}
		}()
	}
	wg.Wait()

	// A final success must leave no cooldown and no failure streak...
	pl.ReportSuccess(p)
	snap := pl.Snapshot()[0]
	if !snap.Available || snap.CooldownFor != "0s" || snap.ConsecutiveFailures != 0 {
		t.Fatalf("post-success state = %+v, want available, no cooldown, no streak", snap)
	}
	if snap.Failures != workers*rounds || snap.Successes != workers*rounds+1 {
		t.Fatalf("counters = (%d failures, %d successes), want (%d, %d)",
			snap.Failures, snap.Successes, workers*rounds, workers*rounds+1)
	}

	// ...and a final failure must leave a live cooldown with the streak at 1.
	if cd := pl.ReportFailure(p, errors.New("dial refused (TEST)")); cd != 30*time.Second {
		t.Fatalf("applied cooldown = %s, want the 30s base after the success reset", cd)
	}
	snap = pl.Snapshot()[0]
	if snap.Available || snap.CooldownFor == "0s" || snap.ConsecutiveFailures != 1 {
		t.Fatalf("post-failure state = %+v, want cooling with streak 1", snap)
	}
}

// saturatingCooldown is the pool's backoff spine: exponential growth must cap
// at max, never overflow, and never return a negative duration even when base
// or max bypass runtime validation (direct unit construction does that).
func TestSaturatingCooldownMath(t *testing.T) {
	base, max := time.Second, 60*time.Second
	for _, tc := range []struct {
		failures int
		want     time.Duration
	}{
		{0, base},
		{1, base},
		{2, 2 * base},
		{3, 4 * base},
		{7, max}, // 64s would exceed max.
		{100, max},
	} {
		if got := SaturatingCooldown(base, max, tc.failures); got != tc.want {
			t.Errorf("SaturatingCooldown(%v, %v, %d) = %v, want %v", base, max, tc.failures, got, tc.want)
		}
	}
	for _, tc := range []struct {
		name           string
		base, max      time.Duration
		failures       int
		want           time.Duration
		wantNonNegZero bool
	}{
		{"base at max", max, max, 5, max, false},
		{"base above max", 2 * max, max, 5, max, false},
		{"zero base", 0, max, 5, 0, true},
		{"negative base", -time.Second, max, 5, 0, true},
		{"zero max", base, 0, 5, 0, true},
		{"huge base near overflow", time.Duration(1) << 62, time.Duration(1) << 62, 10, time.Duration(1) << 62, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := SaturatingCooldown(tc.base, tc.max, tc.failures)
			if got != tc.want {
				t.Fatalf("SaturatingCooldown(%v, %v, %d) = %v, want %v", tc.base, tc.max, tc.failures, got, tc.want)
			}
			if tc.wantNonNegZero && got < 0 {
				t.Fatalf("SaturatingCooldown(%v, %v, %d) = %v, must never be negative", tc.base, tc.max, tc.failures, got)
			}
		})
	}
}

// CoolingFor mirrors the availableAt arithmetic the pick path uses: the full
// remaining cooldown right after a failure, zero for healthy and recovered
// routes. The proxy server logs it when the all-cooling fallback serves.
func TestCoolingForReportsRemainingCooldown(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1", "socks5://b:2")

	a := pl.PickFor(nil, nil)
	if a == nil || a.URL.Host != "a:1" {
		t.Fatalf("pick = %v, want a:1", a)
	}
	if got := pl.CoolingFor(a); got != 0 {
		t.Fatalf("CoolingFor(healthy) = %s, want 0", got)
	}
	pl.ReportFailure(a, errors.New("dial refused (TEST)"))
	if got := pl.CoolingFor(a); got != 30*time.Second {
		t.Fatalf("CoolingFor right after failure = %s, want the 30s base", got)
	}
	c.advance(31 * time.Second)
	if got := pl.CoolingFor(a); got != 0 {
		t.Fatalf("CoolingFor after expiry = %s, want 0", got)
	}
}

// Size counts every route; CountAllowed applies only the listener's kind
// filter, health notwithstanding.
func TestPoolSizeAndCountAllowed(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1", "socks5://b:2", "socks5://c:3")
	v4Only := func(p *Proxy) bool { return p.Kind == config.EgressV4 }
	v6Only := func(p *Proxy) bool { return p.Kind == config.EgressV6 }

	if got := pl.Size(); got != 3 {
		t.Fatalf("Size() = %d, want 3", got)
	}
	if got := pl.CountAllowed(v4Only); got != 3 {
		t.Fatalf("CountAllowed(v4) = %d, want 3", got)
	}
	if got := pl.CountAllowed(v6Only); got != 0 {
		t.Fatalf("CountAllowed(v6) over a v4 pool = %d, want 0", got)
	}

	pl6 := NewRoutes([]config.RouteSpec{{URL: mustURL(t, "socks5://v6:1"), Kind: config.EgressV6}},
		30*time.Second, time.Minute, config.KindBalance{})
	if got := pl6.CountAllowed(v6Only); got != 1 {
		t.Fatalf("CountAllowed(v6) = %d, want 1", got)
	}
	if got := pl6.CountAllowed(v4Only); got != 0 {
		t.Fatalf("CountAllowed(v4) over a v6 pool = %d, want 0", got)
	}
}
