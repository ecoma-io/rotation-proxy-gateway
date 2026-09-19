package pool

import (
	"errors"
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
		if got := saturatingCooldown(base, max, tc.failures); got != tc.want {
			t.Errorf("saturatingCooldown(%v, %v, %d) = %v, want %v", base, max, tc.failures, got, tc.want)
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
			got := saturatingCooldown(tc.base, tc.max, tc.failures)
			if got != tc.want {
				t.Fatalf("saturatingCooldown(%v, %v, %d) = %v, want %v", tc.base, tc.max, tc.failures, got, tc.want)
			}
			if tc.wantNonNegZero && got < 0 {
				t.Fatalf("saturatingCooldown(%v, %v, %d) = %v, must never be negative", tc.base, tc.max, tc.failures, got)
			}
		})
	}
}
