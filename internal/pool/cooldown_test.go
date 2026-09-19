package pool

import (
	"testing"
	"time"
)

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
