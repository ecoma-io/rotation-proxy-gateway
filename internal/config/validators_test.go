package config

import (
	"strings"
	"testing"
)

// parseMaxConcurrent is the gate for the rotation concurrency knob: bad input
// must fail loudly at load, never silently clamp to a dangerous value.
func TestParseMaxConcurrentEdges(t *testing.T) {
	for _, raw := range []any{nil, 1, 8, "25%", "100%", "1%", "25 %"} {
		fixed, percent, err := parseMaxConcurrent(raw)
		if err != nil {
			t.Fatalf("parseMaxConcurrent(%v): %v", raw, err)
		}
		if (fixed == nil) == (percent == nil) {
			t.Fatalf("parseMaxConcurrent(%v) must return exactly one representation", raw)
		}
	}
	for _, tc := range []struct {
		name string
		raw  any
		want string
	}{
		{"zero count", 0, "must be >= 1"},
		{"negative count", -2, "must be >= 1"},
		{"zero percent", "0%", "whole number between 1 and 100"},
		{"over one hundred percent", "101%", "whole number between 1 and 100"},
		{"non-numeric", "abc", "must be a count or a percent"},
		{"bare percent sign", "%", "whole number between 1 and 100"},
		{"float count", 1.5, "must be a count or a percent"},
		{"bool", true, "must be a count or a percent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := parseMaxConcurrent(tc.raw); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parseMaxConcurrent(%v) = %v, want %q", tc.raw, err, tc.want)
			}
		})
	}
}

// Header values and methods flow into provider rotate-API calls; the RFC 9110
// shape checks pin the boundary so a typo'd config fails at load, not mid-cycle.
func TestHeaderAndMethodValidators(t *testing.T) {
	for _, value := range []string{"application/json", "Bearer abc123~!@#$", "tab\there", " space-padded "} {
		if !validHeaderFieldValue(value) {
			t.Errorf("validHeaderFieldValue(%q) = false", value)
		}
	}
	for _, value := range []string{"", "has\nnewline", "has\rcr", "euro-\u20ac", "del\x7f", "ctl\x01"} {
		if validHeaderFieldValue(value) {
			t.Errorf("validHeaderFieldValue(%q) = true", value)
		}
	}
	for _, method := range []string{"GET", "POST", "X-CUSTOM-1", "M-SEARCH"} {
		if !validHTTPMethod(method) {
			t.Errorf("validHTTPMethod(%q) = false", method)
		}
	}
	for _, method := range []string{"", "has space", "low er", "semi;colon", "paren(x)", strings.Repeat("G", 33)} {
		if validHTTPMethod(method) {
			t.Errorf("validHTTPMethod(%q) = true", method)
		}
	}
}

// SHUTDOWN_GRACE is process-global: garbage must fail LoadBootstrap loudly
// rather than silently keeping the default drain budget.
func TestLoadBootstrapRejectsBadShutdownGrace(t *testing.T) {
	t.Setenv("CONFIG_FILE", "")
	t.Setenv("ADMIN_ADDR", "")
	t.Setenv("MIXED_LISTEN_ADDR", DefaultMixedListenAddr)
	t.Setenv("V4_LISTEN_ADDR", DefaultV4ListenAddr)
	t.Setenv("V6_LISTEN_ADDR", DefaultV6ListenAddr)
	t.Setenv("SHUTDOWN_GRACE", "not-a-duration")
	_, err := LoadBootstrap()
	if err == nil || !strings.Contains(err.Error(), "SHUTDOWN_GRACE") {
		t.Fatalf("LoadBootstrap() error = %v, want SHUTDOWN_GRACE complaint", err)
	}
}
