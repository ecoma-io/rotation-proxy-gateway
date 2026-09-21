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

// RPGW_SHUTDOWN_GRACE is process-global: garbage must fail LoadBootstrap loudly
// rather than silently keeping the default drain budget.
func TestLoadBootstrapRejectsBadShutdownGrace(t *testing.T) {
	t.Setenv("RPGW_CONFIG_FILE", "")
	t.Setenv("RPGW_ADMIN_ADDR", "")
	t.Setenv("RPGW_MIXED_LISTEN_ADDR", DefaultMixedListenAddr)
	t.Setenv("RPGW_V4_LISTEN_ADDR", DefaultV4ListenAddr)
	t.Setenv("RPGW_V6_LISTEN_ADDR", DefaultV6ListenAddr)
	t.Setenv("RPGW_SHUTDOWN_GRACE", "not-a-duration")
	_, err := LoadBootstrap()
	if err == nil || !strings.Contains(err.Error(), "RPGW_SHUTDOWN_GRACE") {
		t.Fatalf("LoadBootstrap() error = %v, want RPGW_SHUTDOWN_GRACE complaint", err)
	}
}

// The unprefixed bootstrap names are retired: a set legacy name must fail
// loudly with its replacement named, not let the process silently boot on
// defaults. Presence alone is fatal — an empty legacy listener value used to
// mean "disable", so ignoring it would silently re-enable the listener.
func TestLoadBootstrapRejectsLegacyEnvNames(t *testing.T) {
	for _, legacy := range []string{"ADMIN_ADDR", "CONFIG_FILE", "MIXED_LISTEN_ADDR", "SHUTDOWN_GRACE", "V4_LISTEN_ADDR", "V6_LISTEN_ADDR"} {
		t.Run(legacy, func(t *testing.T) {
			t.Setenv(legacy, "")
			_, err := LoadBootstrap()
			if err == nil || !strings.Contains(err.Error(), legacy) || !strings.Contains(err.Error(), "RPGW_"+legacy) {
				t.Fatalf("LoadBootstrap() error = %v, want %s renamed to RPGW_%s", err, legacy, legacy)
			}
		})
	}
	t.Run("every set legacy name is reported", func(t *testing.T) {
		t.Setenv("CONFIG_FILE", "config.yaml")
		t.Setenv("ADMIN_ADDR", "0.0.0.0:30120")
		_, err := LoadBootstrap()
		if err == nil || !strings.Contains(err.Error(), "RPGW_CONFIG_FILE") || !strings.Contains(err.Error(), "RPGW_ADMIN_ADDR") {
			t.Fatalf("LoadBootstrap() error = %v, want both legacy names reported", err)
		}
	})
}

// Overlap must compare ports numerically: validation admits leading-zero
// spellings, and two spellings of one port must collide at validation time,
// not as an "address already in use" bind failure afterwards.
func TestListenersOverlapNumericPorts(t *testing.T) {
	for _, pair := range [][2]string{
		{"0.0.0.0:80", "127.0.0.1:080"},
		{"127.0.0.1:0080", "[::]:80"},
		{"host.example:080", "HOST.example:80"},
	} {
		if !listenersOverlap(pair[0], pair[1]) {
			t.Errorf("listenersOverlap(%q, %q) = false, want true", pair[0], pair[1])
		}
	}
	for _, pair := range [][2]string{
		{"127.0.0.1:80", "127.0.0.2:80"},
		{"127.0.0.1:80", "127.0.0.1:81"},
	} {
		if listenersOverlap(pair[0], pair[1]) {
			t.Errorf("listenersOverlap(%q, %q) = true, want false", pair[0], pair[1])
		}
	}
}
