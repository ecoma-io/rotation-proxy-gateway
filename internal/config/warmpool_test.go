package config

import (
	"strings"
	"testing"
	"time"
)

const warmPoolBlock = `warm-pool:
  enabled: true
  min-idle-per-proxy: 2
  max-idle-per-proxy: 4
  max-total-idle: 16
  max-replenish-concurrency: 3
  max-replenish-per-route: 1
  idle-ttl: 30s
`

func TestLoadRuntimeWarmPoolDefaultsWhenAbsent(t *testing.T) {
	cfg, err := LoadRuntime(writeRuntimeConfig(t, validRuntimeConfig))
	if err != nil {
		t.Fatalf("LoadRuntime() error = %v", err)
	}
	w := cfg.WarmPool
	if w.Enabled {
		t.Fatal("warm-pool default enabled")
	}
	if w.MinIdlePerProxy != DefaultWarmMinIdlePerProxy || w.MaxIdlePerProxy != DefaultWarmMaxIdlePerProxy ||
		w.MaxTotalIdle != DefaultWarmMaxTotalIdle || w.MaxReplenishConcurrency != DefaultWarmMaxReplenishConcurrency ||
		w.MaxReplenishPerRoute != DefaultWarmMaxReplenishPerRoute ||
		w.IdleTTL != DefaultWarmIdleTTL {
		t.Fatalf("warm-pool defaults = %+v", w)
	}
	if w.MaxReplenishPerRoute != 0 {
		t.Fatalf("default max-replenish-per-route = %d, want 0 (uncapped)", w.MaxReplenishPerRoute)
	}
}

func TestLoadRuntimeWarmPoolFullBlock(t *testing.T) {
	cfg, err := LoadRuntime(writeRuntimeConfig(t, validRuntimeConfig+warmPoolBlock))
	if err != nil {
		t.Fatalf("LoadRuntime() error = %v", err)
	}
	w := cfg.WarmPool
	if !w.Enabled || w.MinIdlePerProxy != 2 || w.MaxIdlePerProxy != 4 ||
		w.MaxTotalIdle != 16 || w.MaxReplenishConcurrency != 3 ||
		w.MaxReplenishPerRoute != 1 || w.IdleTTL != 30*time.Second {
		t.Fatalf("warm-pool = %+v", w)
	}
}

// A disabled pool still validates its bounds: a bad bound is reported at load
// time, not silently shipped to the day the pool is switched on.
func TestLoadRuntimeWarmPoolInvalidEvenWhenDisabled(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"min exceeds max", `
warm-pool:
  min-idle-per-proxy: 5
  max-idle-per-proxy: 4
`, "must not exceed"},
		{"max idle below one", `
warm-pool:
  max-idle-per-proxy: 0
`, "max-idle-per-proxy must be >= 1"},
		{"total below per-route max", `
warm-pool:
  max-total-idle: 1
`, "must be at least"},
		{"fractional count", `
warm-pool:
  max-replenish-concurrency: 2.5
`, "must be a whole number"},
		{"negative per-route cap", `
warm-pool:
  max-replenish-per-route: -1
`, "max-replenish-per-route must be >= 0"},
		{"fractional per-route cap", `
warm-pool:
  max-replenish-per-route: 1.5
`, "must be a whole number"},
		{"bad duration", `
warm-pool:
  idle-ttl: soon
`, "must be a Go duration"},
		{"zero duration", `
warm-pool:
  idle-ttl: 0s
`, "must be positive"},
		{"negative min", `
warm-pool:
  min-idle-per-proxy: -1
`, "must be >= 0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadRuntime(writeRuntimeConfig(t, validRuntimeConfig+tc.content))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestLoadRuntimeWarmPoolUnknownKeyRejected(t *testing.T) {
	_, err := LoadRuntime(writeRuntimeConfig(t, validRuntimeConfig+`
warm-pool:
  enabled: true
  idle-ttl-x: 30s
`))
	if err == nil || !strings.Contains(err.Error(), "decode runtime config") {
		t.Fatalf("error = %v, want a decode failure for the unknown key", err)
	}
}
