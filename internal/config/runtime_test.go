package config

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeRuntimeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const rotationBlock = `rotation:
  max-concurrent: 1
  drain-timeout: 30s
  ip-check-url: https://ipcheck.example/trace
  ip-check-timeout: 5s
  ip-check-interval: 1s
  retry-backoff-max: 4m
`

const validRuntimeConfig = `
log-level: debug
max-retries: 4
cooldown:
  base: 2s
  max: 1m
dial-timeout: 7s
` + rotationBlock + `
proxies:
  auto:
    - proxy: alice:secret@v4.example:1080
      kind: v4
    - proxy: "[2001:db8::1]:1080:bob:other-secret"
      kind: v6
  manual:
    - proxy: carol:manual-secret@manual.example:1080
      kind: v6
      rotate-interval: 90s
      api:
        url: https://provider.example/rotate
        method: POST
        headers:
          Content-Type: application/json
          X-Api-Token: rot-token
        body: |
          {"proxy_id": 7}
        timeout: 4s
`

// runtimeSecrets lists every credential the fixtures carry; no config error
// may echo any of them.
var runtimeSecrets = []string{"secret", "other-secret", "manual-secret", "rot-token"}

func assertNoSecretLeak(t *testing.T, err error) {
	t.Helper()
	for _, secret := range runtimeSecrets {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaked %q: %v", secret, err)
		}
	}
}

func TestLoadRuntimeMissingFileReportsSetupGuidance(t *testing.T) {
	_, err := LoadRuntime(filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil || !strings.Contains(err.Error(), "copy config.example.yaml") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadRuntimeParsesManualRoutesAndRotation(t *testing.T) {
	cfg, err := LoadRuntime(writeRuntimeConfig(t, validRuntimeConfig))
	if err != nil {
		t.Fatalf("LoadRuntime() error = %v", err)
	}
	if cfg.MaxRetries != 4 || cfg.CooldownBase != 2*time.Second || cfg.CooldownMax != time.Minute || cfg.DialTimeout != 7*time.Second || cfg.LogLevel != "debug" {
		t.Fatalf("unexpected runtime config: %+v", cfg)
	}
	if len(cfg.Routes) != 2 || cfg.Routes[0].Kind != EgressV4 || cfg.Routes[1].Kind != EgressV6 {
		t.Fatalf("routes = %+v", cfg.Routes)
	}
	if got := cfg.Routes[0].URL.Host; got != "v4.example:1080" {
		t.Fatalf("v4 route host = %q", got)
	}
	if cfg.Routes[0].Origin != RouteOriginAuto {
		t.Fatalf("auto origin = %q", cfg.Routes[0].Origin)
	}

	if len(cfg.ManualRoutes) != 1 {
		t.Fatalf("manual routes = %+v", cfg.ManualRoutes)
	}
	manual := cfg.ManualRoutes[0]
	if manual.URL.Host != "manual.example:1080" || manual.Kind != EgressV6 || manual.Origin != RouteOriginManual {
		t.Fatalf("manual route = %+v", manual.RouteSpec)
	}
	if manual.RotateInterval != 90*time.Second {
		t.Fatalf("rotate-interval = %s", manual.RotateInterval)
	}
	api := manual.API
	if api.URL.String() != "https://provider.example/rotate" || api.Method != http.MethodPost || api.Timeout != 4*time.Second {
		t.Fatalf("api = %+v", api)
	}
	if api.Headers["Content-Type"] != "application/json" || api.Headers["X-Api-Token"] != "rot-token" {
		t.Fatalf("api headers = %+v", api.Headers)
	}
	if !strings.Contains(api.Body, "proxy_id") {
		t.Fatalf("api body = %q", api.Body)
	}

	rotation := cfg.Rotation
	if rotation.MaxConcurrentFixed == nil || *rotation.MaxConcurrentFixed != 1 || rotation.MaxConcurrentPercent != nil {
		t.Fatalf("max-concurrent = fixed %v percent %v", rotation.MaxConcurrentFixed, rotation.MaxConcurrentPercent)
	}
	if rotation.DrainTimeout != 30*time.Second || rotation.IPCheckURL != "https://ipcheck.example/trace" ||
		rotation.IPCheckTimeout != 5*time.Second || rotation.IPCheckInterval != time.Second || rotation.RetryBackoffMax != 4*time.Minute {
		t.Fatalf("rotation = %+v", rotation)
	}
	if rotation.RotateOnStart {
		t.Fatalf("rotate-on-start default = true")
	}
}

func TestLoadRuntimeRotationDefaults(t *testing.T) {
	content := strings.Replace(validRuntimeConfig, rotationBlock, "", 1)
	cfg, err := LoadRuntime(writeRuntimeConfig(t, content))
	if err != nil {
		t.Fatalf("LoadRuntime() error = %v", err)
	}
	rotation := cfg.Rotation
	if rotation.MaxConcurrentFixed == nil || *rotation.MaxConcurrentFixed != 1 || rotation.MaxConcurrentPercent != nil {
		t.Fatalf("max-concurrent default = fixed %v percent %v", rotation.MaxConcurrentFixed, rotation.MaxConcurrentPercent)
	}
	if rotation.DrainTimeout != DefaultDrainTimeout || rotation.IPCheckURL != DefaultIPCheckURL ||
		rotation.IPCheckTimeout != DefaultIPCheckTimeout || rotation.IPCheckInterval != DefaultIPCheckInterval ||
		rotation.RetryBackoffMax != DefaultRetryBackoffMax || rotation.RotateOnStart {
		t.Fatalf("rotation defaults = %+v", rotation)
	}
}

func TestLoadRuntimeParsesPercentAndRotateOnStart(t *testing.T) {
	content := strings.Replace(validRuntimeConfig,
		"  max-concurrent: 1\n",
		"  max-concurrent: 25%\n  rotate-on-start: true\n", 1)
	cfg, err := LoadRuntime(writeRuntimeConfig(t, content))
	if err != nil {
		t.Fatalf("LoadRuntime() error = %v", err)
	}
	if cfg.Rotation.MaxConcurrentFixed != nil || cfg.Rotation.MaxConcurrentPercent == nil || *cfg.Rotation.MaxConcurrentPercent != 25 {
		t.Fatalf("max-concurrent = fixed %v percent %v", cfg.Rotation.MaxConcurrentFixed, cfg.Rotation.MaxConcurrentPercent)
	}
	if !cfg.Rotation.RotateOnStart {
		t.Fatalf("rotate-on-start = false, want true")
	}
}

func TestResolveMaxConcurrent(t *testing.T) {
	one, two, ten := 1, 2, 10
	pct25, pct50, pct100 := 25, 50, 100
	for _, tc := range []struct {
		name     string
		settings RotationSettings
		n        int
		want     int
	}{
		{"nothing to rotate", RotationSettings{MaxConcurrentFixed: &one}, 0, 0},
		{"fixed under pool", RotationSettings{MaxConcurrentFixed: &two}, 5, 2},
		{"fixed clamped to pool", RotationSettings{MaxConcurrentFixed: &ten}, 3, 3},
		{"percent rounds up", RotationSettings{MaxConcurrentPercent: &pct25}, 3, 1},
		{"percent half rounds up", RotationSettings{MaxConcurrentPercent: &pct50}, 5, 3},
		{"percent full", RotationSettings{MaxConcurrentPercent: &pct100}, 4, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.settings.ResolveMaxConcurrent(tc.n); got != tc.want {
				t.Fatalf("ResolveMaxConcurrent(%d) = %d, want %d", tc.n, got, tc.want)
			}
		})
	}
}

func TestLoadRuntimeRejectsInvalidRotationSettings(t *testing.T) {
	for _, tc := range []struct {
		name, old, replacement, want string
	}{
		{"zero fixed", "  max-concurrent: 1\n", "  max-concurrent: 0\n", "rotation.max-concurrent must be >= 1"},
		{"float", "  max-concurrent: 1\n", "  max-concurrent: 1.5\n", "must be a count or a percent"},
		{"percent over 100", "  max-concurrent: 1\n", "  max-concurrent: 150%\n", "between 1 and 100"},
		{"percent zero", "  max-concurrent: 1\n", "  max-concurrent: 0%\n", "between 1 and 100"},
		{"bare word", "  max-concurrent: 1\n", "  max-concurrent: many\n", "must be a count or a percent"},
		{"zero drain", "  drain-timeout: 30s\n", "  drain-timeout: 0s\n", "rotation.drain-timeout must be positive"},
		{"bad duration", "  ip-check-timeout: 5s\n", "  ip-check-timeout: bogus\n", "rotation.ip-check-timeout must be a Go duration"},
		{"interval over timeout", "  ip-check-interval: 1s\n", "  ip-check-interval: 30s\n", "must not exceed"},
		{"negative backoff", "  retry-backoff-max: 4m\n", "  retry-backoff-max: -1s\n", "rotation.retry-backoff-max must be positive"},
		{"plaintext check url", "  ip-check-url: https://ipcheck.example/trace\n", "  ip-check-url: http://ipcheck.example/trace\n", "rotation.ip-check-url must use https"},
		{"relative check url", "  ip-check-url: https://ipcheck.example/trace\n", "  ip-check-url: /trace\n", "rotation.ip-check-url must be an absolute URL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := strings.Replace(validRuntimeConfig, tc.old, tc.replacement, 1)
			_, err := LoadRuntime(writeRuntimeConfig(t, content))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			assertNoSecretLeak(t, err)
		})
	}
}

func TestLoadRuntimeStrictAndCredentialSafe(t *testing.T) {
	for _, tc := range []struct {
		name, mutate, want string
	}{
		{"unknown top level", "unknown: value\n", "invalid keys"},
		{"per route override", "      target-tls-insecure: false\n", "invalid keys"},
		{"legacy global block", "global:\n  target-tls-insecure: true\n", "invalid keys"},
		{"invalid kind", "      kind: ipv4\n", "kind must be exactly v4 or v6"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := validRuntimeConfig
			switch tc.name {
			case "invalid kind":
				content = strings.Replace(content, "      kind: v4\n", tc.mutate, 1)
			case "per route override":
				content = strings.Replace(content, "      kind: v4\n", "      kind: v4\n"+tc.mutate, 1)
			default:
				content += tc.mutate
			}
			_, err := LoadRuntime(writeRuntimeConfig(t, content))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			assertNoSecretLeak(t, err)
		})
	}
}

func TestLoadRuntimeDurationErrorsDoNotLeakYAMLValue(t *testing.T) {
	content := strings.Replace(validRuntimeConfig, "dial-timeout: 7s", "dial-timeout: secret-duration", 1)
	_, err := LoadRuntime(writeRuntimeConfig(t, content))
	if err == nil || !strings.Contains(err.Error(), "dial-timeout must be a Go duration") {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), "secret-duration") {
		t.Fatalf("error leaked YAML value: %v", err)
	}
}

func TestLoadRuntimeRejectsInvalidRuntimeValues(t *testing.T) {
	for _, tc := range []struct {
		name, old, replacement, want string
	}{
		{"invalid log level", "log-level: debug", "log-level: DEBUG", "log-level must be one of"},
		{"zero retries", "max-retries: 4", "max-retries: 0", "max-retries must be >= 1"},
		{"float retries", "max-retries: 4", "max-retries: 2.5", "max-retries must be a whole number"},
		{"string retries", "max-retries: 4", `max-retries: "3"`, "max-retries must be a whole number"},
		{"cooldown ordering", "  base: 2s\n  max: 1m", "  base: 2m\n  max: 1s", "must not exceed"},
		{"non-positive timeout", "dial-timeout: 7s", "dial-timeout: 0s", "dial-timeout must be positive"},
		{"nested unknown key", "  base: 2s\n  max: 1m", "  base: 2s\n  max: 1m\n  unknown: value", "invalid keys"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := strings.Replace(validRuntimeConfig, tc.old, tc.replacement, 1)
			_, err := LoadRuntime(writeRuntimeConfig(t, content))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			assertNoSecretLeak(t, err)
		})
	}
}

func TestLoadRuntimeRejectsDuplicateRegardlessOfKind(t *testing.T) {
	content := strings.Replace(validRuntimeConfig,
		"    - proxy: \"[2001:db8::1]:1080:bob:other-secret\"\n      kind: v6",
		"    - proxy: alice:secret@V4.example:1080\n      kind: v6", 1)
	_, err := LoadRuntime(writeRuntimeConfig(t, content))
	if err == nil || !strings.Contains(err.Error(), "duplicate route") {
		t.Fatalf("error = %v, want duplicate route", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("error leaked secret: %v", err)
	}
}

func TestLoadRuntimeAcceptsSingleFamilyRoutes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remove string
	}{
		{
			name:   "v4 only",
			remove: "    - proxy: \"[2001:db8::1]:1080:bob:other-secret\"\n      kind: v6\n",
		},
		{
			name:   "v6 only",
			remove: "    - proxy: alice:secret@v4.example:1080\n      kind: v4\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := strings.Replace(validRuntimeConfig, tc.remove, "", 1)
			cfg, err := LoadRuntime(writeRuntimeConfig(t, content))
			if err != nil {
				t.Fatalf("LoadRuntime() error = %v", err)
			}
			if len(cfg.Routes) != 1 {
				t.Fatalf("routes = %+v", cfg.Routes)
			}
		})
	}
}

func TestLoadRuntimeManualOnlyPoolIsValid(t *testing.T) {
	content := strings.Replace(validRuntimeConfig,
		"    - proxy: alice:secret@v4.example:1080\n      kind: v4\n    - proxy: \"[2001:db8::1]:1080:bob:other-secret\"\n      kind: v6\n", "", 1)
	cfg, err := LoadRuntime(writeRuntimeConfig(t, content))
	if err != nil {
		t.Fatalf("LoadRuntime() error = %v", err)
	}
	if len(cfg.Routes) != 0 || len(cfg.ManualRoutes) != 1 {
		t.Fatalf("routes=%d manual=%d", len(cfg.Routes), len(cfg.ManualRoutes))
	}
	if len(cfg.AllRoutes()) != 1 || cfg.AllRoutes()[0].Origin != RouteOriginManual {
		t.Fatalf("AllRoutes() = %+v", cfg.AllRoutes())
	}
}

func TestLoadRuntimeRejectsEmptyPools(t *testing.T) {
	content := strings.Replace(validRuntimeConfig,
		"    - proxy: alice:secret@v4.example:1080\n      kind: v4\n    - proxy: \"[2001:db8::1]:1080:bob:other-secret\"\n      kind: v6\n  manual:\n    - proxy: carol:manual-secret@manual.example:1080\n      kind: v6\n      rotate-interval: 90s\n      api:\n        url: https://provider.example/rotate\n        method: POST\n        headers:\n          Content-Type: application/json\n          X-Api-Token: rot-token\n        body: |\n          {\"proxy_id\": 7}\n        timeout: 4s\n", "", 1)
	_, err := LoadRuntime(writeRuntimeConfig(t, content))
	if err == nil || !strings.Contains(err.Error(), "proxies must contain at least one route") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadRuntimeRejectsInvalidManualRoutes(t *testing.T) {
	for _, tc := range []struct {
		name, old, replacement, want string
	}{
		{"missing rotate-interval", "      rotate-interval: 90s\n", "", "rotate-interval is required"},
		{"zero rotate-interval", "      rotate-interval: 90s\n", "      rotate-interval: 0s\n", "rotate-interval must be positive"},
		{"bad rotate-interval", "      rotate-interval: 90s\n", "      rotate-interval: sometimes\n", "rotate-interval must be a Go duration"},
		{"missing api url", "        url: https://provider.example/rotate\n", "", "api.url is required"},
		{"relative api url", "        url: https://provider.example/rotate\n", "        url: /rotate\n", "api.url must be an absolute http or https URL"},
		{"bad method", "        method: POST\n", "        method: BAD METHOD\n", "api.method must be a valid HTTP method token"},
		{"zero api timeout", "        timeout: 4s\n", "        timeout: 0s\n", "api.timeout must be positive"},
		{"invalid header name", "          Content-Type: application/json\n", "          Content Type: application/json\n", "api.headers contains an invalid header name"},
		{"unknown manual field", "      rotate-interval: 90s\n", "      rotate-interval: 90s\n      interval: 90\n", "invalid keys"},
		{"missing kind", "      kind: v6\n      rotate-interval: 90s\n", "      rotate-interval: 90s\n", "kind must be exactly v4 or v6"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := strings.Replace(validRuntimeConfig, tc.old, tc.replacement, 1)
			_, err := LoadRuntime(writeRuntimeConfig(t, content))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			assertNoSecretLeak(t, err)
		})
	}
}

func TestLoadRuntimeRejectsDuplicateAcrossPools(t *testing.T) {
	// Same endpoint identity as the first auto route; a different claimed kind
	// must not rescue it.
	content := strings.Replace(validRuntimeConfig,
		"    - proxy: carol:manual-secret@manual.example:1080\n      kind: v6\n",
		"    - proxy: alice:secret@V4.example:1080\n      kind: v4\n", 1)
	_, err := LoadRuntime(writeRuntimeConfig(t, content))
	if err == nil || !strings.Contains(err.Error(), "duplicate route") {
		t.Fatalf("error = %v, want duplicate route", err)
	}
	assertNoSecretLeak(t, err)
}

func TestLoadBootstrapDefaultsAndConflicts(t *testing.T) {
	for _, key := range []string{"CONFIG_FILE", "ADMIN_ADDR"} {
		t.Setenv(key, "")
	}
	t.Setenv("MIXED_LISTEN_ADDR", DefaultMixedListenAddr)
	t.Setenv("V4_LISTEN_ADDR", DefaultV4ListenAddr)
	t.Setenv("V6_LISTEN_ADDR", DefaultV6ListenAddr)
	cfg, err := LoadBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AdminAddr != DefaultRuntimeAdminAddr || cfg.MixedListenAddr != DefaultMixedListenAddr || cfg.V4ListenAddr != DefaultV4ListenAddr || cfg.V6ListenAddr != DefaultV6ListenAddr {
		t.Fatalf("bootstrap defaults = %+v", cfg)
	}

	for _, tc := range []struct {
		name string
		set  map[string]string
		want string
	}{
		{
			name: "wildcard overlap",
			set:  map[string]string{"V4_LISTEN_ADDR": ":30121"},
			want: "must not overlap",
		},
		{
			name: "specific overlaps wildcard",
			set:  map[string]string{"V4_LISTEN_ADDR": "127.0.0.1:30121"},
			want: "must not overlap",
		},
		{
			name: "invalid host",
			set:  map[string]string{"ADMIN_ADDR": "bad host!:30120"},
			want: "invalid host",
		},
		{
			name: "no proxy listeners",
			set: map[string]string{
				"MIXED_LISTEN_ADDR": "",
				"V4_LISTEN_ADDR":    "",
				"V6_LISTEN_ADDR":    "",
			},
			want: "at least one proxy listener",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for key, value := range tc.set {
				t.Setenv(key, value)
			}
			_, err := LoadBootstrap()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestValidListenerHostname(t *testing.T) {
	for _, host := range []string{"proxy.example", "localhost", "localhost-1", "127.0.0.1"} {
		if host != "127.0.0.1" && !validListenerHostname(host) {
			t.Errorf("validListenerHostname(%q) = false", host)
		}
	}
	for _, host := range []string{"", ".example", "example.", "bad host", "-bad.example", "bad-.example"} {
		if validListenerHostname(host) {
			t.Errorf("validListenerHostname(%q) = true", host)
		}
	}
}

// The atomic generation store lives in internal/pool (which already imports
// this package); its nil-rejection, publication, and in-flight snapshot
// behavior is covered by internal/pool/generation_test.go.
