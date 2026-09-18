package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

func runtimeBootstrap(t *testing.T) *BootstrapConfig {
	t.Helper()
	return &BootstrapConfig{
		ConfigFile:      "ignored.yaml",
		AdminAddr:       "127.0.0.1:30120",
		MixedListenAddr: ":30121",
		V4ListenAddr:    ":30122",
		V6ListenAddr:    ":30123",
	}
}

func writeRuntimeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const validRuntimeConfig = `
log-level: debug
max-retries: 4
cooldown:
  base: 2s
  max: 1m
dial-timeout: 7s
global:
  target-tls-insecure: true
  max-body-buffer: 42
proxies:
  auto:
    - proxy: socks5://alice:secret@v4.example:1080
      kind: v4
    - proxy: "[2001:db8::1]:1080:bob:other-secret"
      kind: v6
  manual:
    - api:
        url: https://future.example/rotate
`

func TestLoadRuntimeMissingFileReportsSetupGuidance(t *testing.T) {
	_, err := LoadRuntime(filepath.Join(t.TempDir(), "missing.yaml"), runtimeBootstrap(t))
	if err == nil || !strings.Contains(err.Error(), "copy config.example.yaml") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadRuntimeValidAndManualIgnored(t *testing.T) {
	cfg, err := LoadRuntime(writeRuntimeConfig(t, validRuntimeConfig), runtimeBootstrap(t))
	if err != nil {
		t.Fatalf("LoadRuntime() error = %v", err)
	}
	if cfg.MaxRetries != 4 || cfg.CooldownBase != 2*time.Second || cfg.CooldownMax != time.Minute || cfg.DialTimeout != 7*time.Second || !cfg.TargetTLSInsecure || cfg.MaxBodyBuffer != 42 || cfg.LogLevel != "debug" {
		t.Fatalf("unexpected runtime config: %+v", cfg)
	}
	if len(cfg.Routes) != 2 || cfg.Routes[0].Kind != EgressV4 || cfg.Routes[1].Kind != EgressV6 {
		t.Fatalf("routes = %+v", cfg.Routes)
	}
	if got := cfg.Routes[0].URL.Host; got != "v4.example:1080" {
		t.Fatalf("v4 route host = %q", got)
	}
}

func TestLoadRuntimeStrictAndCredentialSafe(t *testing.T) {
	for _, tc := range []struct {
		name, mutate, want string
	}{
		{"unknown top level", "unknown: value\n", "invalid keys"},
		{"per route override", "      target-tls-insecure: false\n", "invalid keys"},
		{"invalid kind", "      kind: ipv4\n", "kind must be exactly v4 or v6"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := validRuntimeConfig
			if tc.name == "invalid kind" {
				content = strings.Replace(content, "      kind: v4\n", tc.mutate, 1)
			} else if tc.name == "per route override" {
				content = strings.Replace(content, "      kind: v4\n", "      kind: v4\n"+tc.mutate, 1)
			} else {
				content += tc.mutate
			}
			_, err := LoadRuntime(writeRuntimeConfig(t, content), runtimeBootstrap(t))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			for _, secret := range []string{"secret", "other-secret"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaked %q: %v", secret, err)
				}
			}
		})
	}
}

func TestLoadRuntimeDurationErrorsDoNotLeakYAMLValue(t *testing.T) {
	content := strings.Replace(validRuntimeConfig, "dial-timeout: 7s", "dial-timeout: secret-duration", 1)
	_, err := LoadRuntime(writeRuntimeConfig(t, content), runtimeBootstrap(t))
	if err == nil || !strings.Contains(err.Error(), "dial-timeout must be a Go duration") {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), "secret-duration") {
		t.Fatalf("error leaked YAML value: %v", err)
	}
}

func TestLoadRuntimeRejectsDuplicateRegardlessOfKind(t *testing.T) {
	content := strings.Replace(validRuntimeConfig,
		"    - proxy: \"[2001:db8::1]:1080:bob:other-secret\"\n      kind: v6",
		"    - proxy: socks5://alice:secret@V4.example:1080\n      kind: v6", 1)
	_, err := LoadRuntime(writeRuntimeConfig(t, content), runtimeBootstrap(t))
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
			remove: "    - proxy: socks5://alice:secret@v4.example:1080\n      kind: v4\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := strings.Replace(validRuntimeConfig, tc.remove, "", 1)
			cfg, err := LoadRuntime(writeRuntimeConfig(t, content), runtimeBootstrap(t))
			if err != nil {
				t.Fatalf("LoadRuntime() error = %v", err)
			}
			if len(cfg.Routes) != 1 {
				t.Fatalf("routes = %+v", cfg.Routes)
			}
		})
	}
}

func TestLoadRuntimeRejectsEmptyAutoRoutes(t *testing.T) {
	content := strings.Replace(validRuntimeConfig,
		"    - proxy: socks5://alice:secret@v4.example:1080\n      kind: v4\n    - proxy: \"[2001:db8::1]:1080:bob:other-secret\"\n      kind: v6\n", "", 1)
	_, err := LoadRuntime(writeRuntimeConfig(t, content), runtimeBootstrap(t))
	if err == nil || !strings.Contains(err.Error(), "proxies.auto must contain at least one route") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadRuntimeAllowsMissingKindWhenListenerDisabled(t *testing.T) {
	content := strings.Replace(validRuntimeConfig,
		"    - proxy: \"[2001:db8::1]:1080:bob:other-secret\"\n      kind: v6\n", "", 1)
	bootstrap := runtimeBootstrap(t)
	bootstrap.V6ListenAddr = ""
	if _, err := LoadRuntime(writeRuntimeConfig(t, content), bootstrap); err != nil {
		t.Fatalf("disabled v6 LoadRuntime() error = %v", err)
	}
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

func TestRuntimeStoreRejectsNilSnapshot(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewStore(nil) did not panic")
		}
	}()
	NewStore(nil)
}

func TestRuntimeStorePublishesSnapshots(t *testing.T) {
	initial := &RuntimeConfig{MaxRetries: 1}
	store := NewStore(initial)
	if got := store.Load(); got != initial {
		t.Fatal("store did not load initial snapshot")
	}
	next := &RuntimeConfig{MaxRetries: 2}
	store.Store(next)
	if got := store.Load(); got != next {
		t.Fatal("store did not publish new snapshot")
	}
}

func TestWatchRuntimeReportsFileChange(t *testing.T) {
	path := writeRuntimeConfig(t, validRuntimeConfig)
	events := make(chan struct{}, 1)
	watcher, err := WatchRuntime(path, func(_ fsnotify.Event) {
		select {
		case events <- struct{}{}:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = watcher // Its lifetime must cover the write below.
	if err := os.WriteFile(path, []byte(strings.Replace(validRuntimeConfig, "max-retries: 4", "max-retries: 5", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-events:
	case <-time.After(2 * time.Second):
		t.Fatal("runtime watcher did not report a file change")
	}
}
