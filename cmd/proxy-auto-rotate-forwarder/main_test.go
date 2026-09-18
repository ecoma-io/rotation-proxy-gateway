package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestHealthcheckURL(t *testing.T) {
	cases := []struct {
		name string
		addr string
		want string
	}{
		{name: "empty host defaults to loopback", addr: ":8081", want: "http://127.0.0.1:8081/healthz"},
		{name: "IPv4 wildcard defaults to loopback", addr: "0.0.0.0:8081", want: "http://127.0.0.1:8081/healthz"},
		{name: "IPv6 wildcard defaults to loopback", addr: "[::]:8081", want: "http://[::1]:8081/healthz"},
		{name: "loopback host", addr: "127.0.0.1:8081", want: "http://127.0.0.1:8081/healthz"},
		{name: "ipv6 loopback", addr: "[::1]:8081", want: "http://[::1]:8081/healthz"},
		{name: "named host with port passes through", addr: "localhost:8081", want: "http://localhost:8081/healthz"},
		// Current fallback: SplitHostPort failure keeps the whole input as
		// host with an empty port, producing a trailing colon.
		{name: "host-only keeps current trailing-colon form", addr: "example.com", want: "http://example.com:/healthz"},
		{name: "malformed keeps current trailing-colon form", addr: "not-an-addr", want: "http://not-an-addr:/healthz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := healthcheckURL(tc.addr); got != tc.want {
				t.Fatalf("healthcheckURL(%q) = %q, want %q", tc.addr, got, tc.want)
			}
		})
	}
}

// isolateHealthcheckEnv neutralizes ambient deployment config so healthcheck()
// only sees the values set by the test. Empty values are treated as unset by
// config.Load.
func isolateHealthcheckEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"LISTEN_ADDR", "ADMIN_ADDR", "PROXIES_FILE", "LOG_LEVEL",
		"MAX_RETRIES", "COOLDOWN_BASE", "COOLDOWN_MAX",
		"CONNECT_TIMEOUT", "MAX_BODY_BUFFER", "TARGET_TLS_INSECURE",
	} {
		t.Setenv(k, "")
	}
	t.Setenv("LISTEN_ADDR", ":8080")
	t.Setenv("LOG_LEVEL", "info")
}

func adminAddrFor(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	return u.Host
}

func TestHealthcheck(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		isolateHealthcheckEnv(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/healthz" {
				http.NotFound(w, r)
				return
			}
			w.Write([]byte("ok\n")) //nolint:errcheck
		}))
		defer srv.Close()
		t.Setenv("ADMIN_ADDR", adminAddrFor(t, srv))
		if got := healthcheck(); got != 0 {
			t.Fatalf("healthcheck() = %d, want 0", got)
		}
	})

	t.Run("non-200 fails", func(t *testing.T) {
		isolateHealthcheckEnv(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("ok\n")) //nolint:errcheck
		}))
		defer srv.Close()
		t.Setenv("ADMIN_ADDR", adminAddrFor(t, srv))
		if got := healthcheck(); got != 1 {
			t.Fatalf("healthcheck() = %d, want 1 for non-200", got)
		}
	})

	t.Run("bad body fails", func(t *testing.T) {
		isolateHealthcheckEnv(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("nope\n")) //nolint:errcheck
		}))
		defer srv.Close()
		t.Setenv("ADMIN_ADDR", adminAddrFor(t, srv))
		if got := healthcheck(); got != 1 {
			t.Fatalf("healthcheck() = %d, want 1 for bad body", got)
		}
	})

	t.Run("unreachable fails", func(t *testing.T) {
		isolateHealthcheckEnv(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		addr := adminAddrFor(t, srv)
		srv.Close()
		t.Setenv("ADMIN_ADDR", addr)
		if got := healthcheck(); got != 1 {
			t.Fatalf("healthcheck() = %d, want 1 for unreachable admin", got)
		}
	})
}

func TestSetupLoggerLevels(t *testing.T) {
	cases := []struct {
		level                  string
		debug, info, warn, err bool
	}{
		{level: "debug", debug: true, info: true, warn: true, err: true},
		{level: "info", debug: false, info: true, warn: true, err: true},
		{level: "warn", debug: false, info: false, warn: true, err: true},
		{level: "error", debug: false, info: false, warn: false, err: true},
	}
	ctx := context.Background()
	for _, tc := range cases {
		t.Run(tc.level, func(t *testing.T) {
			log := setupLogger(tc.level)
			if got := log.Enabled(ctx, slog.LevelDebug); got != tc.debug {
				t.Errorf("level %q debug enabled = %v, want %v", tc.level, got, tc.debug)
			}
			if got := log.Enabled(ctx, slog.LevelInfo); got != tc.info {
				t.Errorf("level %q info enabled = %v, want %v", tc.level, got, tc.info)
			}
			if got := log.Enabled(ctx, slog.LevelWarn); got != tc.warn {
				t.Errorf("level %q warn enabled = %v, want %v", tc.level, got, tc.warn)
			}
			if got := log.Enabled(ctx, slog.LevelError); got != tc.err {
				t.Errorf("level %q error enabled = %v, want %v", tc.level, got, tc.err)
			}
		})
	}
}
