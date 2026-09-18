package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/proxyserver"
)

func TestHealthcheckURL(t *testing.T) {
	cases := []struct {
		name string
		addr string
		want string
	}{
		{name: "empty host defaults to loopback", addr: ":30120", want: "http://127.0.0.1:30120/healthz"},
		{name: "IPv4 wildcard defaults to loopback", addr: "0.0.0.0:30120", want: "http://127.0.0.1:30120/healthz"},
		{name: "IPv6 wildcard defaults to loopback", addr: "[::]:30120", want: "http://[::1]:30120/healthz"},
		{name: "loopback host", addr: "127.0.0.1:30120", want: "http://127.0.0.1:30120/healthz"},
		{name: "ipv6 loopback", addr: "[::1]:30120", want: "http://[::1]:30120/healthz"},
		{name: "named host with port passes through", addr: "localhost:30120", want: "http://localhost:30120/healthz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := healthcheckURL(tc.addr); got != tc.want {
				t.Fatalf("healthcheckURL(%q) = %q, want %q", tc.addr, got, tc.want)
			}
		})
	}
}

// isolateHealthcheckEnv neutralizes ambient bootstrap config so healthcheck()
// only sees the values set by the test. It leaves one proxy listener enabled
// because bootstrap validation requires it.
func isolateHealthcheckEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"CONFIG_FILE", "ADMIN_ADDR", "MIXED_LISTEN_ADDR", "V4_LISTEN_ADDR", "V6_LISTEN_ADDR",
	} {
		t.Setenv(k, "")
	}
	t.Setenv("MIXED_LISTEN_ADDR", ":30121")
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

func TestHealthcheckURLRejectsMalformed(t *testing.T) {
	for _, addr := range []string{"", "not-an-addr", "127.0.0.1"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("healthcheckURL(%q) did not panic", addr)
				}
			}()
			healthcheckURL(addr)
		}()
	}
}

func TestHealthcheckInvalidBootstrapFails(t *testing.T) {
	isolateHealthcheckEnv(t)
	t.Setenv("ADMIN_ADDR", "bad host!:30120")
	if got := healthcheck(); got != 1 {
		t.Fatalf("healthcheck() = %d, want 1 for invalid bootstrap", got)
	}
}

func warnTestConfig(t *testing.T, kinds ...config.EgressKind) *config.RuntimeConfig {
	t.Helper()
	cfg := &config.RuntimeConfig{}
	for i, kind := range kinds {
		u, err := url.Parse("socks5://route.test:1080")
		if err != nil {
			t.Fatal(err)
		}
		// Distinct hosts per route so CanonicalRouteID never collides.
		u.Host = "route" + string(rune('a'+i)) + ".test:1080"
		cfg.Routes = append(cfg.Routes, config.RouteSpec{URL: u, Kind: kind})
	}
	return cfg
}

func warnTestBootstrap(v4, v6 string) *config.BootstrapConfig {
	return &config.BootstrapConfig{
		ConfigFile:      "ignored.yaml",
		AdminAddr:       "127.0.0.1:30120",
		MixedListenAddr: ":30121",
		V4ListenAddr:    v4,
		V6ListenAddr:    v6,
	}
}

func captureWarnOutput(t *testing.T, cfg *config.RuntimeConfig, bootstrap *config.BootstrapConfig) string {
	t.Helper()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	warnUnavailableKindListeners(log, cfg, bootstrap)
	return buf.String()
}

func TestWarnUnavailableKindListeners(t *testing.T) {
	v4only := warnTestConfig(t, config.EgressV4)
	out := captureWarnOutput(t, v4only, warnTestBootstrap(":30122", ":30123"))
	if !strings.Contains(out, "listener=v6") {
		t.Fatalf("v4-only pool did not warn for v6 listener:\n%s", out)
	}
	if strings.Contains(out, "listener=v4") {
		t.Fatalf("v4-only pool warned for v4 listener:\n%s", out)
	}

	v6only := warnTestConfig(t, config.EgressV6)
	out = captureWarnOutput(t, v6only, warnTestBootstrap(":30122", ":30123"))
	if !strings.Contains(out, "listener=v4") {
		t.Fatalf("v6-only pool did not warn for v4 listener:\n%s", out)
	}

	both := warnTestConfig(t, config.EgressV4, config.EgressV6)
	if out := captureWarnOutput(t, both, warnTestBootstrap(":30122", ":30123")); out != "" {
		t.Fatalf("mixed pool warned unexpectedly:\n%s", out)
	}

	// A disabled dedicated listener never warns, even with no matching route.
	if out := captureWarnOutput(t, v4only, warnTestBootstrap(":30122", "")); out != "" {
		t.Fatalf("disabled v6 listener warned unexpectedly:\n%s", out)
	}
}

func TestShutdownGraceIsPerListenerTenSeconds(t *testing.T) {
	if shutdownGrace != 10*time.Second {
		t.Fatalf("shutdownGrace = %s, want 10s per enabled listener plus admin", shutdownGrace)
	}
}

func serveTestListener(t *testing.T, handler http.Handler) (net.Listener, *http.Server) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln)                  //nolint:errcheck // shutdownAll stops the server
	t.Cleanup(func() { srv.Close() }) //nolint:errcheck // best-effort
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return ln, srv
		}
		if time.Now().After(deadline) {
			t.Fatalf("test server %s never became reachable: %v", ln.Addr(), err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestShutdownAllClosesProxyListenersThenAdmin(t *testing.T) {
	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelError}))
	runtime := &config.RuntimeConfig{
		MaxRetries:    1,
		DialTimeout:   time.Second,
		MaxBodyBuffer: 1 << 20,
		CooldownBase:  time.Second,
		CooldownMax:   time.Minute,
	}
	store := pool.NewStore(runtime, pool.NewRoutes(nil, time.Second, time.Minute))
	srvA := proxyserver.NewRuntime(store, log, "test", "mixed", config.EgressV4, config.EgressV6)
	srvB := proxyserver.NewRuntime(store, log, "test", "v4", config.EgressV4)

	lnA, httpA := serveTestListener(t, srvA)
	lnB, httpB := serveTestListener(t, srvB)
	lnAdmin, adminSrv := serveTestListener(t, proxyserver.AdminMux("test", time.Now(), store, map[string]*proxyserver.Server{"mixed": srvA}))

	listeners := []runningListener{
		{name: "mixed", server: srvA, http: httpA},
		{name: "v4", server: srvB, http: httpB},
	}

	done := make(chan struct{})
	go func() {
		shutdownAll(listeners, adminSrv)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("shutdownAll did not return within 15s")
	}

	// Each server was bound to an ephemeral port; after shutdown the listener
	// address is closed so redialing must fail.
	for _, ln := range []net.Listener{lnA, lnB, lnAdmin} {
		if conn, err := net.DialTimeout("tcp", ln.Addr().String(), 200*time.Millisecond); err == nil {
			conn.Close()
			t.Fatalf("server %s still reachable after shutdownAll", ln.Addr())
		}
	}
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
