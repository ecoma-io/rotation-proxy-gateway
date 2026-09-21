package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/logging"
	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/proxyserver"

	"github.com/rs/zerolog"
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
	// Warn level on the logger itself keeps the capture hermetic even though
	// the reload loop mutates the process-global level in production.
	log := logging.New(&buf).Level(zerolog.WarnLevel)
	warnUnavailableKindListeners(log, cfg, bootstrap)
	return buf.String()
}

// warnUnavailableListenerMsg is the fixed message of the
// warnUnavailableKindListeners records; the listener name rides in a field.
const warnUnavailableListenerMsg = "listener has no eligible routes; replying a general SOCKS failure"

func TestWarnUnavailableKindListeners(t *testing.T) {
	v4only := warnTestConfig(t, config.EgressV4)
	out := captureWarnOutput(t, v4only, warnTestBootstrap(":30122", ":30123"))
	if !findWarnListener(out, "v6") {
		t.Fatalf("v4-only pool did not warn for v6 listener:\n%s", out)
	}
	if findWarnListener(out, "v4") {
		t.Fatalf("v4-only pool warned for v4 listener:\n%s", out)
	}

	v6only := warnTestConfig(t, config.EgressV6)
	out = captureWarnOutput(t, v6only, warnTestBootstrap(":30122", ":30123"))
	if !findWarnListener(out, "v4") {
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

func TestDefaultShutdownGrace(t *testing.T) {
	if config.DefaultShutdownGrace != 55*time.Second {
		t.Fatalf("DefaultShutdownGrace = %s, want 55s", config.DefaultShutdownGrace)
	}
	t.Setenv("SHUTDOWN_GRACE", "") // neutralize the environment
	cfg, err := config.LoadBootstrap()
	if err != nil {
		t.Fatalf("LoadBootstrap: %v", err)
	}
	if cfg.ShutdownGrace != config.DefaultShutdownGrace {
		t.Fatalf("default ShutdownGrace = %s, want %s", cfg.ShutdownGrace, config.DefaultShutdownGrace)
	}
}

func TestBootstrapShutdownGraceEnv(t *testing.T) {
	t.Run("override", func(t *testing.T) {
		t.Setenv("SHUTDOWN_GRACE", "2s")
		cfg, err := config.LoadBootstrap()
		if err != nil {
			t.Fatalf("LoadBootstrap: %v", err)
		}
		if cfg.ShutdownGrace != 2*time.Second {
			t.Fatalf("ShutdownGrace = %s, want 2s", cfg.ShutdownGrace)
		}
	})
	t.Run("not a duration", func(t *testing.T) {
		t.Setenv("SHUTDOWN_GRACE", "soon")
		if _, err := config.LoadBootstrap(); err == nil || !strings.Contains(err.Error(), "must be a Go duration") {
			t.Fatalf("err = %v, want a Go-duration error", err)
		}
	})
	t.Run("not positive", func(t *testing.T) {
		t.Setenv("SHUTDOWN_GRACE", "0s")
		if _, err := config.LoadBootstrap(); err == nil || !strings.Contains(err.Error(), "must be positive") {
			t.Fatalf("err = %v, want a positivity error", err)
		}
	})
}

// findWarnListener reports whether output carries a
// warnUnavailableKindListeners record for the named listener.
func findWarnListener(output, listener string) bool {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec struct {
			Msg      string `json:"msg"`
			Listener string `json:"listener"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec.Msg == warnUnavailableListenerMsg && rec.Listener == listener {
			return true
		}
	}
	return false
}

func newTestLogger() zerolog.Logger {
	// Discard everything: pre-greeting conns killed by the shutdown tests log
	// at debug, and dropped tunnels at warn.
	return zerolog.Nop()
}

// newTestStore builds a pool store with no routes: the shutdown tests exercise
// listener lifecycle only, never a route pick.
func newTestStore() *pool.Store {
	runtime := &config.RuntimeConfig{
		MaxRetries:   1,
		DialTimeout:  time.Second,
		CooldownBase: time.Second,
		CooldownMax:  time.Minute,
	}
	return pool.NewStore(runtime, pool.NewRoutes(nil, time.Second, time.Minute))
}

// awaitReachable dials the listener until the address accepts TCP connections,
// so tests never race their first request against Serve starting up.
func awaitReachable(t *testing.T, ln net.Listener) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("listener %s never became reachable: %v", ln.Addr(), err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// serveSocksListener binds an ephemeral loopback address, serves the SOCKS
// server on it, and waits until the address accepts TCP dials. Cleanup closes
// the listener, which makes Serve return.
func serveSocksListener(t *testing.T, srv *proxyserver.Server) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }() // Serve returns nil once shutdown closes ln
	t.Cleanup(func() { _ = ln.Close() })
	awaitReachable(t, ln)
	return ln
}

// serveAdminListener is the admin counterpart: the admin listener stays a
// plain *http.Server rather than a proxyserver.Server.
func serveAdminListener(t *testing.T, handler http.Handler) (net.Listener, *http.Server) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln) //nolint:errcheck // shutdownAll and cleanup stop the server
	t.Cleanup(func() { _ = srv.Close() })
	awaitReachable(t, ln)
	return ln, srv
}

// parkConn dials the listener and writes nothing, so the accepted session sits
// in its SOCKS greeting read until the server force-closes the conn or the 30s
// handshake deadline expires — a session that can never finish on its own.
func parkConn(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// assertForceClosed reads on a client conn the server should have force-closed:
// the read must fail promptly and must not merely time out.
func assertForceClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := conn.Read(make([]byte, 1))
	switch {
	case err == nil:
		t.Fatalf("conn to %s is still open after shutdownAll: read returned data", conn.RemoteAddr())
	case errors.Is(err, os.ErrDeadlineExceeded):
		t.Fatalf("conn to %s is still open 5s after shutdownAll", conn.RemoteAddr())
	}
}

func TestShutdownAllClosesProxyListenersThenAdmin(t *testing.T) {
	log := newTestLogger()
	store := newTestStore()
	srvA := proxyserver.NewRuntime(store, log, "test", "mixed", config.EgressV4, config.EgressV6)
	srvB := proxyserver.NewRuntime(store, log, "test", "v4", config.EgressV4)

	lnA := serveSocksListener(t, srvA)
	lnB := serveSocksListener(t, srvB)
	lnAdmin, adminSrv := serveAdminListener(t, proxyserver.AdminMux("test", time.Now(), store, map[string]*proxyserver.Server{"mixed": srvA}, nil, nil))

	listeners := []runningListener{
		{name: "mixed", server: srvA, ln: lnA},
		{name: "v4", server: srvB, ln: lnB},
	}

	done := make(chan struct{})
	go func() {
		shutdownAll(logging.Nop(), func() {}, func() {}, listeners, adminSrv, 5*time.Second)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdownAll on a process with no live sessions did not return within 2s, well under the 5s grace")
	}

	// Each listener was bound to an ephemeral port; after shutdownAll the
	// sockets are closed so redialing must fail.
	for _, ln := range []net.Listener{lnA, lnB, lnAdmin} {
		if conn, err := net.DialTimeout("tcp", ln.Addr().String(), 200*time.Millisecond); err == nil {
			_ = conn.Close()
			t.Fatalf("listener %s still reachable after shutdownAll", ln.Addr())
		}
	}
}

// shutdownAll must bound the whole drain with the single shared grace budget,
// not hand each listener its own window: with every proxy listener holding a
// client conn parked before its SOCKS greeting — a session that never finishes
// on its own — total shutdown time stays near one budget.
//
// Liveness discipline: the parked conns get a fixed 250ms beat to be accepted
// before shutdownAll starts, instead of polling "Shutdown has not returned
// yet" on a goroutine. Both disciplines lose the same race — a conn accepted
// too late means the drain finds no live session — but the beat keeps the
// elapsed measurement and its bounds in one place, and loopback accepts land
// microseconds after the dial, orders of magnitude below the beat. The
// lower-bound assertion below still fails on a too-early return, so the beat
// cannot turn a regression into a false pass.
func TestShutdownAllSharedBudget(t *testing.T) {
	log := newTestLogger()
	store := newTestStore()
	srvA := proxyserver.NewRuntime(store, log, "test", "mixed", config.EgressV4, config.EgressV6)
	srvB := proxyserver.NewRuntime(store, log, "test", "v4", config.EgressV4)
	lnA := serveSocksListener(t, srvA)
	lnB := serveSocksListener(t, srvB)
	lnAdmin, adminSrv := serveAdminListener(t, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	listeners := []runningListener{
		{name: "mixed", server: srvA, ln: lnA},
		{name: "v4", server: srvB, ln: lnB},
	}

	parkedA := parkConn(t, lnA.Addr().String())
	parkedB := parkConn(t, lnB.Addr().String())
	// One beat for both accept loops to start the parked sessions.
	time.Sleep(250 * time.Millisecond)

	const grace = 500 * time.Millisecond
	start := time.Now()
	done := make(chan struct{})
	go func() {
		shutdownAll(logging.Nop(), func() {}, func() {}, listeners, adminSrv, grace)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdownAll did not return within 5s")
	}
	elapsed := time.Since(start)

	// The parked sessions can never finish, so shutdownAll must wait out the
	// budget before force-closing them.
	if elapsed < grace-100*time.Millisecond {
		t.Fatalf("shutdownAll returned after %s, want at least the %s budget (it must bound the drain)", elapsed, grace)
	}
	// One budget for all listeners: a per-listener window would push two proxy
	// listeners to ~2x grace.
	if elapsed >= 2*grace-100*time.Millisecond {
		t.Fatalf("shutdownAll took %s, want within one shared %s budget, not one window per listener", elapsed, grace)
	}

	// The expired budget force-closed the parked client conns ...
	assertForceClosed(t, parkedA)
	assertForceClosed(t, parkedB)

	// ... and every listener socket refuses new dials.
	for _, ln := range []net.Listener{lnA, lnB, lnAdmin} {
		if conn, err := net.DialTimeout("tcp", ln.Addr().String(), 200*time.Millisecond); err == nil {
			_ = conn.Close()
			t.Fatalf("listener %s still reachable after shutdownAll", ln.Addr())
		}
	}
}

// A quiesced process must not wait out the budget: once the only session has
// ended — the parked client closed its own conn, so the greeting read failed and
// the server untracked the session — shutdownAll returns at once even with a
// generous grace.
func TestShutdownAllDrainsCompletedSessionsImmediately(t *testing.T) {
	log := newTestLogger()
	store := newTestStore()
	srv := proxyserver.NewRuntime(store, log, "test", "mixed", config.EgressV4, config.EgressV6)
	ln := serveSocksListener(t, srv)
	_, adminSrv := serveAdminListener(t, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))

	parked := parkConn(t, ln.Addr().String())
	// One beat so the server really accepted the conn and the session went
	// live; closing it then fails the greeting read and ends the session. If
	// the beat is missed, the conn is accepted as already closed and ends the
	// same way, so the assertions below hold either way.
	time.Sleep(100 * time.Millisecond)
	_ = parked.Close()

	listeners := []runningListener{{name: "mixed", server: srv, ln: ln}}
	done := make(chan struct{})
	go func() {
		shutdownAll(logging.Nop(), func() {}, func() {}, listeners, adminSrv, 5*time.Second)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdownAll did not return within 1s although the only session had already ended (grace 5s)")
	}
}

func TestParseZerologLevel(t *testing.T) {
	cases := []struct {
		level string
		want  zerolog.Level
	}{
		{level: "debug", want: zerolog.DebugLevel},
		{level: "info", want: zerolog.InfoLevel},
		{level: "warn", want: zerolog.WarnLevel},
		{level: "error", want: zerolog.ErrorLevel},
		{level: "", want: zerolog.InfoLevel},
		{level: "nonsense", want: zerolog.InfoLevel},
	}
	for _, tc := range cases {
		t.Run(tc.level, func(t *testing.T) {
			if got := parseZerologLevel(tc.level); got != tc.want {
				t.Errorf("parseZerologLevel(%q) = %v, want %v", tc.level, got, tc.want)
			}
		})
	}
}
