package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/configstore"
	"rotation-proxy-gateway/internal/control"
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
		{name: "empty host defaults to loopback", addr: ":30120", want: "http://127.0.0.1:30120/readyz"},
		{name: "IPv4 wildcard defaults to loopback", addr: "0.0.0.0:30120", want: "http://127.0.0.1:30120/readyz"},
		{name: "IPv6 wildcard defaults to loopback", addr: "[::]:30120", want: "http://[::1]:30120/readyz"},
		{name: "loopback host", addr: "127.0.0.1:30120", want: "http://127.0.0.1:30120/readyz"},
		{name: "ipv6 loopback", addr: "[::1]:30120", want: "http://[::1]:30120/readyz"},
		{name: "named host with port passes through", addr: "localhost:30120", want: "http://localhost:30120/readyz"},
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
		"RPGW_CONFIG_FILE", "RPGW_ADMIN_ADDR", "RPGW_MIXED_LISTEN_ADDR", "RPGW_V4_LISTEN_ADDR", "RPGW_V6_LISTEN_ADDR",
	} {
		t.Setenv(k, "")
	}
	t.Setenv("RPGW_MIXED_LISTEN_ADDR", ":30121")
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
			// The probe targets readiness, not liveness: a 200 from /healthz
			// must not satisfy it, or a draining process would keep reporting
			// healthy until its listener closed.
			if r.URL.Path != proxyserver.ReadyPath {
				http.NotFound(w, r)
				return
			}
			w.Write([]byte(proxyserver.ReadyBody)) //nolint:errcheck
		}))
		defer srv.Close()
		t.Setenv("RPGW_ADMIN_ADDR", adminAddrFor(t, srv))
		if got := healthcheck(); got != 0 {
			t.Fatalf("healthcheck() = %d, want 0", got)
		}
	})

	t.Run("draining 503 fails", func(t *testing.T) {
		isolateHealthcheckEnv(t)
		lc := proxyserver.NewLifecycle()
		lc.MarkReady()
		srv := httptest.NewServer(proxyserver.AdminMux(proxyserver.AdminOptions{Version: "test", Started: time.Now(), Store: newTestStore(), Lifecycle: lc}))
		lc.BeginDraining()
		defer srv.Close()
		t.Setenv("RPGW_ADMIN_ADDR", adminAddrFor(t, srv))
		if got := healthcheck(); got != 1 {
			t.Fatalf("healthcheck() = %d, want 1 for a draining process", got)
		}
	})

	t.Run("liveness 200 does not satisfy the probe", func(t *testing.T) {
		// The quiet failure this guards: a process answering 200 "ok\n" on
		// /healthz for its whole life, drain window included. Probing liveness
		// would report that process as healthy for exactly as long as its
		// sockets are the wrong thing to send traffic to.
		isolateHealthcheckEnv(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/healthz" {
				http.NotFound(w, r)
				return
			}
			w.Write([]byte("ok\n")) //nolint:errcheck
		}))
		defer srv.Close()
		t.Setenv("RPGW_ADMIN_ADDR", adminAddrFor(t, srv))
		if got := healthcheck(); got != 1 {
			t.Fatalf("healthcheck() = %d, want 1: /healthz must not pass the readiness probe", got)
		}
	})

	t.Run("non-200 fails", func(t *testing.T) {
		isolateHealthcheckEnv(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("ok\n")) //nolint:errcheck
		}))
		defer srv.Close()
		t.Setenv("RPGW_ADMIN_ADDR", adminAddrFor(t, srv))
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
		t.Setenv("RPGW_ADMIN_ADDR", adminAddrFor(t, srv))
		if got := healthcheck(); got != 1 {
			t.Fatalf("healthcheck() = %d, want 1 for bad body", got)
		}
	})

	t.Run("unreachable fails", func(t *testing.T) {
		isolateHealthcheckEnv(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		addr := adminAddrFor(t, srv)
		srv.Close()
		t.Setenv("RPGW_ADMIN_ADDR", addr)
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
	t.Setenv("RPGW_ADMIN_ADDR", "bad host!:30120")
	if got := healthcheck(); got != 1 {
		t.Fatalf("healthcheck() = %d, want 1 for invalid bootstrap", got)
	}
}

// captureFileOutput swaps one os.Stdout/os.Stderr for a pipe, runs fn, and
// returns what fn wrote. The captured streams carry at most a usage line or a
// version string, far below the pipe buffer, so the read cannot block.
func captureFileOutput(t *testing.T, target **os.File, fn func()) string {
	t.Helper()
	saved := *target
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	*target = w
	defer func() { *target = saved }()
	fn()
	_ = w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// isolateServerEnv neutralizes ambient bootstrap config and points the config
// file at a guaranteed-missing path, so any dispatch that reaches the server
// path deterministically fails at config load — before any listener binds —
// and returns 1 instead of blocking the test.
func isolateServerEnv(t *testing.T) {
	t.Helper()
	isolateHealthcheckEnv(t)
	t.Setenv("RPGW_CONFIG_FILE", filepath.Join(t.TempDir(), "missing.yaml"))
}

func TestRunArgsUnknownArgumentIsUsageError(t *testing.T) {
	isolateServerEnv(t)
	for _, arg := range []string{"--help", "--version", "healthchek"} {
		t.Run(arg, func(t *testing.T) {
			var code int
			out := captureFileOutput(t, &os.Stderr, func() { code = runArgs([]string{arg}) })
			// Exit 2 proves the server path was never entered: with the
			// missing config file, a fall-through to run() would return 1
			// after starting (and failing) startup, not print usage.
			if code != 2 {
				t.Fatalf("runArgs([%q]) = %d, want 2", arg, code)
			}
			if out != usageLine {
				t.Fatalf("stderr = %q, want the usage line %q", out, usageLine)
			}
		})
	}
}

func TestRunArgsEmptyArgsEnterServerPath(t *testing.T) {
	isolateServerEnv(t)
	// With a missing config file the server path fails at LoadRuntime and
	// returns 1 — never the usage code 2 — pinning that the no-argument
	// invocation still dispatches to run() and never reaches a listener bind.
	if got := runArgs(nil); got != 1 {
		t.Fatalf("runArgs(nil) = %d, want 1 (server path failing on the missing config)", got)
	}
}

func TestRunArgsVersionPrintsAndSucceeds(t *testing.T) {
	isolateServerEnv(t)
	var code int
	out := captureFileOutput(t, &os.Stdout, func() { code = runArgs([]string{"version"}) })
	if code != 0 {
		t.Fatalf("runArgs([version]) = %d, want 0", code)
	}
	if out != version+"\n" {
		t.Fatalf("stdout = %q, want %q", out, version+"\n")
	}
}

func TestRunArgsHealthcheckKeepsExitContract(t *testing.T) {
	t.Run("healthy admin exits 0", func(t *testing.T) {
		isolateServerEnv(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != proxyserver.ReadyPath {
				http.NotFound(w, r)
				return
			}
			w.Write([]byte(proxyserver.ReadyBody)) //nolint:errcheck
		}))
		defer srv.Close()
		t.Setenv("RPGW_ADMIN_ADDR", adminAddrFor(t, srv))
		if got := runArgs([]string{"healthcheck"}); got != 0 {
			t.Fatalf("runArgs([healthcheck]) = %d, want 0", got)
		}
	})
	t.Run("unreachable admin exits 1", func(t *testing.T) {
		isolateServerEnv(t)
		srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
		addr := adminAddrFor(t, srv)
		srv.Close()
		t.Setenv("RPGW_ADMIN_ADDR", addr)
		if got := runArgs([]string{"healthcheck"}); got != 1 {
			t.Fatalf("runArgs([healthcheck]) = %d, want 1", got)
		}
	})
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
const warnUnavailableListenerMsg = "listener has no eligible routes; replying 503 Service Unavailable"

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
	t.Setenv("RPGW_SHUTDOWN_GRACE", "") // neutralize the environment
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
		t.Setenv("RPGW_SHUTDOWN_GRACE", "2s")
		cfg, err := config.LoadBootstrap()
		if err != nil {
			t.Fatalf("LoadBootstrap: %v", err)
		}
		if cfg.ShutdownGrace != 2*time.Second {
			t.Fatalf("ShutdownGrace = %s, want 2s", cfg.ShutdownGrace)
		}
	})
	t.Run("not a duration", func(t *testing.T) {
		t.Setenv("RPGW_SHUTDOWN_GRACE", "soon")
		if _, err := config.LoadBootstrap(); err == nil || !strings.Contains(err.Error(), "must be a Go duration") {
			t.Fatalf("err = %v, want a Go-duration error", err)
		}
	})
	t.Run("not positive", func(t *testing.T) {
		t.Setenv("RPGW_SHUTDOWN_GRACE", "0s")
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
	lnAdmin, adminSrv := serveAdminListener(t, proxyserver.AdminMux(proxyserver.AdminOptions{Version: "test", Started: time.Now(), Store: store, Listeners: map[string]*proxyserver.Server{"mixed": srvA}, Lifecycle: proxyserver.NewLifecycle()}))

	listeners := []runningListener{
		{name: "mixed", server: srvA, ln: lnA},
		{name: "v4", server: srvB, ln: lnB},
	}

	// A 12s grace: the readiness head start is capped at grace/2, so this one
	// takes the full 5s while the drain itself returns at once, and the two
	// halves stay separable.
	const grace = 12 * time.Second
	done := make(chan struct{})
	go func() {
		shutdownAll(logging.Nop(), proxyserver.NewLifecycle(), func() {}, func(context.Context) {}, listeners, adminSrv, grace)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(grace/2 + 3*time.Second):
		t.Fatalf("shutdownAll on a process with no live sessions did not return in head+drain time, well under the %s grace", grace)
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
		shutdownAll(logging.Nop(), proxyserver.NewLifecycle(), func() {}, func(context.Context) {}, listeners, adminSrv, grace)
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
	// A 12s grace, for the reason above: the head start is capped at grace/2,
	// so this process waits 5s to unready and then drains nothing at all.
	const grace = 12 * time.Second
	done := make(chan struct{})
	go func() {
		shutdownAll(logging.Nop(), proxyserver.NewLifecycle(), func() {}, func(context.Context) {}, listeners, adminSrv, grace)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(grace/2 + 3*time.Second):
		t.Fatalf("shutdownAll did not return in head+drain time although the only session had already ended (grace %s)", grace)
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

// The ordering the whole readiness feature exists for: /readyz goes 503 the
// instant the drain starts, while every proxy listener and the admin listener
// are still accepting. Asserting the two states separately would prove nothing —
// a probe that only ever sees "503" after the sockets are gone would pass too.
func TestShutdownAllUnreadsBeforeAnyListenerCloses(t *testing.T) {
	log := newTestLogger()
	store := newTestStore()
	lc := proxyserver.NewLifecycle()
	lc.MarkReady()

	srvA := proxyserver.NewRuntime(store, log, "test", "mixed", config.EgressV4, config.EgressV6)
	srvB := proxyserver.NewRuntime(store, log, "test", "v4", config.EgressV4)
	srvC := proxyserver.NewRuntime(store, log, "test", "v6", config.EgressV6)
	lnA := serveSocksListener(t, srvA)
	lnB := serveSocksListener(t, srvB)
	lnC := serveSocksListener(t, srvC)
	lnAdmin, adminSrv := serveAdminListener(t, proxyserver.AdminMux(proxyserver.AdminOptions{Version: "test", Started: time.Now(), Store: store, Lifecycle: lc}))

	listeners := []runningListener{
		{name: "mixed", server: srvA, ln: lnA},
		{name: "v4", server: srvB, ln: lnB},
		{name: "v6", server: srvC, ln: lnC},
	}

	// A 12s grace: the head start is capped at grace/2, so this one takes the
	// full 5s — long enough to sample the window repeatedly, and the drain
	// itself has nothing to wait for.
	const grace = 12 * time.Second
	// reachability is sampled at the moment it is asked for, so the answer
	// belongs to that instant rather than to whenever the goroutine got
	// scheduled.
	reachable := func(ln net.Listener) bool {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 200*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}
	// A refused connection is 0, not a failure: the admin socket closing is
	// what the end of the drain looks like from outside. What must never
	// happen is a 200 once the drain has begun.
	readyz := func() int {
		client := &http.Client{Timeout: time.Second}
		resp, err := client.Get("http://" + lnAdmin.Addr().String() + proxyserver.ReadyPath)
		if err != nil {
			return 0
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	// Sampled before the goroutine exists, so the "before" answer belongs to
	// the serving phase and not to a race with the drain.
	if got := readyz(); got != http.StatusOK {
		t.Fatalf("before the signal /readyz = %d, want 200", got)
	}
	done := make(chan struct{})
	go func() {
		shutdownAll(logging.Nop(), lc, func() {}, func(context.Context) {}, listeners, adminSrv, grace)
		close(done)
	}()

	// The window between the two transitions is exactly the head start, so
	// sampling faster than it is what proves the listeners stayed open across
	// it.
	deadline := time.Now().Add(grace/2 + 2*time.Second)
	samples, unready := 0, 0
	for time.Now().Before(deadline) {
		got := readyz()
		if got == http.StatusOK {
			t.Fatal("the process advertised readiness after the drain began; /readyz is what evicts it from the load balancer")
		}
		if got == http.StatusServiceUnavailable {
			unready++
		}
		// Sampled only while the admin listener is still answering: after the
		// drain its socket is gone, and a refused connection is not evidence
		// about reachability.
		if got != 0 {
			for _, ln := range []net.Listener{lnA, lnB, lnC, lnAdmin} {
				if !reachable(ln) {
					t.Fatalf("listener %s stopped accepting before the head start ended; the readiness window is the feature", ln.Addr())
				}
			}
		}
		samples++
		time.Sleep(100 * time.Millisecond)
	}
	if samples < 10 || unready < 10 {
		t.Fatalf("%d samples of which %d answered 503, want the %s head start sampled throughout", samples, unready, proxyserver.ReadinessPropagation)
	}

	select {
	case <-done:
	case <-time.After(grace/2 + 5*time.Second):
		t.Fatal("shutdownAll did not return after the head start and an empty drain")
	}
	// Terminal: the process no longer advertises readiness even if something
	// answers the admin socket late.
	if got := lc.Ready(); got {
		t.Fatal("lifecycle still reports ready after shutdownAll returned")
	}
	for _, ln := range []net.Listener{lnA, lnB, lnC, lnAdmin} {
		if reachable(ln) {
			t.Fatalf("listener %s still reachable after shutdownAll", ln.Addr())
		}
	}
}

// Every listen socket closes before any of them drains. The old sequence
// closed and drained one listener at a time in construction order, which kept
// the later listeners accepting — and, because each Server only sets its own
// shuttingDown flag inside its own Shutdown, let them admit brand-new sessions
// that the already-expired deadline then force-closed.
//
// The fixture is a listener whose sessions can never finish: the mixed listener
// holds one for the whole budget. If the close were interleaved with the
// drains, the v4 listener's own Shutdown would not have started when the
// budget expired, so its parked session would be released by the wait rather
// than by the force-close sweep — the two are told apart by the fact that only
// the force-close closes a session parked in its greeting read.
func TestShutdownAllClosesEveryListenerBeforeDraining(t *testing.T) {
	log := newTestLogger()
	store := newTestStore()
	srvA := proxyserver.NewRuntime(store, log, "test", "mixed", config.EgressV4, config.EgressV6)
	srvB := proxyserver.NewRuntime(store, log, "test", "v4", config.EgressV4)
	lnA := serveSocksListener(t, srvA)
	lnB := serveSocksListener(t, srvB)
	_, adminSrv := serveAdminListener(t, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))

	parkedMixed := parkConn(t, lnA.Addr().String())
	parkedV4 := parkConn(t, lnB.Addr().String())
	// One beat so both accept loops really start the parked sessions, for the
	// reason spelled out on TestShutdownAllSharedBudget.
	time.Sleep(250 * time.Millisecond)

	listeners := []runningListener{
		{name: "mixed", server: srvA, ln: lnA},
		{name: "v4", server: srvB, ln: lnB},
	}

	// A long grace, so the head start is the full 5s and the shared budget that
	// follows is long enough that the drain is what ends the sessions.
	const grace = 30 * time.Second
	done := make(chan struct{})
	go func() {
		shutdownAll(logging.Nop(), proxyserver.NewLifecycle(), func() {}, func(context.Context) {}, listeners, adminSrv, grace)
		close(done)
	}()

	// Part-way through the head start both sockets are still open — that is the
	// property this test is about, checked without depending on a specific
	// close ordering being observable from outside.
	time.Sleep(proxyserver.ReadinessPropagation / 2)
	for _, ln := range []net.Listener{lnA, lnB} {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 200*time.Millisecond)
		if err != nil {
			t.Fatalf("listener %s stopped accepting %s into a %s head start", ln.Addr(), proxyserver.ReadinessPropagation/2, proxyserver.ReadinessPropagation)
		}
		_ = conn.Close()
	}

	select {
	case <-done:
	case <-time.After(grace + 10*time.Second):
		t.Fatal("shutdownAll did not return within grace + 10s")
	}
	// Both parked sessions were force-closed by the sweep, which is what proves
	// the v4 listener's Shutdown had begun before the budget expired.
	assertForceClosed(t, parkedMixed)
	assertForceClosed(t, parkedV4)
}

// The head start is a pause, not a floor: a process whose listeners have
// already failed on their own has nothing left to unready for anyone, and
// burning the full window on it would delay every real shutdown for nothing.
func TestShutdownAllHeadStartIsBoundedByTheBudget(t *testing.T) {
	log := newTestLogger()
	store := newTestStore()
	lc := proxyserver.NewLifecycle()
	lc.MarkReady()
	srv := proxyserver.NewRuntime(store, log, "test", "mixed", config.EgressV4, config.EgressV6)
	ln := serveSocksListener(t, srv)
	_, adminSrv := serveAdminListener(t, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	listeners := []runningListener{{name: "mixed", server: srv, ln: ln}}

	// A grace too short to carry the head start: the cap hands back grace/2
	// instead, and total signal→exit still stays inside the budget.
	const grace = 200 * time.Millisecond
	start := time.Now()
	shutdownAll(logging.Nop(), lc, func() {}, func(context.Context) {}, listeners, adminSrv, grace)
	elapsed := time.Since(start)
	if elapsed > grace+2*time.Second {
		t.Fatalf("shutdownAll took %s for a %s grace; the head start escaped the budget", elapsed, grace)
	}
	if lc.Ready() {
		t.Fatal("lifecycle still reports ready after shutdownAll returned")
	}
}

// A zero or negative grace is not a configuration this process produces, but it
// must not hang the head start: the previous behavior (no pause at all) is the
// correct one for a budget that cannot carry a pause.
func TestShutdownAllNoHeadStartWithoutABudget(t *testing.T) {
	for _, grace := range []time.Duration{0, -time.Second} {
		log := newTestLogger()
		store := newTestStore()
		lc := proxyserver.NewLifecycle()
		lc.MarkReady()
		srv := proxyserver.NewRuntime(store, log, "test", "mixed", config.EgressV4, config.EgressV6)
		ln := serveSocksListener(t, srv)
		_, adminSrv := serveAdminListener(t, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
		listeners := []runningListener{{name: "mixed", server: srv, ln: ln}}

		start := time.Now()
		shutdownAll(logging.Nop(), lc, func() {}, func(context.Context) {}, listeners, adminSrv, grace)
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatalf("grace %s: shutdownAll took %s, want it to return at once", grace, elapsed)
		}
		if lc.Ready() {
			t.Fatalf("grace %s: lifecycle still reports ready after shutdownAll", grace)
		}
	}
}

// Regression for issue #104: a durable revision committed by another instance
// must reach the generation this process serves from.
//
// The defect was invisible from the outside: openControlPlane built a store for
// the reconciler and run() built a second one for the listeners, but every
// process-global effect of a reconciled revision (the log level, the
// "configuration reloaded" line) still applied — so the logs announced a
// revision the gateway was not serving. This test pins the wiring, not the
// reconciler's own correctness: it asserts that the store selectServingStore
// returns is the same one the reconciler publishes into.
func TestSelectServingStoreReconcilesIntoTheServingGeneration(t *testing.T) {
	ctx := context.Background()

	seedJSON := `{"version":1,"log-level":"info","max-retries":2,
		"cooldown":{"base":"15s","max":"10m"},"dial-timeout":"10s",
		"proxies":{"auto":[{"id":"egress-a","proxy":"good.example:1080","kind":"v4"}]}}`
	runtimeCfg := mustRuntime(t, seedJSON)

	// The store openControlPlane hands the reconciler, and the store run() would
	// serve from — the two the fix must make identical.
	generations := pool.NewStore(runtimeCfg, pool.NewRoutes(runtimeCfg.AllRoutes(), runtimeCfg.CooldownBase, runtimeCfg.CooldownMax))
	repo := newStubRepository()
	reconciler := control.NewReconciler(repo, generations, zerolog.Nop(), control.Options{})

	// Revision 1: the boot generation, the same revision openControlPlane's Seed
	// commits first from the local file.
	revision1, err := reconciler.Seed(ctx, runtimeCfg)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	cp := &controlPlane{store: repo, generations: generations, reconciler: reconciler}
	serving := selectServingStore(cp, runtimeCfg, revision1)

	// The stamp selectServingStore applies must be on the store the reconciler
	// publishes into, not a copy of it.
	if got := serving.Load().ConfigRevision; got != int64(revision1) {
		t.Fatalf("serving generation stamped revision %d, want %d", got, revision1)
	}

	// A peer commits revision 2: a second route, a different log level.
	changedJSON := `{"version":1,"log-level":"debug","max-retries":7,
		"cooldown":{"base":"15s","max":"10m"},"dial-timeout":"10s",
		"proxies":{"auto":[
			{"id":"egress-a","proxy":"good.example:1080","kind":"v4"},
			{"id":"egress-b","proxy":"other.example:1080","kind":"v6"}
		]}}`
	changed := mustRuntime(t, changedJSON)
	doc, err := configstore.NewDocument(changed)
	if err != nil {
		t.Fatalf("encode revision 2: %v", err)
	}
	if _, err := repo.Commit(ctx, revision1, doc, configstore.Meta{Author: "peer", Note: "second revision"}); err != nil {
		t.Fatalf("peer commit: %v", err)
	}

	// One reconcile tick, exactly as the Run loop performs.
	if err := reconciler.ReconcileOnce(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// The serving store — the one selectServingStore returned, the one the
	// listeners and /status read — must now be serving revision 2. On the
	// pre-fix wiring this store was a second object the reconciler never
	// touched, so it still read revision 1 with one route.
	gen := serving.Load()
	if gen.ConfigRevision != int64(revision1)+1 {
		t.Errorf("serving generation revision = %d, want %d — the durable revision never reached the serving store", gen.ConfigRevision, int64(revision1)+1)
	}
	if got := len(gen.Config.AllRoutes()); got != 2 {
		t.Errorf("serving route count = %d, want 2 — revision 2's route set did not materialize", got)
	}
	if gen.Config.LogLevel != "debug" {
		t.Errorf("serving log level = %q, want %q", gen.Config.LogLevel, "debug")
	}

	// File mode has no durable store and no reconciler: selectServingStore must
	// build a local store rather than dereferencing a nil control plane, and must
	// leave its revision unstamped.
	local := selectServingStore(nil, runtimeCfg, configstore.NoRevision)
	if local.Load().ConfigRevision != 0 {
		t.Errorf("file-mode generation revision = %d, want 0 (not from the durable store)", local.Load().ConfigRevision)
	}
	if len(local.Load().Config.AllRoutes()) != 1 {
		t.Errorf("file-mode route count = %d, want 1", len(local.Load().Config.AllRoutes()))
	}
}

// mustRuntime decodes a document body into a validated RuntimeConfig, failing
// the test on any validation error.
func mustRuntime(t *testing.T, document string) *config.RuntimeConfig {
	t.Helper()
	cfg, err := config.DecodeDocument([]byte(document))
	if err != nil {
		t.Fatalf("decode document: %v", err)
	}
	return cfg
}
