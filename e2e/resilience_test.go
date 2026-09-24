package e2e_test

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// With every route cooling, the all-cooling fallback still hands out routes,
// so consecutive requests keep recording dial failures and the exponential
// cooldown doubles per consecutive failure until the pool is capped.
func TestE2E_ExhaustedPoolNoRouteWithCooldownDoubling(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	target := NewEchoTarget(t)
	cfg := defaultGatewayConfig([]RouteConfig{
		{Proxy: deadRouteValue(t), Kind: "v4"},
		{Proxy: deadRouteValue(t), Kind: "v4"},
	})
	// With pool size == max-retries, the cap ends the chain after both routes
	// were tried; the budget, not route exhaustion, stops it, so the terminal
	// record is retry_exhausted, not no_route.
	cfg.MaxRetries = 2
	g := NewGateway(t, cfg)

	// Request n leaves each route at n consecutive failures and a cooldown of
	// base*2^(n-1). Requests run back to back, so /status must report the
	// remaining cooldown inside (want-1s, want].
	steps := []struct {
		consecutiveFailures int
		cooldown            time.Duration
	}{
		{1, 5 * time.Second},
		{2, 10 * time.Second},
		{3, 20 * time.Second},
	}
	for i, step := range steps {
		failedSocksTunnel(t, g.MixedAddr, target.Host)

		st, err := g.Status()
		if err != nil {
			t.Fatal(err)
		}
		if len(st.Pool) != 2 {
			t.Fatalf("request %d: pool=%+v", i, st.Pool)
		}
		for _, e := range st.Pool {
			if e.ConsecutiveFailures != step.consecutiveFailures {
				t.Fatalf("request %d: consecutiveFailures=%d, want %d (%+v)",
					i, e.ConsecutiveFailures, step.consecutiveFailures, e)
			}
			if e.Available {
				t.Fatalf("request %d: route still available while cooling: %+v", i, e)
			}
			cd, err := time.ParseDuration(e.CooldownFor)
			if err != nil {
				t.Fatalf("request %d: cooldownFor=%q: %v", i, e.CooldownFor, err)
			}
			low, high := step.cooldown-time.Second, step.cooldown
			if cd <= low || cd > high {
				t.Fatalf("request %d: cooldownFor=%s, want in (%s, %s] for cf=%d",
					i, e.CooldownFor, low, high, step.consecutiveFailures)
			}
		}
	}

	waitForLogRecord(t, g, map[string]string{"msg": "tunnel failed", "error_kind": "retry_exhausted", "attempts": "2"}, 5*time.Second)
}

// The terminal record must reflect which condition ended the chain: a true
// pool exhaustion logs no_route — the issue #39 case of pool==max-retries
// covers that — while stopping at the retry cap with eligible routes still
// untried logs retry_exhausted. The client still gets 05 01 in both cases.
func TestE2E_RetryCapExhaustionLogsDistinctKind(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	target := NewEchoTarget(t)
	cfg := defaultGatewayConfig([]RouteConfig{
		{Proxy: deadRouteValue(t), Kind: "v4"},
		{Proxy: deadRouteValue(t), Kind: "v4"},
		{Proxy: deadRouteValue(t), Kind: "v4"},
	})
	cfg.MaxRetries = 2 // three routes, the cap stops the chain with one untried
	g := NewGateway(t, cfg)

	failedSocksTunnel(t, g.MixedAddr, target.Host)

	// The cap ends the chain after two attempts: eligible routes remained.
	waitForLogRecord(t, g, map[string]string{
		"msg": "tunnel failed", "error_kind": "retry_exhausted", "attempts": "2",
	}, 5*time.Second)
	for _, rec := range decodeLogRecords(g.Logs()) {
		if recordHas(rec, map[string]string{"msg": "tunnel failed", "error_kind": "no_route"}) {
			t.Fatalf("retry-cap stop wrongly logged no_route:\n%s", g.Logs())
		}
	}
	st, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Pool) != 3 {
		t.Fatalf("pool size = %d, want 3", len(st.Pool))
	}
	// Two attempts dialed two distinct routes once each; the third route never
	// was tried — proof that eligible routes remained when the cap stopped the
	// chain. The two dialed routes report their 5s base cooldown still in the
	// window.
	dialed := 0
	for _, e := range st.Pool {
		if e.Failures == 1 {
			dialed++
		}
	}
	if dialed != 2 {
		t.Fatalf("dialed routes = %d, want 2 of 3 tried before the cap stopped the chain: %+v", dialed, st.Pool)
	}
}

// A tunnel established before a reload must keep relaying on its original
// upstream connection across generation swaps.
func TestE2E_TunnelSurvivesReload(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socksA := NewSocksSim(t, SocksOK, "", "")
	socksB := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socksA.RouteValue(), Kind: "v4"},
	}))

	conn := socksTunnel(t, g.MixedAddr, target.Host)
	br := bufio.NewReader(conn)

	// Grow and shrink the pool while the tunnel stays open.
	g.ReloadConfig(defaultGatewayConfig([]RouteConfig{
		{Proxy: socksA.RouteValue(), Kind: "v4"},
		{Proxy: socksB.RouteValue(), Kind: "v4"},
	}), []string{socksA.Addr, socksB.Addr})
	g.ReloadConfig(defaultGatewayConfig([]RouteConfig{
		{Proxy: socksA.RouteValue(), Kind: "v4"},
	}), []string{socksA.Addr})

	// The same tunnel must still relay after both generation swaps.
	_, _ = fmt.Fprintf(conn, "GET /after-reload HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target.Host)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read in-tunnel response after reload: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "e2e-echo:/after-reload" {
		t.Fatalf("in-tunnel status=%d body=%q, want the echo through the original tunnel", resp.StatusCode, body)
	}
}

// An established tunnel that breaks mid-relay is ordinary connection
// teardown: the client observes the close, route health is untouched, and the
// listener keeps serving new requests.
func TestE2E_TunnelBreakDoesNotMutateHealth(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	cfg := defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	})
	cfg.LogLevel = "debug" // tunnel close records are flow detail
	g := NewGateway(t, cfg)

	conn := socksTunnel(t, g.MixedAddr, target.Host)
	br := bufio.NewReader(conn)

	// Tear the target down under the live tunnel, then push a request through:
	// the relay must end and the client must observe the close.
	target.Server.Close()
	fmt.Fprintf(conn, "GET /gone HTTP/1.1\r\nHost: %s\r\n\r\n", target.Host) //nolint:errcheck // a racing close may reject the write; the read decides
	if _, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet}); err == nil {
		t.Fatal("read from broken tunnel unexpectedly succeeded")
	}

	st, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Pool[0].Successes != 1 || st.Pool[0].Failures != 0 || !st.Pool[0].Available {
		t.Fatalf("tunnel break mutated health: %+v", st.Pool[0])
	}

	// The relay writes a close record naming the lifetime and both directions'
	// byte counts, so mid-stream drops are attributable in production logs.
	// Which close_reason materializes is timing-dependent (a racing FIN reads
	// as upstream_closed, a mid-stream RST as upstream_broken), so match any
	// close record and assert its attribution fields.
	var closeRec logRecord
	g.WaitForCondition(10*time.Second, "tunnel close record", func(*Status) bool {
		for _, rec := range decodeLogRecords(g.Logs()) {
			if recordHasKey(rec, "close_reason") {
				closeRec = rec
				return true
			}
		}
		return false
	})
	if closeRec["target"] != target.Host || closeRec["upstream"] != socks.Addr {
		t.Fatalf("close record lost route identity: %v", closeRec)
	}
	for _, key := range []string{"client_to_upstream_bytes", "upstream_to_client_bytes", "duration"} {
		if !recordHasKey(closeRec, key) {
			t.Fatalf("close record missing %q: %v", key, closeRec)
		}
	}

	// The same listener keeps serving fresh requests afterwards.
	after := NewEchoTarget(t)
	GetVia(t, ProxyClient(g.MixedAddr), after.URL+"/after", "e2e-echo:/after")
	st, err = g.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Pool[0].Successes != 2 || st.Pool[0].Failures != 0 {
		t.Fatalf("post-break pool = %+v, want exactly the new success", st.Pool[0])
	}
}

// TerminateAndWait sends SIGTERM, waits for exit, and returns the exit code.
func (g *Gateway) TerminateAndWait() int {
	g.t.Helper()
	if g.cmd == nil || (g.cmd.ProcessState != nil && g.cmd.ProcessState.Exited()) {
		g.t.Fatal("gateway already exited")
	}
	if err := g.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		g.t.Fatalf("SIGTERM: %v", err)
	}
	err := g.cmd.Wait()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	g.t.Fatalf("wait: %v", err)
	return -1
}

// Shutdown must drain in-flight proxy requests: the listener keeps serving
// until the request completes, and the process exits 0.
func TestE2E_ShutdownDrainsInFlightRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(400 * time.Millisecond)
		_, _ = io.WriteString(w, "e2e-slow")
	}))
	t.Cleanup(srv.Close)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}))

	type result struct {
		status int
		body   []byte
		err    error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := ProxyClient(g.MixedAddr).Get(srv.URL + "/slow")
		if err != nil {
			done <- result{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		done <- result{status: resp.StatusCode, body: b}
	}()
	time.Sleep(100 * time.Millisecond) // let the request go in flight

	if code := g.TerminateAndWait(); code != 0 {
		t.Fatalf("exit=%d, want 0\nlogs:\n%s", code, g.Logs())
	}
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("in-flight request failed during shutdown: %v", r.err)
		}
		if r.status != http.StatusOK || string(r.body) != "e2e-slow" {
			t.Fatalf("in-flight status=%d body=%q, want 200 e2e-slow", r.status, r.body)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("in-flight request never completed")
	}
}

// The configured RPGW_SHUTDOWN_GRACE is one shared budget for the whole drain: an
// in-flight request that never completes must still let the process exit near
// the budget with a graceful exit code instead of hanging on it.
func TestE2E_ShutdownGraceBoundsDrain(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	const grace = time.Second
	socks := NewSocksSim(t, SocksOK, "", "")
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// Hold the target response until the client (the gateway) goes away:
		// the request context cancels when the gateway's connection closes.
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	g := NewGatewayWithEnv(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}), "RPGW_SHUTDOWN_GRACE="+grace.String())

	type result struct {
		status int
		body   []byte
		err    error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := ProxyClient(g.MixedAddr).Get(srv.URL + "/stuck")
		if err != nil {
			done <- result{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		done <- result{status: resp.StatusCode, body: b}
	}()
	time.Sleep(150 * time.Millisecond) // let the request go in flight

	start := time.Now()
	if code := g.TerminateAndWait(); code != 0 {
		t.Fatalf("exit=%d, want graceful 0\nlogs:\n%s", code, g.Logs())
	}
	elapsed := time.Since(start)
	if elapsed < grace-100*time.Millisecond {
		t.Fatalf("exit after %s, want at least the %s budget", elapsed, grace)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("exit after %s, want near the %s budget", elapsed, grace)
	}

	// The stuck request must observe the exit as a connection error.
	select {
	case r := <-done:
		if r.err == nil {
			t.Fatalf("stuck request completed with status=%d body=%q, want a connection error", r.status, r.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stuck request never observed the exit")
	}
}

// runGatewayOnce starts the binary with explicit bootstrap env, waits for it
// to exit, and returns the exit code with the combined output. Bootstrap
// failures exit before any listener binds, so this never blocks.
func runGatewayOnce(t *testing.T, configPath, admin, mixed, v4, v6 string) (int, string) {
	t.Helper()
	if testBinaryPath == "" {
		t.Skip("e2e binary not built (short mode?)")
	}
	var out lockedBuffer
	cmd := exec.Command(testBinaryPath)
	cmd.Env = []string{
		"RPGW_CONFIG_FILE=" + configPath,
		"RPGW_ADMIN_ADDR=" + admin,
		"RPGW_MIXED_LISTEN_ADDR=" + mixed,
		"RPGW_V4_LISTEN_ADDR=" + v4,
		"RPGW_V6_LISTEN_ADDR=" + v6,
		"PATH=" + os.Getenv("PATH"),
	}
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start gateway: %v", err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("gateway kept running past a bootstrap failure:\n%s", out.String())
	}
	return cmd.ProcessState.ExitCode(), out.String()
}

func writeBootstrapConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg := defaultGatewayConfig([]RouteConfig{{Proxy: "127.0.0.1:1", Kind: "v4"}})
	if err := os.WriteFile(path, []byte(renderConfig(cfg)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Invalid bootstrap configuration must fail fast with a non-zero exit code
// and a diagnosis, never serve with a partially applied setup.
func TestE2E_BootstrapValidationFailsFast(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	t.Run("overlapping listeners", func(t *testing.T) {
		cfgPath := writeBootstrapConfig(t)
		same := freeAddr(t)
		code, out := runGatewayOnce(t, cfgPath, same, same, freeAddr(t), freeAddr(t))
		if code == 0 {
			t.Fatalf("exit=0, want failure\noutput:\n%s", out)
		}
		if !strings.Contains(out, "must not overlap") {
			t.Fatalf("output missing overlap error:\n%s", out)
		}
	})
	t.Run("all proxy listeners disabled", func(t *testing.T) {
		cfgPath := writeBootstrapConfig(t)
		code, out := runGatewayOnce(t, cfgPath, freeAddr(t), "", "", "")
		if code == 0 {
			t.Fatalf("exit=0, want failure\noutput:\n%s", out)
		}
		if !strings.Contains(out, "at least one proxy listener must be enabled") {
			t.Fatalf("output missing disabled-listener error:\n%s", out)
		}
	})
	t.Run("missing config file", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "absent.yaml")
		code, out := runGatewayOnce(t, missing, freeAddr(t), freeAddr(t), freeAddr(t), freeAddr(t))
		if code == 0 {
			t.Fatalf("exit=0, want failure\noutput:\n%s", out)
		}
		if !strings.Contains(out, "not found") {
			t.Fatalf("output missing missing-config error:\n%s", out)
		}
	})
	t.Run("schemed route line", func(t *testing.T) {
		// Route lines carry no scheme; on first boot the process must refuse
		// to start rather than serve a config it would have to reject.
		path := filepath.Join(t.TempDir(), "config.yaml")
		cfg := defaultGatewayConfig([]RouteConfig{{Proxy: "socks5://127.0.0.1:1", Kind: "v4"}})
		if err := os.WriteFile(path, []byte(renderConfig(cfg)), 0o600); err != nil {
			t.Fatal(err)
		}
		code, out := runGatewayOnce(t, path, freeAddr(t), freeAddr(t), freeAddr(t), freeAddr(t))
		if code == 0 {
			t.Fatalf("exit=0, want failure\noutput:\n%s", out)
		}
		if !strings.Contains(out, "carry no scheme") {
			t.Fatalf("output missing scheme rejection:\n%s", out)
		}
	})
}

// A session stuck inside an upstream dial must not stretch shutdown: once the
// shared grace budget expires, the gateway cancels pending dials, force-closes
// its client connections, and exits inside the budget plus the bounded
// force-close tail — never anywhere near the dial timeout. The upstream here
// is a black hole that accepts TCP but never answers the SOCKS greeting, so
// the tunnel parks for dial-timeout (30s) unless shutdown unwinds it.
//
// The black hole's accepted connections must outlive the test: dropping the
// only reference lets the Go runtime finalizer close the socket, which would
// unwind the stuck dial as an EOF/reset and let shutdown finish in
// milliseconds — the issue #66 false failure. Every accepted conn is therefore
// retained until cleanup, and the test proves via /status that the gateway
// session is genuinely holding its in-flight pick before SIGTERM is sent.
func TestE2E_ShutdownGraceBoundsStuckDial(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	bhLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bhLn.Close() })

	// accepted feeds the accept loop; parked retains every accepted conn for
	// the whole test so neither GC finalization nor a stray close can kill the
	// session the gateway is stuck dialing.
	accepted := make(chan net.Conn, 4)
	var parked []net.Conn
	var parkedMu sync.Mutex
	t.Cleanup(func() {
		parkedMu.Lock()
		defer parkedMu.Unlock()
		for _, c := range parked {
			_ = c.Close()
		}
	})
	retain := func(c net.Conn) {
		parkedMu.Lock()
		parked = append(parked, c)
		parkedMu.Unlock()
	}
	go func() {
		for {
			c, err := bhLn.Accept()
			if err != nil {
				return
			}
			retain(c)
			accepted <- c
		}
	}()

	cfg := defaultGatewayConfig([]RouteConfig{
		{Proxy: bhLn.Addr().String(), Kind: "v4"},
	})
	cfg.DialTimeout = "30s"
	g := NewGatewayWithEnv(t, cfg, "RPGW_SHUTDOWN_GRACE=2s")

	// One CONNECT parks the gateway inside the upstream SOCKS handshake.
	conn, err := net.Dial("tcp", g.MixedAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second)) // the whole fixture may wait out a grace cycle
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	choice := make([]byte, 2)
	if _, err := io.ReadFull(conn, choice); err != nil {
		t.Fatal(err)
	}
	req, err := socksConnectRequestBytes("example.test:80")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("gateway never dialed the black-hole upstream")
	}

	// Prove the session genuinely holds its in-flight pick before SIGTERM: the
	// pool reports inFlight=1 for the black-hole route and the listener counted
	// the CONNECT. Without this, a fixture race could send SIGTERM against an
	// idle gateway and report a spuriously-instant drain (the issue #66 shape).
	g.WaitForCondition(5*time.Second, "stuck dial holds its in-flight pick", func(st *Status) bool {
		if st.Requests != 1 || len(st.Pool) != 1 {
			return false
		}
		// The pick is held in flight and no report has been recorded yet — the
		// greeting read is still pending against the black hole. Available stays
		// true until the dial failure actually lands, so it is not part of the
		// in-flight proof.
		return st.Pool[0].InFlight == 1 && st.Pool[0].Failures == 0
	})

	start := time.Now()
	// TerminateAndWait keeps the process's real exit status: a signal-defined
	// death (the default SIGTERM disposition the old startup race produced)
	// would land here as a non-zero, never a graceful 0.
	exitCode := g.TerminateAndWait()
	if exitCode != 0 {
		t.Fatalf("exit=%d, want graceful 0\nlogs:\n%s", exitCode, g.Logs())
	}
	elapsed := time.Since(start)
	// Grace 2s (established tunnels are never broken early) plus the bounded
	// force-close tail; the 30s dial timeout must not appear in the exit time.
	// The log dump on failure is deliberate: a shutdown-path panic or early
	// unwind must carry its own trace, not be swallowed by the harness buffer.
	if elapsed < 1900*time.Millisecond || elapsed > 4500*time.Millisecond {
		t.Fatalf("shutdown took %s, want within [1.9s, 4.5s] (grace 2s + force-close tail)\nlogs:\n%s", elapsed, g.Logs())
	}
}

// A SIGTERM arriving the moment the gateway becomes healthy used to race the
// signal handler's registration: /healthz could answer before signal.Notify
// ran, so a manager that stopped a just-started instance could kill it with
// the default disposition — no drain, non-zero exit. Registration now happens
// before any listener binds, so SIGTERM at (or immediately after) readiness
// must always drain gracefully and exit 0. Repeated start/stop rounds make the
// race window observable.
func TestE2E_SIGTERMAtReadinessExitsGracefully(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	const grace = time.Second
	cfg := defaultGatewayConfig([]RouteConfig{
		{Proxy: deadRouteValue(t), Kind: "v4"},
	})
	// Idle shutdown is immediate: no session to drain, so the process must
	// exit well under the grace budget.
	for round := range 20 {
		g := NewGatewayWithEnv(t, cfg, "RPGW_SHUTDOWN_GRACE="+grace.String())
		start := time.Now()
		exitCode := g.TerminateAndWait()
		if exitCode != 0 {
			t.Fatalf("round %d: exit=%d, want graceful 0 (SIGTERM at readiness must not use the default disposition)\nlogs:\n%s",
				round, exitCode, g.Logs())
		}
		if elapsed := time.Since(start); elapsed > grace+2*time.Second {
			t.Fatalf("round %d: idle shutdown took %s, want immediate (well under the %s grace)", round, elapsed, grace)
		}
	}
}
