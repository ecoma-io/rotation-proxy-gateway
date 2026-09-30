package e2e_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Readiness is the only signal a load balancer gets before this process's
// sockets go away, so the two things the black-box suite has to prove are the
// ordering (/readyz 503 while every listener is still accepting) and the
// consequence (a connection opened inside that window is still served).
//
// Everything here drives the real binary as a subprocess, so the head start
// under test is the one the process actually takes.

// reachable dials addr and reports whether a connection was accepted. It is
// sampled at call time, so the answer belongs to that instant rather than to
// whenever the goroutine got scheduled.
func reachable(t *testing.T, addr string) bool {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// The end-to-end invariant: on SIGTERM the process answers 503 on /readyz and
// keeps accepting on all four listeners for a real head start, then closes
// them. /healthz stays 200 throughout — it is liveness, and a probe that fails
// while a process is stopping correctly is exactly the wrong thing to leave
// Docker reading.
func TestE2E_ReadyzUnreadyBeforeAnyListenerCloses(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}))

	if code, body := g.AdminPath("/readyz"); code != http.StatusOK || body != "ok\n" {
		t.Fatalf("while serving /readyz = %d %q, want 200 %q", code, body, "ok\n")
	}
	if code := g.Healthcheck(); code != 0 {
		t.Fatalf("healthcheck subcommand = %d while serving, want 0", code)
	}

	g.Signal(syscall.SIGTERM)

	// The head start is 5s; sample well inside it. Every listener must still
	// accept for the whole span, and /readyz must never come back 200.
	deadline := time.Now().Add(4 * time.Second)
	samples := 0
	for time.Now().Before(deadline) {
		code, body := g.AdminPath("/readyz")
		if code == 0 {
			// The admin listener answered nothing: the drain is already past the
			// head start, so there is no window left to assert about.
			break
		}
		if code != http.StatusServiceUnavailable {
			t.Fatalf("/readyz = %d %q during the drain, want 503", code, body)
		}
		if !strings.Contains(body, "draining") {
			t.Fatalf("/readyz body = %q during the drain, want the draining token", body)
		}
		// Liveness is the deliberate mirror image: 200 for the whole remaining
		// life of the process, drain window included.
		if hcode, _ := g.AdminPath("/healthz"); hcode != http.StatusOK {
			t.Fatalf("/healthz = %d during the drain, want 200 (liveness must not fail while stopping correctly)", hcode)
		}
		for _, addr := range []string{g.MixedAddr, g.V4Addr, g.V6Addr} {
			if !reachable(t, addr) {
				t.Fatalf("listener %s refused a connection inside the readiness head start", addr)
			}
		}
		samples++
		time.Sleep(250 * time.Millisecond)
	}
	if samples < 3 {
		t.Fatalf("only %d samples inside the readiness head start; it was not actually open", samples)
	}

	if code := g.Wait(); code != 0 {
		t.Fatalf("exit=%d, want graceful 0\nlogs:\n%s", code, g.Logs())
	}
	logs := g.Logs()
	if !strings.Contains(logs, `"msg":"readiness unready`) {
		t.Fatalf("no readiness-unready record; the drain was silent again\nlogs:\n%s", logs)
	}
}

// A tunnel opened after the process stopped advertising readiness is still
// served: the head start exists so an instance that a load balancer has not yet
// evicted keeps working, not to turn into a dead port the instant it goes
// unready.
func TestE2E_TunnelOpenedDuringHeadStartIsServed(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	// A 12s grace: the head start is capped at grace/2, so this one takes the
	// full 5s and the drain behind it has plenty left.
	const grace = 12 * time.Second
	socks := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	g := NewGatewayWithEnv(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}), "RPGW_SHUTDOWN_GRACE="+grace.String())

	g.Signal(syscall.SIGTERM)
	// Wait for the transition, then open a tunnel inside the window.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if code, _ := g.AdminPath("/readyz"); code == http.StatusServiceUnavailable {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/head-start", "e2e-echo:/head-start")

	if code := g.Wait(); code != 0 {
		t.Fatalf("exit=%d, want graceful 0 after serving a tunnel opened during the head start\nlogs:\n%s", code, g.Logs())
	}
}

// An in-flight tunnel is drained, not cut: under a generous grace it runs to
// completion with real relays at both ends, and under a tiny one the same
// fixture is force-closed rather than left hanging. Both halves use the same
// SOCKS5 simulator and the same HTTP target, so nothing about the fixture
// differs between them but the budget.
func TestE2E_InFlightTunnelDrainedThenForceClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	t.Run("generous grace drains to completion", func(t *testing.T) {
		socks := NewSocksSim(t, SocksOK, "", "")
		srv := newDelayedTarget(t, 400*time.Millisecond)
		g := NewGatewayWithEnv(t, defaultGatewayConfig([]RouteConfig{
			{Proxy: socks.RouteValue(), Kind: "v4"},
		}), "RPGW_SHUTDOWN_GRACE=20s")

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
		time.Sleep(150 * time.Millisecond) // let the request go in flight

		g.Signal(syscall.SIGTERM)
		// Mid-head-start the tunnel is still the process's problem, not the
		// orchestrator's: the drain behind the signal has not started yet.
		if code, _ := g.AdminPath("/readyz"); code != http.StatusServiceUnavailable {
			t.Fatalf("/readyz = %d right after SIGTERM, want 503", code)
		}
		if code := g.Wait(); code != 0 {
			t.Fatalf("exit=%d, want graceful 0\nlogs:\n%s", code, g.Logs())
		}
		select {
		case r := <-done:
			if r.err != nil {
				t.Fatalf("in-flight request failed during a generous-grace drain: %v", r.err)
			}
			if r.status != http.StatusOK || !strings.HasPrefix(string(r.body), "delayed:") {
				t.Fatalf("in-flight status=%d body=%q, want the target's own response", r.status, r.body)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("in-flight request never completed")
		}
	})

	t.Run("tiny grace force-closes", func(t *testing.T) {
		socks := NewSocksSim(t, SocksOK, "", "")
		// A target that never answers: only the deadline can end this tunnel.
		srv := newHoldingTarget(t)
		g := NewGatewayWithEnv(t, defaultGatewayConfig([]RouteConfig{
			{Proxy: socks.RouteValue(), Kind: "v4"},
		}), "RPGW_SHUTDOWN_GRACE=1s")

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
		g.WaitForCondition(10*time.Second, "the stuck request is in flight",
			func(st *Status) bool { return st.Requests >= 1 })

		start := time.Now()
		g.Signal(syscall.SIGTERM)
		if code := g.Wait(); code != 0 {
			t.Fatalf("exit=%d, want graceful 0 even when the budget expires mid-tunnel\nlogs:\n%s", code, g.Logs())
		}
		if elapsed := time.Since(start); elapsed > 20*time.Second {
			t.Fatalf("exit after %s, want near the budget plus the force-close tail", elapsed)
		}
		select {
		case r := <-done:
			if r.err == nil {
				t.Fatalf("stuck request completed with status=%d body=%q, want a connection error", r.status, r.body)
			}
			if errors.Is(r.err, context.DeadlineExceeded) {
				t.Fatalf("stuck request failed on its own client timeout (%v) rather than the gateway's force-close", r.err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("stuck request never observed the exit")
		}
	})
}

// The binary healthcheck is the shipped container probe, so it is pinned
// against the real process in both phases: 0 while serving, 1 once draining.
func TestE2E_HealthcheckSubcommandTracksReadiness(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	const grace = 12 * time.Second
	socks := NewSocksSim(t, SocksOK, "", "")
	g := NewGatewayWithEnv(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}), "RPGW_SHUTDOWN_GRACE="+grace.String())

	if code := g.Healthcheck(); code != 0 {
		t.Fatalf("healthcheck subcommand = %d while serving, want 0", code)
	}
	g.Signal(syscall.SIGTERM)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if code, _ := g.AdminPath("/readyz"); code == http.StatusServiceUnavailable {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if code := g.Healthcheck(); code != 1 {
		t.Fatalf("healthcheck subcommand = %d on a draining process, want 1", code)
	}
	if code := g.Wait(); code != 0 {
		t.Fatalf("exit=%d, want graceful 0\nlogs:\n%s", code, g.Logs())
	}
}

// The signal contract must survive the readiness change: SIGHUP still never
// triggers a drain, and the process is still running afterwards.
func TestE2E_SIGHUPStillDoesNotDrain(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}))

	g.Signal(syscall.SIGHUP)
	g.Signal(syscall.SIGHUP)
	time.Sleep(500 * time.Millisecond)

	if code, _ := g.AdminPath("/readyz"); code != http.StatusOK {
		t.Fatalf("/readyz = %d after SIGHUP, want 200: SIGHUP must never start a drain", code)
	}
	if !reachable(t, g.MixedAddr) {
		t.Fatal("mixed listener stopped accepting after SIGHUP")
	}
	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/after-hup", "e2e-echo:/after-hup")
	if !strings.Contains(g.Logs(), "SIGHUP received; ignored") {
		t.Fatalf("no SIGHUP-ignored record\nlogs:\n%s", g.Logs())
	}
}

// The signal contract must survive the readiness head start as well: a
// repeated SIGTERM does not accelerate the drain. The process keeps every
// listener up through the head start and then exits on its own schedule, and a
// third signal changes nothing about that.
func TestE2E_SecondSigtermStillDoesNotKillTheProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	// A long grace so the head start is the full 5s and the budget behind it is
	// nowhere near exhausted: if a repeated SIGTERM were honoured as a kill, the
	// process would leave inside the head start instead.
	const grace = 30 * time.Second
	socks := NewSocksSim(t, SocksOK, "", "")
	g := NewGatewayWithEnv(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}), "RPGW_SHUTDOWN_GRACE="+grace.String())

	g.Signal(syscall.SIGTERM)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if code, _ := g.AdminPath("/readyz"); code == http.StatusServiceUnavailable {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Repeated signals during the head start must change nothing.
	for range 3 {
		g.Signal(syscall.SIGTERM)
		time.Sleep(100 * time.Millisecond)
	}
	for _, addr := range []string{g.AdminAddr, g.MixedAddr, g.V4Addr, g.V6Addr} {
		if !reachable(t, addr) {
			t.Fatalf("listener %s went away after a repeated SIGTERM inside the head start", addr)
		}
	}

	if code := g.Wait(); code != 0 {
		t.Fatalf("exit=%d, want graceful 0: a repeated SIGTERM must not turn into a kill\nlogs:\n%s", code, g.Logs())
	}
	if n := strings.Count(g.Logs(), `"msg":"shutting down"`); n != 1 {
		t.Fatalf("shutdown started %d times, want 1: a repeated SIGTERM must not begin a second drain\nlogs:\n%s", n, g.Logs())
	}
}
