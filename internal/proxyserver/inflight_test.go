package proxyserver

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/socksdial"
)

// The in-flight hold is the pool's record of work that currently occupies a
// route — the thing a rotation drain waits for and /status reports. These tests
// pin the serving path's ownership of it: an attempt that fails before a tunnel
// exists releases its hold at the failure point, and only the route that really
// established the tunnel keeps one, for the tunnel's whole lifetime.

// deadRoute is a route whose endpoint never accepts; a test's dial seam answers
// it with the proxy_connect classification without touching the network.
func deadRoute(host string) *url.URL {
	return &url.URL{Scheme: "socks5", Host: host}
}

// failRouteSeam fails every dial aimed at dead and runs the rest through the
// real dial path, so one route fails while its peers keep serving.
func failRouteSeam(dead *url.URL) func(context.Context, *url.URL, socksdial.Target, time.Duration) (net.Conn, error) {
	return func(ctx context.Context, pu *url.URL, target socksdial.Target, timeout time.Duration) (net.Conn, error) {
		if pu.Host == dead.Host {
			return nil, &ProxyDialError{Err: errors.New("connect refused")}
		}
		return dialVia(ctx, pu, target, timeout)
	}
}

// hangDial parks one attempt inside the dial seam until the returned gate is
// closed, then fails it: a test can observe pool state while the retry chain is
// still running instead of only after the session has ended. Only routes whose
// host is parked hang; every other route dials normally.
func hangDial(t *testing.T, parked *url.URL) (func(context.Context, *url.URL, socksdial.Target, time.Duration) (net.Conn, error), func()) {
	gate := make(chan struct{})
	seam := func(ctx context.Context, pu *url.URL, target socksdial.Target, timeout time.Duration) (net.Conn, error) {
		if pu.Host != parked.Host {
			return dialVia(ctx, pu, target, timeout)
		}
		<-gate
		return nil, &ProxyDialError{Err: errors.New("parked attempt released")}
	}
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	t.Cleanup(release)
	return seam, release
}

// socksRequestNoReply performs the greeting and sends one CONNECT without
// reading the reply, for tests that must inspect the gateway while the retry
// chain is still running.
func socksRequestNoReply(t *testing.T, gatewayAddr, target string) net.Conn {
	t.Helper()
	frame, err := socksRequestFrame(socksCmdConnect, target)
	if err != nil {
		t.Fatalf("encode request for %s: %v", target, err)
	}
	conn, err := net.Dial("tcp", gatewayAddr)
	if err != nil {
		t.Fatalf("dial gateway %s: %v", gatewayAddr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(socksGreetingFrame(socksAuthNone)); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if method[0] != socksVersion || method[1] != socksAuthNone {
		t.Fatalf("method selection = %#02x %#02x, want 05 00", method[0], method[1])
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write request: %v", err)
	}
	return conn
}

// readSocksReplyCode consumes the gateway's 10-byte CONNECT reply and returns
// its reply code.
func readSocksReplyCode(t *testing.T, conn net.Conn) byte {
	t.Helper()
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read SOCKS reply: %v", err)
	}
	if reply[0] != socksVersion {
		t.Fatalf("reply version = %#02x, want 05", reply[0])
	}
	return reply[1]
}

// waitInFlight polls until p reports exactly want in-flight holds: establishing
// and tearing down a tunnel are asynchronous with respect to the client.
func waitInFlight(t *testing.T, p *pool.Proxy, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		if got := p.InFlight(); got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("in-flight = %d, want %d", p.InFlight(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

// The central regression: a pick that fails before any tunnel exists drops its
// hold immediately, so a later route's long-lived tunnel is the only work the
// pool reports as held.
func TestFailedAttemptReleasesInFlightHoldBeforeAnyTunnelExists(t *testing.T) {
	dead := deadRoute("dead.test:1080")
	good := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(dead, good.URL), time.Second, time.Minute)
	s := newRuntimeServer(pl, defaultRuntime(), testLogger())
	s.dial = failRouteSeam(dead)
	addr := startServer(t, s)
	failed, held := pl.RoutePointers()[0], pl.RoutePointers()[1]

	conn := socksDialVia(t, addr, startRawEchoTarget(t))
	if got := readBanner(t, conn); got != "banner\n" {
		t.Fatalf("banner = %q", got)
	}

	// The tunnel is open on the fallback route and the failed attempt is over:
	// its hold must be gone already, not parked until the session ends.
	if got := failed.InFlight(); got != 0 {
		t.Fatalf("failed route in-flight = %d, want 0 while the tunnel is open on another route", got)
	}
	if got := held.InFlight(); got != 1 {
		t.Fatalf("holding route in-flight = %d, want 1", got)
	}
	// /status reads the same counter the drain does: the cooling failed route
	// is unavailable, and it holds nothing.
	failedSnap := pl.Snapshot()[0]
	if failedSnap.InFlight != 0 || failedSnap.Failures != 1 {
		t.Fatalf("failed route status = %+v, want one dial failure and no hold", failedSnap)
	}

	_ = conn.Close()
	waitInFlight(t, held, 0)
	if got := failed.InFlight(); got != 0 {
		t.Fatalf("failed route in-flight after the tunnel ended = %d, want 0", got)
	}
}

// Every route failing is terminal: the chain ends on the empty pick, each
// attempted route has already released its own hold, and the client's
// general-failure reply is written after those releases.
func TestEveryRouteFailingReleasesEachHold(t *testing.T) {
	first, second := deadRoute("dead-one.test:1080"), deadRoute("dead-two.test:1080")
	pl := pool.NewRoutes(mixedRoutes(first, second), time.Second, time.Minute)
	s := newRuntimeServer(pl, defaultRuntime(), testLogger())
	s.dial = func(context.Context, *url.URL, socksdial.Target, time.Duration) (net.Conn, error) {
		return nil, &ProxyDialError{Err: errors.New("connect refused")}
	}
	addr := startServer(t, s)

	conn, code := socksConnectReply(t, addr, "example.test:443", socksCmdConnect)
	_ = conn.Close()
	if code != socksReplyGeneral {
		t.Fatalf("reply = 0x%02x, want general failure 0x01", code)
	}
	for _, route := range pl.RoutePointers() {
		if got := route.InFlight(); got != 0 {
			t.Fatalf("route %s in-flight = %d after every attempt failed, want 0", route.URL.Host, got)
		}
	}
	for _, snap := range pl.Snapshot() {
		if snap.InFlight != 0 {
			t.Fatalf("status in-flight for %s = %d, want 0", snap.Proxy, snap.InFlight)
		}
	}
	if status := s.ListenerStatus(); status.Requests != 1 || status.Failovers != 2 {
		t.Fatalf("listener status = %+v, want 1 request and 2 fallbacks", status)
	}
}

// A route that refuses the target itself (non-zero CONNECT reply) never
// established anything, so its hold is gone while the next attempt is still
// running — the fallback attempt is parked to prove it. The refusal stays
// pair-scoped: one cooled pair, no route-level failure.
func TestConnectTargetRefusalReleasesTheHold(t *testing.T) {
	refusing := startSocks5Proxy(t, socksOptions{connectRep: 0x05})
	parked := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(refusing.URL, parked.URL), time.Second, time.Minute)
	var logs safeLogBuffer
	s := newRuntimeServer(pl, defaultRuntime(), captureLogger(&logs))
	seam, release := hangDial(t, parked.URL)
	s.dial = seam
	addr := startServer(t, s)
	route := pl.RoutePointers()[0]

	conn := socksRequestNoReply(t, addr, "blocked.test:443")
	waitForRecord(t, &logs, map[string]string{"msg": "upstream refused connect target"})

	if got := route.InFlight(); got != 0 {
		t.Fatalf("refusing route in-flight = %d while the retry chain is running, want 0", got)
	}
	snap := pl.Snapshot()[0]
	if snap.InFlight != 0 || snap.TargetFailures != 1 || snap.Failures != 0 {
		t.Fatalf("pair-scoped refusal state = %+v, want one cooled pair and no hold", snap)
	}

	release()
	if code := readSocksReplyCode(t, conn); code != socksReplyGeneral {
		t.Fatalf("reply = 0x%02x, want general failure 0x01", code)
	}
	if got := route.InFlight(); got != 0 {
		t.Fatalf("refusing route in-flight after the chain ended = %d, want 0", got)
	}
	if got := len(parked.hits); got != 0 {
		t.Fatalf("parked endpoint was reached %d times, want 0", got)
	}
}

// A SOCKS handshake failure before the tunnel exists is the same story: the
// route is cooled and excluded, and its hold is dropped with it rather than
// carried into the next attempt.
func TestSocksHandshakeFailureReleasesTheHold(t *testing.T) {
	failing := startSocks5Proxy(t, socksOptions{connectRaw: []byte{0x05, 0x00, 0x00, 0x06}})
	parked := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(failing.URL, parked.URL), time.Second, time.Minute)
	var logs safeLogBuffer
	s := newRuntimeServer(pl, defaultRuntime(), captureLogger(&logs))
	seam, release := hangDial(t, parked.URL)
	s.dial = seam
	addr := startServer(t, s)
	route := pl.RoutePointers()[0]

	conn := socksRequestNoReply(t, addr, "example.test:443")
	waitForRecord(t, &logs, map[string]string{"msg": "upstream handshake failed"})

	if got := route.InFlight(); got != 0 {
		t.Fatalf("handshake-failing route in-flight = %d while the retry chain is running, want 0", got)
	}
	snap := pl.Snapshot()[0]
	if snap.InFlight != 0 || snap.Failures != 1 || snap.AuthFailures != 0 {
		t.Fatalf("handshake-failure state = %+v, want one dial failure and no hold", snap)
	}

	release()
	if code := readSocksReplyCode(t, conn); code != socksReplyGeneral {
		t.Fatalf("reply = 0x%02x, want general failure 0x01", code)
	}
	if got := route.InFlight(); got != 0 {
		t.Fatalf("handshake-failing route in-flight after the chain ended = %d, want 0", got)
	}
}

// An auth-blocked route is excluded without dial cooldown and, like every other
// pre-tunnel failure, holds nothing while the fallback route serves the tunnel.
func TestAuthRouteFailureReleasesTheHold(t *testing.T) {
	bad := startSocks5Proxy(t, socksOptions{user: "TEST-user", pass: "TEST-pass"})
	good := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(bad.URL, good.URL), time.Second, time.Minute)
	_, addr := newSocksServer(t, pl, defaultRuntime(), testLogger())
	blocked, held := pl.RoutePointers()[0], pl.RoutePointers()[1]

	conn := socksDialVia(t, addr, startRawEchoTarget(t))
	readBanner(t, conn)

	if got := blocked.InFlight(); got != 0 {
		t.Fatalf("auth-blocked route in-flight = %d, want 0", got)
	}
	if got := held.InFlight(); got != 1 {
		t.Fatalf("holding route in-flight = %d, want 1", got)
	}
	if snap := pl.Snapshot()[0]; snap.InFlight != 0 || !snap.AuthBlocked || snap.AuthFailures != 1 {
		t.Fatalf("auth-blocked route state = %+v, want a blocked route holding nothing", snap)
	}

	_ = conn.Close()
	waitInFlight(t, held, 0)
}

// A warm borrow that dies at the transport level falls through to a cold dial
// inside the same attempt: the pick happened once, so the tunnel lifetime gets
// exactly one hold — the dead borrow must not leak a second one.
func TestDeadWarmBorrowKeepsOneHoldForTheTunnelLifetime(t *testing.T) {
	good := startSocks5Proxy(t, socksOptions{})
	hc, err := socksdial.DialHalf(context.Background(), parkThenDie(t), 2*time.Second)
	if err != nil {
		t.Fatalf("DialHalf: %v", err)
	}
	warm := &stubWarm{queue: []*socksdial.HalfConn{hc}}
	pl := pool.NewRoutes(mixedRoutes(good.URL), time.Second, time.Minute)
	s := newRuntimeServer(pl, defaultRuntime(), testLogger())
	s.warm = warm
	addr := startServer(t, s)
	route := pl.RoutePointers()[0]

	conn := socksDialVia(t, addr, startRawEchoTarget(t))
	readBanner(t, conn)

	if got := route.InFlight(); got != 1 {
		t.Fatalf("in-flight after a dead borrow plus cold dial = %d, want exactly 1", got)
	}
	if b, d := warm.counts(); b != 1 || d != 1 {
		t.Fatalf("borrowed=%d discarded=%d, want the dead borrow used and its siblings dropped", b, d)
	}

	_ = conn.Close()
	waitInFlight(t, route, 0)
}

// One hold per live tunnel on a shared route: N concurrent tunnels report N and
// the count falls back one tunnel at a time.
func TestConcurrentTunnelsHoldOneEach(t *testing.T) {
	good := startSocks5Proxy(t, socksOptions{})
	target := startRawEchoTarget(t)
	pl := pool.NewRoutes(mixedRoutes(good.URL), time.Second, time.Minute)
	_, addr := newSocksServer(t, pl, defaultRuntime(), testLogger())
	route := pl.RoutePointers()[0]

	const tunnels = 3
	conns := make([]net.Conn, 0, tunnels)
	for range tunnels {
		conn := socksDialVia(t, addr, target)
		if got := readBanner(t, conn); got != "banner\n" {
			t.Fatalf("banner = %q", got)
		}
		conns = append(conns, conn)
	}
	if got := route.InFlight(); got != tunnels {
		t.Fatalf("in-flight with %d live tunnels = %d, want %d", tunnels, got, tunnels)
	}

	_ = conns[0].Close()
	waitInFlight(t, route, tunnels-1)
	for _, conn := range conns[1:] {
		_ = conn.Close()
	}
	waitInFlight(t, route, 0)
}

// The first pick succeeding is the plain case the invariant exists for: the hold
// outlives the relay and is released when the handler exits, after the close
// record, with no second attempt ever made.
func TestFirstPickHoldsUntilTheHandlerExits(t *testing.T) {
	good := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(good.URL), time.Second, time.Minute)
	var logs safeLogBuffer
	_, addr := newSocksServer(t, pl, defaultRuntime(), captureLogger(&logs))
	route := pl.RoutePointers()[0]

	conn := socksDialVia(t, addr, startRawEchoTarget(t))
	readBanner(t, conn)
	if got := route.InFlight(); got != 1 {
		t.Fatalf("in-flight on the serving route = %d, want 1", got)
	}

	_ = conn.Close()
	waitInFlight(t, route, 0)
	output := waitForRecord(t, &logs, map[string]string{"msg": "tunnel closed"})
	if _, ok := findRecord(output, map[string]string{"msg": "tunnel", "attempts": "1"}); !ok {
		t.Errorf("logs missing the first-attempt tunnel record:\n%s", output)
	}
}
