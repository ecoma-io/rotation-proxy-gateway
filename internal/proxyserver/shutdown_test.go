package proxyserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/socksdial"
)

// parkClient connects to the gateway, completes the greeting, sends one
// CONNECT, and returns without reading a reply — the session is now parked
// wherever the server's dial seam puts it. The caller owns closing.
func parkClient(t *testing.T, addr, target string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
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
	frame, err := socksRequestFrame(socksCmdConnect, target)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write request: %v", err)
	}
	return conn
}

// When the grace budget expires, Shutdown must cancel upstream dials still in
// flight: the session unwinds through the canceled dial — classified as a
// local setup failure that never mutates route health — instead of hanging
// until its dial timeout, and the client socket is force-closed.
func TestShutdownCancelsPendingUpstreamDial(t *testing.T) {
	u, err := url.Parse("socks5://u.test:1080")
	if err != nil {
		t.Fatal(err)
	}
	pl := pool.NewRoutes([]config.RouteSpec{{URL: u, Kind: config.EgressV4}}, time.Second, time.Minute, config.KindBalance{})
	s := newRuntimeServer(pl, defaultRuntime(), testLogger())

	dialStarted := make(chan struct{})
	s.dial = func(ctx context.Context, _ *url.URL, _ socksdial.Target, _ time.Duration) (net.Conn, error) {
		close(dialStarted)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	addr := startServer(t, s)
	conn := parkClient(t, addr, "example.test:80")

	select {
	case <-dialStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream dial never started")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	shutdownErr := s.Shutdown(ctx)
	elapsed := time.Since(start)
	if !errors.Is(shutdownErr, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v, want DeadlineExceeded", shutdownErr)
	}
	// The canceled dial returned the session promptly, so Shutdown must not
	// have burned the full force-close tail on a wedged handler.
	if elapsed >= forceCloseWait {
		t.Fatalf("Shutdown took %s; the canceled dial did not unwind the session", elapsed)
	}

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("client connection survived the grace expiry force-close")
	}

	snap := pl.Snapshot()[0]
	if snap.Failures != 0 || snap.ConsecutiveFailures != 0 || !snap.Available {
		t.Fatalf("shutdown cancellation mutated route health: %+v", snap)
	}
}

// After Shutdown has run, new sessions are refused: beginSession is the one
// critical section guarding admission against the drain, and its refusal is
// what lets Serve close late connections instead of counting them into a
// drain that already swept.
func TestBeginSessionRefusedAfterShutdown(t *testing.T) {
	s := newRuntimeServer(pool.NewRoutes(nil, time.Second, time.Minute, config.KindBalance{}), defaultRuntime(), testLogger())
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown on an idle server = %v, want nil", err)
	}
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close(); _ = c2.Close() }()
	if s.beginSession(c1) {
		t.Fatal("beginSession admitted a connection after shutdown")
	}
}

// The admission/drain pairing must hold under churn: sessions racing a
// concurrent Shutdown either get counted and drained or are refused — never
// served uncounted, which would hang the drain forever. Fifty rounds under
// the race detector watch for that desync as a hang or a counter panic.
func TestBeginSessionShutdownRace(t *testing.T) {
	for range 50 {
		s := newRuntimeServer(pool.NewRoutes(nil, time.Second, time.Minute, config.KindBalance{}), defaultRuntime(), testLogger())
		const sessionCount = 8
		start := make(chan struct{})
		parked := make(chan net.Conn, sessionCount)
		var sessions sync.WaitGroup
		for range sessionCount {
			sessions.Add(1)
			go func() {
				defer sessions.Done()
				<-start
				c1, c2 := net.Pipe()
				if !s.beginSession(c1) {
					_ = c1.Close()
					_ = c2.Close()
					return
				}
				parked <- c2
				defer func() {
					s.untrackConn(c1)
					s.live.Done()
					_ = c1.Close()
				}()
				// Park like a live session; unblocks when Shutdown's
				// force-close closes c1.
				_, _ = io.Copy(io.Discard, c1)
			}()
		}
		close(start)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		errCh := make(chan error, 1)
		go func() { errCh <- s.Shutdown(ctx) }()
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Shutdown = %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Shutdown hung under session churn; a session escaped its drain count")
		}
		sessions.Wait()
		for len(parked) > 0 {
			_ = (<-parked).Close()
		}
	}
}

// A failure on the final attempt is terminal, not a fallback: the failover
// counter must only count real handoffs to another attempt.
func TestLastAttemptFailureIsNotAFailover(t *testing.T) {
	u, err := url.Parse("socks5://u.test:1080")
	if err != nil {
		t.Fatal(err)
	}
	pl := pool.NewRoutes([]config.RouteSpec{{URL: u, Kind: config.EgressV4}}, time.Second, time.Minute, config.KindBalance{})
	runtime := defaultRuntime()
	runtime.MaxRetries = 1
	var logs safeLogBuffer
	s := newRuntimeServer(pl, runtime, captureLogger(&logs))
	dials := make(chan struct{}, 4)
	s.dial = func(ctx context.Context, pu *url.URL, target socksdial.Target, timeout time.Duration) (net.Conn, error) {
		dials <- struct{}{}
		return nil, &socksdial.ProxyDialError{Err: errors.New("connect refused (TEST)")}
	}
	addr := startServer(t, s)

	conn := parkClient(t, addr, "example.test:80")
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != socksReplyGeneral {
		t.Fatalf("reply = 0x%02x, want general failure 0x01", reply[1])
	}
	if status := s.ListenerStatus(); status.Requests != 1 || status.Failovers != 0 {
		t.Fatalf("listener status = %+v, want the single failed attempt not counted as a fallback", status)
	}
	// The reply can reach the client before the session goroutine flushes its
	// closing log record, so poll instead of asserting immediately.
	waitForRecord(t, &logs, map[string]string{"msg": "tunnel failed", "error_kind": "no_route", "attempts": "1",
		"pool_size": "1", "kind_routes": "1", "excluded": "1"})
}

// A retry chain that outlives the inbound handshake window must stop before
// dialing again: the vanished client cannot be answered, so no further route
// health is spent on it.
func TestServeTunnelStopsRetryingAfterHandshakeDeadline(t *testing.T) {
	u, err := url.Parse("socks5://u.test:1080")
	if err != nil {
		t.Fatal(err)
	}
	pl := pool.NewRoutes([]config.RouteSpec{{URL: u, Kind: config.EgressV4}}, time.Second, time.Minute, config.KindBalance{})
	runtime := defaultRuntime()
	runtime.MaxRetries = 3
	var logs safeLogBuffer
	s := newRuntimeServer(pl, runtime, captureLogger(&logs))
	dials := make(chan struct{}, 4)
	s.dial = func(ctx context.Context, pu *url.URL, target socksdial.Target, timeout time.Duration) (net.Conn, error) {
		dials <- struct{}{}
		return nil, &socksdial.ProxyDialError{Err: errors.New("connect refused (TEST)")}
	}

	client, server := net.Pipe()
	defer func() { _ = client.Close(); _ = server.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.serveTunnel(server, socksdial.Target{Host: "example.test", Port: 80, Type: socksdial.AddrDomain}, time.Now().Add(-time.Second), captureLogger(&logs))
	}()
	// Drain the general-failure reply the cut chain writes to the client;
	// a synchronous pipe would otherwise block the handler forever.
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read cut-chain reply: %v", err)
	}
	if reply[1] != socksReplyGeneral {
		t.Fatalf("cut-chain reply = 0x%02x, want general failure 0x01", reply[1])
	}

	select {
	case <-dials:
	case <-time.After(2 * time.Second):
		t.Fatal("first attempt never dialed")
	}
	// The first failure is in-band, but the expired handshake window must cut
	// the chain before attempt two.
	select {
	case <-dials:
		t.Fatal("second attempt dialed after the handshake deadline expired")
	default:
	}
	snap := pl.Snapshot()[0]
	if snap.Failures != 1 {
		t.Fatalf("route failures = %d, want exactly the first attempt's", snap.Failures)
	}
	// The in-band fallback to attempt two was decided before the deadline cut
	// it, so it counts; the cut only means the handed-off attempt never ran.
	if status := s.ListenerStatus(); status.Failovers != 1 {
		t.Fatalf("failovers = %d, want 1 for the in-band handoff the deadline cut", status.Failovers)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveTunnel did not return after cutting the chain")
	}
	waitForRecord(t, &logs, map[string]string{"msg": "inbound handshake deadline expired before the next attempt", "error_kind": "setup"})
}

// Close-record classification when both relay directions fail: an upstream
// reset behind a client-side failure must surface as a broken tunnel (warn),
// while the artifact error of our own teardown close must not change a clean
// classification.
func TestRecordTunnelCloseBothDirectionsFailed(t *testing.T) {
	realReset := errors.New("read: connection reset by peer")
	for _, tc := range []struct {
		name          string
		first, second relayResult
		wantMsg       string
		wantReason    string
		wantLevel     string
		wantErrSubstr string
	}{
		{
			// Client-side failure first, upstream reset behind it: the
			// upstream break is the deeper cause.
			name:    "upstream reset behind client failure",
			first:   relayResult{direction: relayToUpstream, err: errors.New("write: broken pipe")},
			second:  relayResult{direction: relayToClient, err: realReset},
			wantMsg: "tunnel broken", wantReason: "upstream_broken", wantLevel: "warn",
			wantErrSubstr: "connection reset",
		},
		{
			// Client-side failure first; the other direction only failed
			// because we closed it. Clean client abort.
			name:    "teardown artifact stays a client abort",
			first:   relayResult{direction: relayToUpstream, err: errors.New("write: broken pipe")},
			second:  relayResult{direction: relayToClient, err: net.ErrClosed},
			wantMsg: "tunnel closed", wantReason: "client_aborted", wantLevel: "debug",
			wantErrSubstr: "broken pipe",
		},
		{
			// Upstream direction failing first stays the classic broken case.
			name:    "upstream broke first",
			first:   relayResult{direction: relayToClient, err: realReset},
			second:  relayResult{direction: relayToUpstream, err: net.ErrClosed},
			wantMsg: "tunnel broken", wantReason: "upstream_broken", wantLevel: "warn",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs safeLogBuffer
			recordTunnelClose(captureLogger(&logs), "example.test:80", nil, time.Now(), tc.first, tc.second)
			rec, ok := findRecord(logs.String(), map[string]string{"msg": tc.wantMsg, "close_reason": tc.wantReason})
			if !ok {
				t.Fatalf("records missing %s/%s:\n%s", tc.wantMsg, tc.wantReason, logs.String())
			}
			if rec["level"] != tc.wantLevel {
				t.Fatalf("level = %v, want %s", rec["level"], tc.wantLevel)
			}
			if tc.wantErrSubstr != "" && !strings.Contains(fmt.Sprint(rec["error"]), tc.wantErrSubstr) {
				t.Fatalf("error = %v, want it to name %q", rec["error"], tc.wantErrSubstr)
			}
		})
	}
}
