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

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
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
	s.dial = func(ctx context.Context, _ *url.URL, _ string, _ time.Duration) (net.Conn, error) {
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
