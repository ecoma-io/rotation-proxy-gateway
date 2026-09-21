package proxyserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/socksdial"
)

// A plain available pick logs one route-selected record per attempt carrying
// the attempt number and excluded count — and no cooldown field, which is
// reserved for the all-cooling fallback.
func TestRouteSelectedDebugCarriesAttemptShape(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute, config.KindBalance{})
	var logs safeLogBuffer
	_, addr := newSocksServer(t, pl, defaultRuntime(), captureLogger(&logs))

	conn := socksDialVia(t, addr, startRawEchoTarget(t))
	_ = conn.Close()

	output := waitForRecord(t, &logs, map[string]string{"msg": "tunnel"})
	rec, ok := findRecord(output, map[string]string{
		"msg": "route selected", "request_id": "1", "attempt": "1",
		"excluded": "0", "upstream": fs.URL.Host,
	})
	if !ok {
		t.Fatalf("logs missing the route-selected record:\n%s", output)
	}
	if _, has := rec["cooldown_remaining"]; has {
		t.Errorf("an available pick must not carry cooldown_remaining: %v", rec)
	}
}

// When every route is cooling, the pool still serves from the
// soonest-recovering fallback; the route-selected record must mark the pick
// with the cooldown the tunnel is betting against.
func TestRouteSelectedDebugMarksCoolingFallback(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), 30*time.Second, time.Minute, config.KindBalance{})
	var logs safeLogBuffer
	_, addr := newSocksServer(t, pl, defaultRuntime(), captureLogger(&logs))

	p := pl.PickFor(nil, nil, "t:443")
	if p == nil {
		t.Fatal("pick = nil, want the only route")
	}
	pl.ReportFailure(p, errors.New("dial refused (TEST)"))

	conn := socksDialVia(t, addr, startRawEchoTarget(t))
	_ = conn.Close()

	output := waitForRecord(t, &logs, map[string]string{"msg": "route selected", "attempt": "1"})
	rec, ok := findRecord(output, map[string]string{
		"msg": "route selected", "request_id": "1", "attempt": "1", "excluded": "0",
	})
	if !ok {
		t.Fatalf("logs missing the route-selected record:\n%s", output)
	}
	remaining, err := time.ParseDuration(fmt.Sprint(rec["cooldown_remaining"]))
	if err != nil || remaining <= 15*time.Second || remaining > 30*time.Second {
		t.Fatalf("cooldown_remaining = %v (err=%v), want (15s, 30s]", rec["cooldown_remaining"], err)
	}
}

// The no_route record must show whether the miss was the whole pool or just
// the listener's kind view: pool_size counts everything, kind_routes only
// what this listener could ever serve.
func TestNoRouteRecordShowsPoolAndKindView(t *testing.T) {
	u4, err := url.Parse("socks5://v4.test:1080")
	if err != nil {
		t.Fatal(err)
	}
	u6, err := url.Parse("socks5://v6.test:1080")
	if err != nil {
		t.Fatal(err)
	}
	pl := pool.NewRoutes([]config.RouteSpec{
		{URL: u4, Kind: config.EgressV4},
		{URL: u6, Kind: config.EgressV6},
	}, time.Second, time.Minute, config.KindBalance{})
	runtime := defaultRuntime()
	runtime.MaxRetries = 1
	var logs safeLogBuffer
	s := newRuntimeServer(pl, runtime, captureLogger(&logs), config.EgressV4)
	s.dial = func(context.Context, *url.URL, socksdial.Target, time.Duration) (net.Conn, error) {
		return nil, &socksdial.ProxyDialError{Err: errors.New("connect refused (TEST)")}
	}
	addr := startServer(t, s)

	conn := parkClient(t, addr, "example.test:80")
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}

	output := waitForRecord(t, &logs, map[string]string{"msg": "tunnel failed", "error_kind": "no_route"})
	if _, ok := findRecord(output, map[string]string{
		"msg": "tunnel failed", "error_kind": "no_route", "attempts": "1",
		"pool_size": "2", "kind_routes": "1", "excluded": "1",
	}); !ok {
		t.Fatalf("no_route record missing the pool/kind view:\n%s", output)
	}
}

// A listener that stops on a non-close accept error logs the reason at warn
// before returning it — the operator's only trace of why traffic stopped.
type failingListener struct{ err error }

func (l failingListener) Accept() (net.Conn, error) { return nil, l.err }
func (l failingListener) Close() error              { return nil }
func (l failingListener) Addr() net.Addr            { return &net.TCPAddr{} }

func TestServeLogsAndReturnsAcceptFailure(t *testing.T) {
	pl := pool.NewRoutes(mixedRoutes(mustTestURL(t, "socks5://u.test:1080")), time.Second, time.Minute, config.KindBalance{})
	var logs safeLogBuffer
	s := newRuntimeServer(pl, defaultRuntime(), captureLogger(&logs))

	acceptErr := errors.New("too many open files (TEST)")
	if err := s.Serve(failingListener{err: acceptErr}); !errors.Is(err, acceptErr) {
		t.Fatalf("Serve err = %v, want the accept error", err)
	}
	if _, ok := findRecord(logs.String(), map[string]string{
		"msg": "listener accept failed; stopping", "error": "too many open files (TEST)",
	}); !ok {
		t.Fatalf("logs missing the accept-failure record:\n%s", logs.String())
	}
}

func mustTestURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// A clean drain logs its milestone at debug; the record is what tells an
// operator the listener finished rather than hit the budget.
func TestShutdownLogsCleanDrainMilestone(t *testing.T) {
	pl := pool.NewRoutes(mixedRoutes(mustTestURL(t, "socks5://u.test:1080")), time.Second, time.Minute, config.KindBalance{})
	var logs safeLogBuffer
	s := newRuntimeServer(pl, defaultRuntime(), captureLogger(&logs))

	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("clean Shutdown = %v", err)
	}
	if _, ok := findRecord(logs.String(), map[string]string{"msg": "listener drained; all sessions finished"}); !ok {
		t.Fatalf("logs missing the drained milestone:\n%s", logs.String())
	}
}

// When the grace budget expires, Shutdown cancels pending dials, force-closes
// the tracked sockets, and — once the sessions unwind — logs that the
// force-close finished rather than leaving the tail outcome unrecorded.
func TestShutdownLogsForceCloseMilestone(t *testing.T) {
	pl := pool.NewRoutes(mixedRoutes(mustTestURL(t, "socks5://u.test:1080")), time.Second, time.Minute, config.KindBalance{})
	var logs safeLogBuffer
	s := newRuntimeServer(pl, defaultRuntime(), captureLogger(&logs))

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
	if err := s.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v, want DeadlineExceeded", err)
	}
	output := waitForRecord(t, &logs, map[string]string{"msg": "sessions finished after force-close"})
	if _, ok := findRecord(output, map[string]string{"msg": "sessions finished after force-close", "level": "debug"}); !ok {
		t.Fatalf("force-close milestone not at debug:\n%s", output)
	}
	_ = conn.Close()
}
