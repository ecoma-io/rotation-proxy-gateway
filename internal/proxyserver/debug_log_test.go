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
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute)
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
	pl := pool.NewRoutes(mixedRoutes(fs.URL), 30*time.Second, time.Minute)
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
	}, time.Second, time.Minute)
	runtime := defaultRuntime()
	// The cap outlives the pickable routes: the v4 route fails and is
	// excluded, and the v6 route can never serve the v4-only listener, so the
	// chain ends with a nil pick -- true route exhaustion, logged no_route
	// with the retry budget still unspent.
	runtime.MaxRetries = 2
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

// When the retry budget ends the chain while eligible routes remain untried,
// the terminal record must say retry_exhausted, not no_route: no_route is
// reserved for the case where no eligible untried route remained. The client
// still receives the ordinary 05 01 general failure either way.
func TestRetryCapExhaustionLogsDistinctKind(t *testing.T) {
	// Three always-failing routes; the pool can supply a fresh one on every
	// attempt, so only the cap can stop the chain.
	routes := make([]config.RouteSpec, 0, 3)
	for range 3 {
		u, err := url.Parse("socks5://dead.test:1080")
		if err != nil {
			t.Fatal(err)
		}
		routes = append(routes, config.RouteSpec{URL: u, Kind: config.EgressV4})
	}
	pl := pool.NewRoutes(routes, time.Second, time.Minute)
	runtime := defaultRuntime()
	runtime.MaxRetries = 2
	var logs safeLogBuffer
	s := newRuntimeServer(pl, runtime, captureLogger(&logs), config.EgressV4)
	dials := 0
	s.dial = func(ctx context.Context, pu *url.URL, target socksdial.Target, timeout time.Duration) (net.Conn, error) {
		dials++
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
	if dials != runtime.MaxRetries {
		t.Fatalf("dials = %d, want the retry cap %d", dials, runtime.MaxRetries)
	}

	output := waitForRecord(t, &logs, map[string]string{"msg": "tunnel failed", "error_kind": "retry_exhausted"})
	if _, ok := findRecord(output, map[string]string{
		"msg": "tunnel failed", "error_kind": "retry_exhausted", "attempts": "2",
		"pool_size": "3", "kind_routes": "3", "excluded": "2",
	}); !ok {
		t.Fatalf("retry_exhausted record missing the pool/kind view:\n%s", output)
	}
	// Two eligible routes went untried: the record must not claim no_route.
	if _, ok := findRecord(output, map[string]string{"msg": "tunnel failed", "error_kind": "no_route"}); ok {
		t.Fatalf("retry-cap stop wrongly logged no_route:\n%s", output)
	}

	// Pool size equal to the cap: every route is tried, the cap ends the
	// chain — still retry_exhausted, never no_route, because the budget, not
	// a nil pick, stopped it.
	plEqual := pool.NewRoutes(routes[:2], time.Second, time.Minute)
	var logsEqual safeLogBuffer
	sEqual := newRuntimeServer(plEqual, runtime, captureLogger(&logsEqual), config.EgressV4)
	sEqual.dial = func(ctx context.Context, pu *url.URL, target socksdial.Target, timeout time.Duration) (net.Conn, error) {
		return nil, &socksdial.ProxyDialError{Err: errors.New("connect refused (TEST)")}
	}
	addrEqual := startServer(t, sEqual)
	connEqual := parkClient(t, addrEqual, "example.test:80")
	_ = connEqual.SetDeadline(time.Now().Add(5 * time.Second))
	replyEqual := make([]byte, 10)
	if _, err := io.ReadFull(connEqual, replyEqual); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if replyEqual[1] != socksReplyGeneral {
		t.Fatalf("replyEqual = 0x%02x, want general failure 0x01", replyEqual[1])
	}
	outputEqual := waitForRecord(t, &logsEqual, map[string]string{"msg": "tunnel failed", "error_kind": "retry_exhausted"})
	if _, ok := findRecord(outputEqual, map[string]string{
		"msg": "tunnel failed", "error_kind": "retry_exhausted", "attempts": "2",
		"pool_size": "2", "kind_routes": "2", "excluded": "2",
	}); !ok {
		t.Fatalf("pool==cap record missing retry_exhausted view:\n%s", outputEqual)
	}

	// True route exhaustion -- no eligible untried route remains -- still logs
	// no_route. One route, tried once and excluded: the second pick has nothing
	// left and ends the chain, with the cap (2) never reached.
	pl2 := pool.NewRoutes(routes[:1], time.Second, time.Minute)
	var logs2 safeLogBuffer
	s2 := newRuntimeServer(pl2, runtime, captureLogger(&logs2), config.EgressV4)
	s2.dial = func(ctx context.Context, pu *url.URL, target socksdial.Target, timeout time.Duration) (net.Conn, error) {
		return nil, &socksdial.ProxyDialError{Err: errors.New("connect refused (TEST)")}
	}
	addr2 := startServer(t, s2)
	conn2 := parkClient(t, addr2, "example.test:80")
	_ = conn2.SetDeadline(time.Now().Add(5 * time.Second))
	reply2 := make([]byte, 10)
	if _, err := io.ReadFull(conn2, reply2); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply2[1] != socksReplyGeneral {
		t.Fatalf("reply2 = 0x%02x, want general failure 0x01", reply2[1])
	}
	output2 := waitForRecord(t, &logs2, map[string]string{"msg": "tunnel failed", "error_kind": "no_route"})
	if _, ok := findRecord(output2, map[string]string{
		"msg": "tunnel failed", "error_kind": "no_route", "attempts": "1",
		"pool_size": "1", "kind_routes": "1", "excluded": "1",
	}); !ok {
		t.Fatalf("true-exhaustion record missing the no_route view:\n%s", output2)
	}
	if _, ok := findRecord(output2, map[string]string{"msg": "tunnel failed", "error_kind": "retry_exhausted"}); ok {
		t.Fatalf("true exhaustion wrongly logged retry_exhausted:\n%s", output2)
	}
}

// A listener that stops on a non-close accept error logs the reason at warn
// before returning it — the operator's only trace of why traffic stopped.
type failingListener struct{ err error }

func (l failingListener) Accept() (net.Conn, error) { return nil, l.err }
func (l failingListener) Close() error              { return nil }
func (l failingListener) Addr() net.Addr            { return &net.TCPAddr{} }

func TestServeLogsAndReturnsAcceptFailure(t *testing.T) {
	pl := pool.NewRoutes(mixedRoutes(mustTestURL(t, "socks5://u.test:1080")), time.Second, time.Minute)
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
	pl := pool.NewRoutes(mixedRoutes(mustTestURL(t, "socks5://u.test:1080")), time.Second, time.Minute)
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
	pl := pool.NewRoutes(mixedRoutes(mustTestURL(t, "socks5://u.test:1080")), time.Second, time.Minute)
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
