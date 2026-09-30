package proxyserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
)

// --- relay teardown and close records --------------------------------------

// A client that ends the stream first produces a routine close record at debug
// with both byte counts, and never touches route health.
func TestCloseRecordAfterClientCloses(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), 30*time.Second, time.Minute)
	var logs safeLogBuffer
	s, addr := newProxyServer(t, pl, defaultRuntime(), captureLogger(&logs))

	conn := httpDialVia(t, addr, startRawEchoTarget(t))
	if got := readBanner(t, conn); got != "banner\n" {
		t.Fatalf("banner = %q", got)
	}
	if _, err := conn.Write([]byte("abcd")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	echo := make([]byte, 4)
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	_ = conn.Close()

	output := waitForRecord(t, &logs, map[string]string{"msg": "tunnel closed"})
	rec, ok := findRecord(output, map[string]string{
		"msg":                      "tunnel closed",
		"close_reason":             "client_closed",
		"client_to_upstream_bytes": "4",
		"upstream_to_client_bytes": "11", // banner plus echo
	})
	if !ok {
		t.Errorf("close record missing expected fields:\n%s", output)
	} else if _, has := rec["duration"]; !has {
		t.Errorf("close record missing duration: %v", rec)
	}
	snap := pl.Snapshot()[0]
	if snap.Successes != 1 || snap.Failures != 0 || snap.AuthFailures != 0 {
		t.Fatalf("closing the tunnel mutated route health: %+v", snap)
	}
	if status := s.ListenerStatus(); status.Requests != 1 {
		t.Fatalf("listener status = %+v", status)
	}
}

// An upstream that ends the tunnel abnormally logs a broken-tunnel close at
// warn and resets the client side, so a truncated stream stays truncated.
func TestUpstreamBreakLogsBrokenCloseAndResetsClient(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), 30*time.Second, time.Minute)
	var logs safeLogBuffer
	_, addr := newProxyServer(t, pl, defaultRuntime(), captureLogger(&logs))

	conn := httpDialVia(t, addr, startAbortTarget(t))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(io.Discard, conn); err == nil {
		t.Fatal("tunnel stayed open after the target aborted the stream")
	}

	output := waitForRecord(t, &logs, map[string]string{"msg": "tunnel broken"})
	rec, ok := findRecord(output, map[string]string{
		"msg": "tunnel broken", "close_reason": "upstream_broken",
	})
	if _, ok := findRecord(output, map[string]string{
		"msg": "upstream broke the tunnel; client side set to reset on close",
	}); !ok {
		t.Errorf("logs missing the SetLinger debug record:\n%s", output)
	}
	if !ok {
		t.Errorf("logs missing the broken close record:\n%s", output)
	} else {
		for _, key := range []string{"client_to_upstream_bytes", "upstream_to_client_bytes", "duration", "error"} {
			if _, has := rec[key]; !has {
				t.Errorf("broken close record missing %q: %v", key, rec)
			}
		}
	}
	snap := pl.Snapshot()[0]
	if snap.Successes != 1 || snap.Failures != 0 || snap.AuthFailures != 0 {
		t.Fatalf("broken tunnel mutated route health: %+v", snap)
	}
}

// --- connection tracking and shutdown --------------------------------------

// waitTrackedConns waits until the server has accepted and started tracking
// want client sessions. Only pre-request sessions need this: a tunnel is
// tracked before its success reply reaches the client.
func waitTrackedConns(t *testing.T, s *Server, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		s.cmu.Lock()
		got := len(s.conns)
		s.cmu.Unlock()
		if got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("tracked sessions = %d, want %d", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// CloseConns must close both established tunnels and sessions still inside
// their request exchange.
func TestCloseConnsClosesTunnelsAndRequests(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), 30*time.Second, time.Minute)
	s, addr := newProxyServer(t, pl, defaultRuntime(), testLogger())

	tunnel := httpDialVia(t, addr, startParkedTarget(t))
	// A session that connected but never sent a request is still tracked and
	// still holding a handshake deadline.
	parked := dialGateway(t, addr)
	waitTrackedConns(t, s, 2)

	if closed := s.CloseConns(); closed != 2 {
		t.Errorf("CloseConns() = %d, want both tracked sessions", closed)
	}
	for name, conn := range map[string]net.Conn{"tunnel": tunnel, "unanswered request": parked} {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Errorf("%s connection stayed open after CloseConns", name)
		}
	}
}

// blockingCloseConn delays Close until released, so a test can observe whether
// the connection map stays locked while a Close blocks.
type blockingCloseConn struct {
	net.Conn
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *blockingCloseConn) Close() error {
	c.once.Do(func() { close(c.started) })
	<-c.release
	return c.Conn.Close()
}

func TestCloseConnsDoesNotHoldConnectionMapLockWhileClosing(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer func() { _ = clientSide.Close() }()
	conn := &blockingCloseConn{
		Conn:    serverSide,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	s := newRuntimeServer(pool.NewRoutes(nil, time.Second, time.Minute), defaultRuntime(), testLogger())
	if !s.beginSession(conn) {
		t.Fatal("beginSession refused a connection on a live server")
	}

	closed := make(chan struct{})
	go func() {
		s.CloseConns()
		close(closed)
	}()
	select {
	case <-conn.started:
	case <-time.After(time.Second):
		t.Fatal("CloseConns did not call connection Close")
	}

	untracked := make(chan struct{})
	go func() {
		s.untrackConn(conn)
		close(untracked)
	}()
	select {
	case <-untracked:
	case <-time.After(time.Second):
		t.Fatal("connection map lock remained held while Close blocked")
	}

	close(conn.release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("CloseConns did not return after Close unblocked")
	}
}

func TestShutdownWithNoSessionsReturnsNil(t *testing.T) {
	s := newRuntimeServer(pool.NewRoutes(nil, time.Second, time.Minute), defaultRuntime(), testLogger())
	done := make(chan error, 1)
	go func() { done <- s.Shutdown(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Shutdown = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Shutdown blocked with no live sessions")
	}
}

// Shutdown waits for a live session instead of tearing it down early. The
// target ends only when the client does (a pure parked target would now hold
// the half-closed relay open indefinitely, which is the relay contract, not a
// drain defect).
func TestShutdownWaitsForActiveSession(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), 30*time.Second, time.Minute)
	s, addr := newProxyServer(t, pl, defaultRuntime(), testLogger())

	tunnel := httpDialVia(t, addr, startHalfCloseTarget(t, 0, ""))
	done := make(chan error, 1)
	go func() { done <- s.Shutdown(context.Background()) }()
	select {
	case err := <-done:
		t.Fatalf("Shutdown returned %v while a session was live", err)
	case <-time.After(100 * time.Millisecond):
	}
	_ = tunnel.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Shutdown = %v, want nil after the session drained", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not return after the session closed")
	}
}

// A drain that outlives its budget force-closes the tracked client conns and
// reports the deadline.
func TestShutdownDeadlineForceClosesActiveSession(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute)
	s, addr := newProxyServer(t, pl, defaultRuntime(), testLogger())

	tunnel := httpDialVia(t, addr, startParkedTarget(t))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := s.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v, want the context deadline", err)
	}
	_ = tunnel.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := tunnel.Read(make([]byte, 1)); err == nil {
		t.Fatal("tunnel stayed open after the shutdown deadline force-closed it")
	}
}

// --- admin -----------------------------------------------------------------

// requests counts only valid proxy requests (protocol rejects never advance it)
// and failovers counts in-band route fallbacks.
func TestAdminStatusCountsRequestsAndFallbacks(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := &url.URL{Scheme: "socks5", Host: closed.Addr().String()}
	_ = closed.Close()
	good := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(dead, good.URL), 30*time.Second, time.Minute)
	s := NewRuntime(pool.NewStore(defaultRuntime(), pl), testLogger(), "9.9.9-test", "mixed", config.EgressV4, config.EgressV6)
	addr := startServer(t, s)
	admin := httptest.NewServer(s.AdminMux())
	defer admin.Close()

	// A protocol reject must not move any counter.
	if got := httpRejectExchange(t, addr, httpRejectCase{request: []byte("NOT-A-REQUEST\r\n\r\n")}); got != http.StatusBadRequest {
		t.Fatalf("reject status = %d, want 400", got)
	}
	conn := httpDialVia(t, addr, startRawEchoTarget(t))
	readBanner(t, conn)
	_ = conn.Close()

	hresp, err := http.Get(admin.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	hbody, _ := io.ReadAll(hresp.Body)
	_ = hresp.Body.Close()
	if hresp.StatusCode != http.StatusOK || string(hbody) != "ok\n" {
		t.Fatalf("healthz status=%d body=%q", hresp.StatusCode, hbody)
	}

	sresp, err := http.Get(admin.URL + "/status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	defer func() { _ = sresp.Body.Close() }()
	if sresp.StatusCode != http.StatusOK {
		t.Fatalf("status code=%d", sresp.StatusCode)
	}
	var got struct {
		Version   string                    `json:"version"`
		Requests  uint64                    `json:"requests"`
		Failovers uint64                    `json:"failovers"`
		Listeners map[string]ListenerStatus `json:"listeners"`
		Pool      []pool.Status             `json:"pool"`
	}
	if err := json.NewDecoder(sresp.Body).Decode(&got); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if got.Version != "9.9.9-test" {
		t.Errorf("version = %q", got.Version)
	}
	if got.Requests != 1 || got.Failovers != 1 {
		t.Errorf("totals = %+v, want one request and one fallback", got)
	}
	if want := (ListenerStatus{Requests: 1, Failovers: 1}); got.Listeners["mixed"] != want {
		t.Errorf("listeners = %+v, want %+v", got.Listeners, want)
	}
	if len(got.Pool) != 2 {
		t.Fatalf("pool len = %d, want 2", len(got.Pool))
	}
	if got.Pool[0].Failures != 1 || got.Pool[1].Successes != 1 {
		t.Errorf("pool health = %+v", got.Pool)
	}
}

func TestDialTCPCancellationIsNotEndpointFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := dialTCP(ctx, "127.0.0.1:1", time.Second)
	if !errors.Is(err, context.Canceled) || isProxyDialError(err) {
		t.Fatalf("dialTCP cancellation = %T %v, want plain context cancellation", err, err)
	}
}
