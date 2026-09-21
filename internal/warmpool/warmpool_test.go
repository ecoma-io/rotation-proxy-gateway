package warmpool

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/socksdial"
)

// The tests drive the pool's state machine synchronously — sweep() plus a
// claim/drain loop — so behavior is pinned without ticker timing; one test
// additionally exercises the real Start/Stop goroutine flow.

// halfServer is the far end of a warm half connection: it completes the
// SOCKS5 greeting and parks the connection open. mode "refuse" closes on
// accept (dead endpoint), "authreject" negotiates username/password and
// rejects it, "ok" parks.
type halfServer struct {
	addr   string
	parked atomic.Int64
}

func newHalfServer(t *testing.T, mode string) *halfServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &halfServer{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn, mode)
		}
	}()
	return s
}

func (s *halfServer) handle(conn net.Conn, mode string) {
	if mode == "refuse" {
		_ = conn.Close()
		return
	}
	br := bufio.NewReader(conn)
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		_ = conn.Close()
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		_ = conn.Close()
		return
	}
	offersAuth := false
	for _, m := range methods {
		if m == 0x02 {
			offersAuth = true
		}
	}
	if mode == "authreject" {
		if !offersAuth {
			_, _ = conn.Write([]byte{0x05, 0xff})
			_ = conn.Close()
			return
		}
		if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
			_ = conn.Close()
			return
		}
		hdr := make([]byte, 2) // VER ULEN
		if _, err := io.ReadFull(br, hdr); err != nil {
			_ = conn.Close()
			return
		}
		ub := make([]byte, hdr[1])
		_, _ = io.ReadFull(br, ub)
		plen, err := br.ReadByte()
		if err != nil {
			_ = conn.Close()
			return
		}
		pw := make([]byte, plen)
		_, _ = io.ReadFull(br, pw)
		_, _ = conn.Write([]byte{0x01, 0x01}) // credentials rejected
		_ = conn.Close()
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		_ = conn.Close()
		return
	}
	// Parked: hold the connection open until the pool closes it.
	s.parked.Add(1)
	_, _ = io.Copy(io.Discard, conn)
	s.parked.Add(-1)
	_ = conn.Close()
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func defaultWarm() config.WarmPoolSettings {
	return config.WarmPoolSettings{
		Enabled:                 true,
		MinIdlePerProxy:         1,
		MaxIdlePerProxy:         2,
		MaxTotalIdle:            4,
		MaxReplenishConcurrency: 2,
		IdleTTL:                 time.Minute,
	}
}

// warmStore builds a real store over routes with fast cooldowns and the given
// warm-pool bounds, and returns the store plus its live route pointers.
func warmStore(w config.WarmPoolSettings, routes ...*url.URL) (*pool.Store, []*pool.Proxy) {
	cfg := &config.RuntimeConfig{
		DialTimeout:  2 * time.Second,
		CooldownBase: 50 * time.Millisecond,
		CooldownMax:  time.Second,
		WarmPool:     w,
	}
	for _, u := range routes {
		cfg.Routes = append(cfg.Routes, config.RouteSpec{URL: u, Kind: config.EgressV4})
	}
	store := pool.NewStore(cfg, pool.NewRoutes(cfg.AllRoutes(), cfg.CooldownBase, cfg.CooldownMax, config.KindBalance{}))
	return store, store.Load().Pool.RoutePointers()
}

func newTestPool(store *pool.Store) *Pool {
	return New(store, zerolog.Nop(), nil)
}

// drain runs every scheduled task to completion, synchronously.
func drain(wp *Pool) {
	for {
		task, ok := wp.claimTask()
		if !ok {
			return
		}
		wp.runDial(task)
	}
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s not met within %s", what, timeout)
}

func TestReplenishFillsToMinIdle(t *testing.T) {
	srv := newHalfServer(t, "ok")
	w := defaultWarm()
	w.MinIdlePerProxy = 2
	store, _ := warmStore(w, mustURL(t, "socks5://"+srv.addr))
	wp := newTestPool(store)
	defer wp.Stop()

	wp.sweep()
	drain(wp)
	st := wp.Snapshot()
	if st.IdleTotal != 2 || st.Created != 2 {
		t.Fatalf("after drain: idle=%d created=%d, want 2/2", st.IdleTotal, st.Created)
	}
	// The far end parks a conn only after its greeting write lands, which can
	// trail the client-side handshake the pool already counted — poll rather
	// than assert immediately (observed as a CI flake, never locally).
	waitFor(t, "far-end parked conns", 2*time.Second, func() bool {
		return srv.parked.Load() == 2
	})
	if st.Routes[0].Upstream != srv.addr {
		t.Fatalf("route status upstream = %q, want %q (credentials must never appear)", st.Routes[0].Upstream, srv.addr)
	}
}

func TestPerRouteAndTotalBoundsHold(t *testing.T) {
	srvA := newHalfServer(t, "ok")
	srvB := newHalfServer(t, "ok")
	w := defaultWarm()
	w.MinIdlePerProxy = 3
	w.MaxIdlePerProxy = 3
	w.MaxTotalIdle = 10
	store, proxies := warmStore(w, mustURL(t, "socks5://"+srvA.addr), mustURL(t, "socks5://"+srvB.addr))
	wp := newTestPool(store)
	defer wp.Stop()

	wp.sweep()
	drain(wp)
	st := wp.Snapshot()
	for _, r := range st.Routes {
		if r.Idle > w.MaxIdlePerProxy {
			t.Fatalf("route idle %d exceeds per-route max %d", r.Idle, w.MaxIdlePerProxy)
		}
	}
	if st.IdleTotal != 6 {
		t.Fatalf("total idle = %d, want 6 (min 3 on each of two routes)", st.IdleTotal)
	}
	_ = proxies
}

func TestGlobalCapLimitsRefill(t *testing.T) {
	srvA := newHalfServer(t, "ok")
	srvB := newHalfServer(t, "ok")
	w := defaultWarm()
	w.MinIdlePerProxy = 1
	w.MaxTotalIdle = 1
	store, proxies := warmStore(w, mustURL(t, "socks5://"+srvA.addr), mustURL(t, "socks5://"+srvB.addr))
	wp := newTestPool(store)
	defer wp.Stop()

	wp.sweep()
	drain(wp)
	if got := wp.Snapshot().IdleTotal; got != 1 {
		t.Fatalf("total idle = %d, want 1 (global cap)", got)
	}
	// Borrowing the one warm conn must not push the total past the cap. Map
	// order picks which route won the single slot, so borrow from whichever
	// route holds it.
	var borrowed int
	for _, p := range proxies {
		if hc := wp.Borrow(p); hc != nil {
			borrowed++
			_ = hc.Close()
		}
	}
	if borrowed != 1 {
		t.Fatalf("borrowed %d conns, want exactly the one warm conn", borrowed)
	}
	wp.sweep()
	drain(wp)
	if got := wp.Snapshot().IdleTotal; got > w.MaxTotalIdle {
		t.Fatalf("total idle after refill = %d exceeds cap %d", got, w.MaxTotalIdle)
	}
}

// TestPerRouteReplenishCapHolds pins the multi-provider protection: the fleet
// gate alone lets one hot route take every in-flight dial toward one provider;
// max-replenish-per-route holds each route to its own share while the rest of
// the fleet stays available to other routes.
func TestPerRouteReplenishCapHolds(t *testing.T) {
	srvA := newHalfServer(t, "ok")
	srvB := newHalfServer(t, "ok")
	w := defaultWarm()
	w.MinIdlePerProxy = 2
	w.MaxTotalIdle = 8
	w.MaxReplenishConcurrency = 4 // fleet has room beyond two routes × cap 1
	w.MaxReplenishPerRoute = 1
	store, _ := warmStore(w, mustURL(t, "socks5://"+srvA.addr), mustURL(t, "socks5://"+srvB.addr))

	release := make(chan struct{})
	var calls atomic.Int64
	wp := New(store, zerolog.Nop(), func(ctx context.Context, pu *url.URL, timeout time.Duration) (*socksdial.HalfConn, error) {
		if calls.Add(1) <= 2 {
			<-release // hold the first two dials in the air
			return nil, errors.New("blocked dial failed")
		}
		return socksdial.DialHalf(ctx, pu, timeout)
	})
	defer wp.Stop()

	wp.sweep()
	t1, ok := wp.claimTask()
	if !ok {
		t.Fatal("first claim failed")
	}
	t2, ok := wp.claimTask()
	if !ok {
		t.Fatal("second claim failed")
	}
	if t1.p == t2.p {
		t.Fatal("both claims went to one route; the per-route cap should spread claims across routes")
	}
	if _, ok := wp.claimTask(); ok {
		t.Fatal("third claim succeeded with both routes at cap 1 while the fleet had room")
	}
	st := wp.Snapshot()
	if st.MaxReplenishPerRoute != 1 {
		t.Fatalf("status maxReplenishPerRoute = %d, want 1", st.MaxReplenishPerRoute)
	}
	for _, r := range st.Routes {
		if r.Flying != 1 {
			t.Fatalf("route %s flying = %d, want 1 while its dial is in the air", r.Upstream, r.Flying)
		}
	}

	// Releasing the dials runs them to the error path, which must return the
	// reservations — otherwise the routes stay capped forever after failures.
	close(release)
	wp.runDial(t1)
	wp.runDial(t2)
	for _, r := range wp.Snapshot().Routes {
		if r.Flying != 0 {
			t.Fatalf("after failed dials route %s flying = %d, want 0 (reservation returned)", r.Upstream, r.Flying)
		}
	}

	// Reservations returned, the routes re-arm: once the failure backoff
	// lifts, real dials refill both routes to min-idle.
	waitFor(t, "warm refill after backoff", 3*time.Second, func() bool {
		wp.sweep()
		drain(wp)
		return wp.Snapshot().IdleTotal == w.MinIdlePerProxy*2
	})
}

func TestBorrowPopsOldestAndMissesWhenEmpty(t *testing.T) {
	srv := newHalfServer(t, "ok")
	store, proxies := warmStore(defaultWarm(), mustURL(t, "socks5://"+srv.addr))
	wp := newTestPool(store)
	defer wp.Stop()

	wp.sweep()
	drain(wp)
	hc := wp.Borrow(proxies[0])
	if hc == nil {
		t.Fatal("borrow missed a ready conn")
	}
	if again := wp.Borrow(proxies[0]); again != nil {
		_ = again.Close()
		t.Fatal("second borrow returned a conn from an empty bucket")
	}
	if got := wp.Snapshot().Borrowed; got != 1 {
		t.Fatalf("borrowed counter = %d, want 1", got)
	}
	_ = hc.Close()
	// Unknown pointer: a miss, and no bucket creation.
	if got := wp.Borrow(nil); got != nil {
		t.Fatal("borrow(nil) returned a conn")
	}
}

func TestRotationInvalidatesAndBlocksReplenish(t *testing.T) {
	srv := newHalfServer(t, "ok")
	store, proxies := warmStore(defaultWarm(), mustURL(t, "socks5://"+srv.addr))
	wp := newTestPool(store)
	defer wp.Stop()

	wp.sweep()
	drain(wp)
	before := wp.Snapshot().Created
	p := proxies[0]

	p.BeginRotation(pool.RotationDraining)
	wp.sweep()
	if st := wp.Snapshot(); st.IdleTotal != 0 || st.GenerationInvalidated == 0 {
		t.Fatalf("after BeginRotation: idle=%d invalidated=%d, want 0/>0", st.IdleTotal, st.GenerationInvalidated)
	}
	wp.sweep()
	drain(wp)
	if st := wp.Snapshot(); st.Created != before || st.IdleTotal != 0 {
		t.Fatalf("replenished a rotating route: created=%d idle=%d", st.Created, st.IdleTotal)
	}
	if hc := wp.Borrow(p); hc != nil {
		t.Fatal("borrow handed out a conn mid-rotation")
	}

	p.EndRotation("198.51.100.7", time.Now())
	wp.sweep()
	drain(wp)
	st := wp.Snapshot()
	if st.Created != before+1 || st.IdleTotal != 1 {
		t.Fatalf("after EndRotation: created=%d idle=%d, want refill", st.Created, st.IdleTotal)
	}
	// The new conn carries the new epoch and is borrowable.
	if hc := wp.Borrow(p); hc == nil {
		t.Fatal("borrow missed the post-rotation warm conn")
	} else {
		_ = hc.Close()
	}
}

// TestMidDialRotationDiscardsFreshConn drives the sharpest straddle: a dial
// claimed (epoch stamped), a rotation beginning while the dial is in flight,
// and the dial completing afterwards. The post-dial epoch check must close
// the fresh connection instead of parking it — an old-generation socket must
// never sit in ready, even briefly, waiting for the borrow-time check.
func TestMidDialRotationDiscardsFreshConn(t *testing.T) {
	srv := newHalfServer(t, "ok")
	store, proxies := warmStore(defaultWarm(), mustURL(t, "socks5://"+srv.addr))
	wp := newTestPool(store)
	defer wp.Stop()
	p := proxies[0]

	wp.sweep()
	task, ok := wp.claimTask()
	if !ok {
		t.Fatal("no dial claimed after sweep")
	}
	// The rotation begins between the claim (epoch stamped) and the dial's
	// post-dial check — exactly the window runDial's equality check exists
	// for. Ending the rotation before the dial keeps the epoch moved.
	p.BeginRotation(pool.RotationDraining)
	wp.runDial(task)

	st := wp.Snapshot()
	if st.Created != 0 || st.IdleTotal != 0 {
		t.Fatalf("straddled conn was parked: created=%d idle=%d, want 0/0", st.Created, st.IdleTotal)
	}
	if st.GenerationInvalidated != 1 {
		t.Fatalf("generation-invalidated = %d, want 1 (post-dial discard)", st.GenerationInvalidated)
	}
	waitFor(t, "far end sees the discarded conn close", 2*time.Second, func() bool {
		return srv.parked.Load() == 0
	})
	if hc := wp.Borrow(p); hc != nil {
		_ = hc.Close()
		t.Fatal("borrow handed out a straddled-generation conn")
	}

	// The bucket survives the straddle: the new epoch warms normally.
	p.EndRotation("198.51.100.9", time.Now())
	wp.sweep()
	drain(wp)
	if hc := wp.Borrow(p); hc == nil {
		t.Fatal("borrow missed the new-epoch conn after rotation")
	} else {
		_ = hc.Close()
	}
}

// TestBorrowDisabledAfterReload pins the disable edge: a pool whose config
// was reloaded to enabled=false must stop serving immediately — not one
// sweep interval later — even though parked conns still sit in the bucket
// awaiting the sweeper's drain.
func TestBorrowDisabledAfterReload(t *testing.T) {
	srv := newHalfServer(t, "ok")
	u := mustURL(t, "socks5://"+srv.addr)
	w := defaultWarm()
	store, proxies := warmStore(w, u)
	wp := newTestPool(store)
	defer wp.Stop()

	wp.sweep()
	drain(wp)
	if got := wp.Snapshot().IdleTotal; got != 1 {
		t.Fatalf("setup: idle=%d, want 1", got)
	}

	// Same routes, warm pool disabled: a disable reload, nothing else.
	w.Enabled = false
	store.Publish(&config.RuntimeConfig{
		DialTimeout:  2 * time.Second,
		CooldownBase: 50 * time.Millisecond,
		CooldownMax:  time.Second,
		WarmPool:     w,
		Routes:       []config.RouteSpec{{URL: u, Kind: config.EgressV4}},
	})

	if hc := wp.Borrow(proxies[0]); hc != nil {
		_ = hc.Close()
		t.Fatal("borrow served from a pool disabled by reload")
	}
	if got := wp.Snapshot().IdleTotal; got != 1 {
		t.Fatalf("idle before drain sweep = %d, want 1 (the sweeper owns the drain)", got)
	}
	wp.sweep()
	if got := wp.Snapshot().IdleTotal; got != 0 {
		t.Fatalf("sweep after disable left idle=%d, want 0", got)
	}
}

func TestAuthFailureStopsReplenishUntilEpochMoves(t *testing.T) {
	srv := newHalfServer(t, "authreject")
	store, proxies := warmStore(defaultWarm(), mustURL(t, "socks5://u:p@"+srv.addr))
	wp := newTestPool(store)
	defer wp.Stop()

	wp.sweep()
	drain(wp)
	wp.sweep()
	drain(wp)
	st := wp.Snapshot()
	if st.ConnectFailed < 1 {
		t.Fatalf("connect-failed counter = %d, want >= 1", st.ConnectFailed)
	}
	if st.IdleTotal != 0 {
		t.Fatalf("auth-rejecting endpoint yielded idle conns: %d", st.IdleTotal)
	}
	if attempts := st.ReplenishAttempts; attempts != 1 {
		t.Fatalf("replenish attempts = %d, want exactly 1 (authBroken must stop retries)", attempts)
	}
	if blocked := proxies[0].AuthBlockedNow(); blocked {
		t.Fatal("background auth failure must not block route health")
	}

	// A rotation epoch move re-arms the bucket: one more attempt, still
	// failing, still counted.
	p := proxies[0]
	p.BeginRotation(pool.RotationDraining)
	p.EndRotation("198.51.100.8", time.Now())
	wp.sweep()
	drain(wp)
	if got := wp.Snapshot().ReplenishAttempts; got != 2 {
		t.Fatalf("replenish attempts after epoch move = %d, want 2", got)
	}
}

func TestDialFailureBacksOff(t *testing.T) {
	srv := newHalfServer(t, "refuse")
	store, _ := warmStore(defaultWarm(), mustURL(t, "socks5://"+srv.addr))
	wp := newTestPool(store)
	defer wp.Stop()

	wp.sweep()
	drain(wp)
	st := wp.Snapshot()
	if st.ConnectFailed != 1 || st.IdleTotal != 0 {
		t.Fatalf("after failure: failed=%d idle=%d", st.ConnectFailed, st.IdleTotal)
	}
	// An immediate second sweep must not schedule: the bucket is in backoff.
	wp.sweep()
	drain(wp)
	if got := wp.Snapshot().ReplenishAttempts; got != 1 {
		t.Fatalf("replenish attempts during backoff = %d, want 1", got)
	}
}

func TestCooldownPausesReplenish(t *testing.T) {
	srv := newHalfServer(t, "ok")
	store, proxies := warmStore(defaultWarm(), mustURL(t, "socks5://"+srv.addr))
	wp := newTestPool(store)
	defer wp.Stop()
	pl := store.Load().Pool

	wp.sweep()
	drain(wp)
	baseline := wp.Snapshot().ReplenishAttempts
	if hc := wp.Borrow(proxies[0]); hc == nil {
		t.Fatal("setup borrow failed")
	} else {
		_ = hc.Close()
	}
	// A request-path failure cools the route (base 50ms in this store); the
	// warm pool must pause — and must not change the cooldown itself.
	pl.ReportFailure(proxies[0], nil)
	if !proxies[0].CooldownActive() {
		t.Fatal("setup failure did not cool the route")
	}
	wp.sweep()
	drain(wp)
	if st := wp.Snapshot(); st.ReplenishAttempts != baseline {
		t.Fatalf("replenished a cooling route: attempts=%d, want the setup baseline %d", st.ReplenishAttempts, baseline)
	}
	if !proxies[0].CooldownActive() {
		t.Fatal("warm pool touched route cooldown state")
	}
	// Once the cooldown lifts, replenishment resumes.
	waitFor(t, "cooldown lift", 2*time.Second, func() bool { return !proxies[0].CooldownActive() })
	wp.sweep()
	drain(wp)
	if st := wp.Snapshot(); st.IdleTotal != 1 {
		t.Fatalf("idle after cooldown lift = %d, want 1", st.IdleTotal)
	}
}

func TestSweepExpiresIdleTTL(t *testing.T) {
	srv := newHalfServer(t, "ok")
	w := defaultWarm()
	w.IdleTTL = 20 * time.Millisecond
	store, _ := warmStore(w, mustURL(t, "socks5://"+srv.addr))
	wp := newTestPool(store)
	defer wp.Stop()

	wp.sweep()
	drain(wp)
	if wp.Snapshot().IdleTotal != 1 {
		t.Fatal("setup did not warm the route")
	}
	time.Sleep(40 * time.Millisecond)
	wp.sweep()
	st := wp.Snapshot()
	if st.IdleTotal != 0 || st.DiscardedStale == 0 {
		t.Fatalf("after TTL: idle=%d stale=%d, want 0/>0", st.IdleTotal, st.DiscardedStale)
	}
}

func TestRouteRemovedClosesBucket(t *testing.T) {
	srvA := newHalfServer(t, "ok")
	srvB := newHalfServer(t, "ok")
	w := defaultWarm()
	store, _ := warmStore(w, mustURL(t, "socks5://"+srvA.addr), mustURL(t, "socks5://"+srvB.addr))
	wp := newTestPool(store)
	defer wp.Stop()

	wp.sweep()
	drain(wp)
	if wp.Snapshot().IdleTotal != 2 {
		t.Fatal("setup did not warm both routes")
	}

	// Reload without route A: publish the new generation, then sweep.
	cfg2 := *store.Load().Config
	cfg2.Routes = []config.RouteSpec{{URL: mustURL(t, "socks5://"+srvB.addr), Kind: config.EgressV4}}
	store.Publish(&cfg2)

	wp.sweep()
	st := wp.Snapshot()
	if len(st.Routes) != 1 || st.IdleTotal != 1 {
		t.Fatalf("after removal: routes=%v idle=%d, want 1/1", st.Routes, st.IdleTotal)
	}
	waitFor(t, "removed route's far-end conns closed", 2*time.Second, func() bool {
		return srvA.parked.Load() == 0
	})
}

func TestDisabledDrainsAndReenable(t *testing.T) {
	srv := newHalfServer(t, "ok")
	w := defaultWarm()
	store, _ := warmStore(w, mustURL(t, "socks5://"+srv.addr))
	wp := newTestPool(store)
	defer wp.Stop()

	wp.sweep()
	drain(wp)
	baseline := wp.Snapshot().ReplenishAttempts
	if wp.Snapshot().IdleTotal != 1 {
		t.Fatal("setup did not warm the route")
	}

	off := *store.Load().Config
	off.WarmPool = w
	off.WarmPool.Enabled = false
	store.Publish(&off)
	wp.sweep()
	if st := wp.Snapshot(); st.IdleTotal != 0 {
		t.Fatalf("disabled pool kept idle conns: %d", st.IdleTotal)
	}
	wp.sweep()
	drain(wp)
	if st := wp.Snapshot(); st.ReplenishAttempts != baseline {
		t.Fatalf("disabled pool replenished: attempts=%d, want the setup baseline %d", st.ReplenishAttempts, baseline)
	}

	on := *store.Load().Config
	on.WarmPool = w
	on.WarmPool.Enabled = true
	store.Publish(&on)
	wp.sweep()
	drain(wp)
	if st := wp.Snapshot(); st.IdleTotal != 1 {
		t.Fatalf("re-enabled pool did not refill: idle=%d", st.IdleTotal)
	}
}

// Borrowing nudges the sweeper: with the tick stretched far beyond the
// assertion window, a refill after a borrow can only come from the wake path
// — consumption-paced replenishment instead of tick-paced.
func TestBorrowWakesSweeper(t *testing.T) {
	srv := newHalfServer(t, "ok")
	store, routes := warmStore(defaultWarm(), mustURL(t, "socks5://"+srv.addr))
	wp := newTestPool(store)
	wp.sweepEvery = 30 * time.Second

	wp.Start()
	defer wp.Stop()
	// The startup pass (not a tick — there is none for 30s) fills to min-idle.
	waitFor(t, "startup fill", 5*time.Second, func() bool {
		return wp.Snapshot().IdleTotal == 1
	})

	if hc := wp.Borrow(routes[0]); hc == nil {
		t.Fatal("borrow after fill returned nil")
	}
	waitFor(t, "wake-driven refill after borrow", 5*time.Second, func() bool {
		return wp.Snapshot().IdleTotal == 1
	})
	if b := wp.Snapshot().Borrowed; b != 1 {
		t.Fatalf("borrowed = %d, want 1", b)
	}
}

func TestStartStopLifecycle(t *testing.T) {
	srv := newHalfServer(t, "ok")
	store, _ := warmStore(defaultWarm(), mustURL(t, "socks5://"+srv.addr))
	wp := newTestPool(store)

	wp.Start()
	defer wp.Stop()
	// The real ticker/waker path fills the bucket without any manual sweep.
	waitFor(t, "async warm fill", 5*time.Second, func() bool {
		return wp.Snapshot().IdleTotal == 1
	})

	done := make(chan struct{})
	go func() {
		wp.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not return within its bound")
	}
	st := wp.Snapshot()
	if !st.Stopped || st.IdleTotal != 0 {
		t.Fatalf("after stop: stopped=%v idle=%d", st.Stopped, st.IdleTotal)
	}
	if hc := wp.Borrow(nil); hc != nil {
		t.Fatal("borrow after stop returned a conn")
	}
	waitFor(t, "far-end conns closed after stop", 2*time.Second, func() bool {
		return srv.parked.Load() == 0
	})
}
