package e2e_test

import (
	"context"
	"fmt"
	"syscall"
	"testing"
	"time"
)

// Adversarial warm-pool coverage. The pool is background-only at this stage:
// nothing on the serving path borrows from it, so every test proves the pool
// stays inside its contract on its own — bounded connections, no CONNECT
// frames while parked, generation isolation across rotations, config
// generations honored on reload, no route-health writes, and no leak past
// shutdown.

func warmEnabled() *WarmPoolConfig {
	return &WarmPoolConfig{Enabled: true}
}

// warmStatus fetches the warm-pool view, failing when the section is absent.
func warmStatus(t testing.TB, g *Gateway) *WarmView {
	t.Helper()
	st, err := g.Status()
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.WarmPool == nil {
		t.Fatalf("status has no warmPool section: %+v\nlogs:\n%s", st, g.Logs())
	}
	return st.WarmPool
}

// waitWarm polls until cond holds on the warm-pool view.
func waitWarm(t testing.TB, g *Gateway, what string, cond func(*WarmView) bool, timeout time.Duration) *WarmView {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if w := warmStatus(t, g); cond(w) {
			return w
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("warm pool never %s; last=%+v\nlogs:\n%s", what, warmStatus(t, g), g.Logs())
	return nil
}

// waitSimLive polls until the simulator's live-connection count reaches want.
func waitSimLive(t *testing.T, sim *SocksSim, what string, want int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if sim.Live.Load() == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("sim %s live count never reached %d (%s); now=%d", sim.Addr, want, what, sim.Live.Load())
}

// tunnelOnce proves the serving path works end to end: one CONNECT through
// the mixed listener to target succeeds.
func tunnelOnce(t *testing.T, g *Gateway, target string) {
	t.Helper()
	conn, err := dialSocksTunnel(context.Background(), g.MixedAddr, target)
	if err != nil {
		t.Fatalf("CONNECT %s through mixed listener: %v\nlogs:\n%s", target, err, g.Logs())
	}
	_ = conn.Close()
}

// G: the pool fills exactly to its per-route bounds, holds steady without
// re-dialing, and parked connections never send a CONNECT frame.
func TestE2E_WarmPoolFillsToBoundWithoutConnects(t *testing.T) {
	skipShort(t)
	sim := NewSocksSim(t, SocksOK, "", "")
	cfg := defaultGatewayConfig([]RouteConfig{{Proxy: sim.RouteValue(), Kind: "v4"}})
	w := warmEnabled()
	w.MinIdlePerProxy = 2
	w.MaxIdlePerProxy = 2
	cfg.WarmPool = w
	g := NewGateway(t, cfg)
	defer g.stop()

	waitWarm(t, g, "fills to min-idle 2", func(v *WarmView) bool { return v.IdleTotal == 2 }, 5*time.Second)
	if hits := sim.Hits.Load(); hits != 2 {
		t.Fatalf("sim hits = %d, want exactly the two half dials", hits)
	}
	if got := sim.Connected.Load(); got != 0 {
		t.Fatalf("parked conns sent %d CONNECT frames, want none", got)
	}
	if got := sim.Live.Load(); got != 2 {
		t.Fatalf("sim live = %d, want 2 parked", got)
	}
	// Three more sweeps with the bucket full: no re-dial churn.
	time.Sleep(3 * time.Second)
	if hits := sim.Hits.Load(); hits != 2 {
		t.Fatalf("sim hits after settle = %d, want no extra dials past the bound", hits)
	}
	if v := warmStatus(t, g); v.Created != 2 || v.ConnectFailed != 0 {
		t.Fatalf("counters after settle = %+v, want created=2 failed=0", v)
	}
}

// The pool defaults to disabled and costs nothing: no block, no dials.
func TestE2E_WarmPoolDefaultOffIsInert(t *testing.T) {
	skipShort(t)
	sim := NewSocksSim(t, SocksOK, "", "")
	cfg := defaultGatewayConfig([]RouteConfig{{Proxy: sim.RouteValue(), Kind: "v4"}})
	g := NewGateway(t, cfg)
	defer g.stop()

	time.Sleep(3 * time.Second)
	v := warmStatus(t, g)
	if v.Enabled || v.IdleTotal != 0 || v.Created != 0 {
		t.Fatalf("default pool is active: %+v", v)
	}
	if hits := sim.Hits.Load(); hits != 0 {
		t.Fatalf("default pool dialed the endpoint %d times", hits)
	}
}

// D: disabling through a reload drains every parked connection, and
// re-enabling refills — all without a restart.
func TestE2E_WarmPoolReloadDrainsAndRefills(t *testing.T) {
	skipShort(t)
	sim := NewSocksSim(t, SocksOK, "", "")
	route := RouteConfig{Proxy: sim.RouteValue(), Kind: "v4"}
	cfg := defaultGatewayConfig([]RouteConfig{route})
	cfg.WarmPool = warmEnabled()
	g := NewGateway(t, cfg)
	defer g.stop()

	waitWarm(t, g, "fills", func(v *WarmView) bool { return v.IdleTotal == 1 }, 5*time.Second)

	off := cfg
	off.WarmPool = &WarmPoolConfig{Enabled: false}
	g.ReloadConfig(off, []string{sim.Addr})
	waitWarm(t, g, "drains", func(v *WarmView) bool { return v.IdleTotal == 0 }, 5*time.Second)
	waitSimLive(t, sim, "parked conns closed by disable", 0, 5*time.Second)

	on := cfg
	g.ReloadConfig(on, []string{sim.Addr})
	waitWarm(t, g, "refills after re-enable", func(v *WarmView) bool { return v.IdleTotal == 1 }, 5*time.Second)
}

// C: removing a route through a reload drops its bucket and closes its parked
// connections; the surviving route keeps serving its own.
func TestE2E_WarmPoolRouteRemovedOnReload(t *testing.T) {
	skipShort(t)
	simA := NewSocksSim(t, SocksOK, "", "")
	simB := NewSocksSim(t, SocksOK, "", "")
	cfg := defaultGatewayConfig([]RouteConfig{
		{Proxy: simA.RouteValue(), Kind: "v4"},
		{Proxy: simB.RouteValue(), Kind: "v4"},
	})
	cfg.WarmPool = warmEnabled()
	g := NewGateway(t, cfg)
	defer g.stop()

	waitWarm(t, g, "fills both", func(v *WarmView) bool { return v.IdleTotal == 2 }, 5*time.Second)

	next := cfg
	next.Routes = []RouteConfig{{Proxy: simB.RouteValue(), Kind: "v4"}}
	g.ReloadConfig(next, []string{simB.Addr})
	waitWarm(t, g, "drops removed route", func(v *WarmView) bool { return v.IdleTotal == 1 }, 5*time.Second)
	if v := warmStatus(t, g); len(v.Routes) != 1 || v.Routes[0].Upstream != simB.Addr {
		t.Fatalf("routes after removal = %+v, want only %s", v.Routes, simB.Addr)
	}
	waitSimLive(t, simA, "removed route's parked conns close", 0, 5*time.Second)
}

// F: an endpoint that rejects the route's credentials stops replenishment
// without ever writing route health — the pool entry stays unblocked, the
// request path owns that state.
func TestE2E_WarmPoolAuthFailureStopsWithoutHealthImpact(t *testing.T) {
	skipShort(t)
	sim := NewSocksSim(t, SocksAuthRequired, "user", "real-pass")
	// The route carries wrong credentials: every half handshake fails auth.
	route := RouteConfig{Proxy: fmt.Sprintf("user:wrong-pass@%s", sim.Addr), Kind: "v4"}
	cfg := defaultGatewayConfig([]RouteConfig{route})
	cfg.WarmPool = warmEnabled()
	g := NewGateway(t, cfg)
	defer g.stop()

	v := waitWarm(t, g, "records the auth failure", func(v *WarmView) bool { return v.ConnectFailed >= 1 }, 5*time.Second)
	if v.IdleTotal != 0 {
		t.Fatalf("auth-rejecting endpoint yielded %d idle conns", v.IdleTotal)
	}
	// The bucket is auth-broken: attempts stop growing instead of retrying
	// every sweep.
	attempts := v.ReplenishAttempts
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if now := warmStatus(t, g); now.ReplenishAttempts > attempts {
			attempts = now.ReplenishAttempts
		}
		time.Sleep(100 * time.Millisecond)
	}
	if attempts > v.ReplenishAttempts+1 {
		t.Fatalf("auth-broken bucket kept dialing: attempts %d -> %d", v.ReplenishAttempts, attempts)
	}
	st, err := g.Status()
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	for _, e := range st.Pool {
		if e.Proxy == sim.Addr && (e.AuthBlocked || e.AuthFailures != 0) {
			t.Fatalf("background auth failure leaked into route health: %+v", e)
		}
	}
}

// B: an endpoint whose service dies (TCP answers, SOCKS gone) yields no idle
// connections and records the failures — replenishment backs off rather than
// dial-storming.
func TestE2E_WarmPoolDeadEndpointStaysEmpty(t *testing.T) {
	skipShort(t)
	sim := NewSocksSim(t, SocksOK, "", "")
	sim.Down.Store(true)
	cfg := defaultGatewayConfig([]RouteConfig{{Proxy: sim.RouteValue(), Kind: "v4"}})
	cfg.WarmPool = warmEnabled()
	g := NewGateway(t, cfg)
	defer g.stop()

	v := waitWarm(t, g, "records dial failure", func(v *WarmView) bool { return v.ConnectFailed >= 1 }, 5*time.Second)
	if v.IdleTotal != 0 || v.Created != 0 {
		t.Fatalf("dead endpoint produced conns: %+v", v)
	}
	// Backoff bounds the attempt rate: with 1s doubling to 8s, 5 seconds see
	// at most a handful of attempts, never one per poll.
	time.Sleep(5 * time.Second)
	if now := warmStatus(t, g); now.ReplenishAttempts > v.ReplenishAttempts+5 {
		t.Fatalf("dead endpoint dial-stormed: attempts %d -> %d", v.ReplenishAttempts, now.ReplenishAttempts)
	}
}

// E: idle connections expire by TTL; the sim sees fresh half dials over time
// but never a CONNECT frame, and the total stays inside the bound.
func TestE2E_WarmPoolIdleTTLExpiry(t *testing.T) {
	skipShort(t)
	sim := NewSocksSim(t, SocksOK, "", "")
	cfg := defaultGatewayConfig([]RouteConfig{{Proxy: sim.RouteValue(), Kind: "v4"}})
	w := warmEnabled()
	w.IdleTTL = "2s"
	cfg.WarmPool = w
	g := NewGateway(t, cfg)
	defer g.stop()

	waitWarm(t, g, "fills", func(v *WarmView) bool { return v.Created >= 1 }, 5*time.Second)
	waitWarm(t, g, "expires by TTL", func(v *WarmView) bool { return v.DiscardedStale >= 1 }, 6*time.Second)
	// The refill after expiry keeps the total inside the bound and still
	// never sends CONNECT.
	if v := warmStatus(t, g); v.IdleTotal > 1 {
		t.Fatalf("idle total %d exceeds the per-route bound", v.IdleTotal)
	}
	time.Sleep(3 * time.Second)
	if got := sim.Connected.Load(); got != 0 {
		t.Fatalf("parked conns sent %d CONNECT frames, want none", got)
	}
}

// A: rotation is a hard generation boundary. A parked connection never
// crosses into the new egress generation: BeginRotation invalidates it, the
// bucket re-warms on the new epoch, and tunnels keep flowing.
func TestE2E_WarmPoolRotationInvalidatesGeneration(t *testing.T) {
	skipShort(t)
	rt := newRotationTest(t, 2)
	rt.flipOnCall()
	target := NewEchoTarget(t)
	cfg := defaultGatewayConfig(nil)
	cfg.Manual = []ManualRouteConfig{rt.entry(rt.sims[0], "1500ms"), rt.entry(rt.sims[1], "1500ms")}
	cfg.Rotation = fastRotation(rt.trace)
	cfg.WarmPool = warmEnabled()
	g := startRotationGateway(t, cfg, rt.trace)
	defer g.stop()

	sim := rt.sims[0]
	waitWarm(t, g, "fills", func(v *WarmView) bool { return v.IdleTotal >= 1 }, 5*time.Second)
	// The rotation engine's baseline and verify probes are legitimate traffic
	// through this route, so CONNECT frames here are expected; what must hold
	// is the generation boundary asserted below.

	// First completed rotation: parked conns die with the old generation and
	// the pool re-warms on the new epoch.
	waitRotations(t, g, 1, 15*time.Second)
	waitWarm(t, g, "invalidates the old generation", func(v *WarmView) bool {
		return v.GenerationInvalidated >= 1
	}, 5*time.Second)
	waitWarm(t, g, "re-warms on the new epoch", func(v *WarmView) bool {
		for _, r := range v.Routes {
			if r.Upstream == sim.Addr && r.Idle >= 1 {
				return true
			}
		}
		return false
	}, 5*time.Second)

	// The serving path stays healthy across the whole cycle.
	tunnelOnce(t, g, target.Host)
}

// H: shutdown closes every parked connection before the process exits — no
// upstream socket outlives the gateway.
func TestE2E_WarmPoolShutdownClosesParkedConns(t *testing.T) {
	skipShort(t)
	sim := NewSocksSim(t, SocksOK, "", "")
	cfg := defaultGatewayConfig([]RouteConfig{{Proxy: sim.RouteValue(), Kind: "v4"}})
	w := warmEnabled()
	w.MinIdlePerProxy = 2
	w.MaxIdlePerProxy = 2
	cfg.WarmPool = w
	g := NewGateway(t, cfg)

	waitWarm(t, g, "fills to 2", func(v *WarmView) bool { return v.IdleTotal == 2 }, 5*time.Second)
	if err := g.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM: %v", err)
	}
	done := make(chan struct{})
	go func() { _ = g.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("gateway did not exit\nlogs:\n%s", g.Logs())
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && sim.Live.Load() != 0 {
		time.Sleep(50 * time.Millisecond)
	}
	if got := sim.Live.Load(); got != 0 {
		t.Fatalf("%d parked conns outlived the gateway process", got)
	}
}
