package e2e_test

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func skipShort(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("e2e")
	}
}

// rotationTest binds each manual route to its own SOCKS sim and a distinct
// loopback source. The source distinguishes routes inside the trace endpoint
// and inside source-echoing targets without any shared state.
type rotationTest struct {
	trace  *TraceSim
	api    *RotateAPISim
	sims   []*SocksSim
	source map[*SocksSim]string
}

func newRotationTest(t *testing.T, n int) *rotationTest {
	t.Helper()
	rt := &rotationTest{
		trace:  NewTraceSim(t, "203.0.113.1"),
		api:    NewRotateAPISim(t),
		source: map[*SocksSim]string{},
	}
	for i := range n {
		sim := NewSocksSim(t, SocksOK, "", "")
		sim.Outbound = fmt.Sprintf("127.0.2.%d", i+1)
		rt.sims = append(rt.sims, sim)
		rt.source[sim] = sim.Outbound
	}
	return rt
}

// flipOnCall models providers that rotate on the API call: call n moves route
// n-1's egress to a fresh unique address. Deterministic when the gateway
// serializes procedures under the concurrency cap (config order).
func (rt *rotationTest) flipOnCall() {
	var calls atomic.Int64
	rt.api.OnCall(func() {
		n := int(calls.Add(1))
		if n <= len(rt.sims) {
			rt.trace.SetIP(rt.source[rt.sims[n-1]], fmt.Sprintf("198.51.100.%d", n+9))
		}
	})
}

func (rt *rotationTest) entry(sim *SocksSim, interval string) ManualRouteConfig {
	return ManualRouteConfig{
		Proxy:          sim.RouteValue(),
		Kind:           "v4",
		RotateInterval: interval,
		API: ManualAPIConfig{
			URL:     rt.api.URL,
			Method:  "POST",
			Timeout: "2s",
			Headers: map[string]string{"X-Api-Token": "e2e-rotation-token"},
		},
	}
}

func fastRotation(trace *TraceSim) *RotationConfig {
	return &RotationConfig{
		MaxConcurrent:   "1",
		DrainTimeout:    "2s",
		IPCheckURL:      trace.URL,
		IPCheckTimeout:  "3s",
		IPCheckInterval: "100ms",
		RetryBackoffMax: "5s",
	}
}

// startRotationGateway launches the gateway trusting the trace endpoint's CA.
func startRotationGateway(t *testing.T, cfg GatewayConfig, trace *TraceSim) *Gateway {
	t.Helper()
	return NewGatewayWithEnv(t, cfg, "SSL_CERT_FILE="+trace.CAFile)
}

// rotationView returns the current rotation view of a manual route.
func rotationView(t *testing.T, g *Gateway, sim *SocksSim) *RotationView {
	t.Helper()
	st, err := g.Status()
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	for _, e := range st.Pool {
		if e.Proxy == sim.Addr {
			if e.Rotation == nil {
				t.Fatalf("route %s has no rotation view: %+v", sim.Addr, e)
			}
			return e.Rotation
		}
	}
	t.Fatalf("route %s missing from pool: %+v", sim.Addr, st.Pool)
	return nil
}

// waitRotation polls until cond holds for the route's rotation view.
func waitRotation(t *testing.T, g *Gateway, sim *SocksSim, what string, cond func(*RotationView) bool, timeout time.Duration) *RotationView {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if v := rotationView(t, g, sim); cond(v) {
			return v
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("route %s rotation never %s; last=%+v\nlogs:\n%s", sim.Addr, what,
		rotationView(t, g, sim), g.Logs())
	return nil
}

// waitRotations polls until the global rotations counter reaches want.
func waitRotations(t *testing.T, g *Gateway, want uint64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if st, err := g.Status(); err == nil && st.Rotations >= want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	st, _ := g.Status()
	t.Fatalf("rotations never reached %d (status=%+v)\nlogs:\n%s", want, st, g.Logs())
}

func TestRotationRotateOnStartRespectsFixedCap(t *testing.T) {
	skipShort(t)
	rt := newRotationTest(t, 2)
	rt.flipOnCall()
	cfg := defaultGatewayConfig(nil)
	cfg.Manual = []ManualRouteConfig{rt.entry(rt.sims[0], "1h"), rt.entry(rt.sims[1], "1h")}
	cfg.Rotation = fastRotation(rt.trace)
	cfg.Rotation.RotateOnStart = true
	g := startRotationGateway(t, cfg, rt.trace)

	waitRotations(t, g, 2, 15*time.Second)
	if n := rt.api.MaxConcurrent(); n > 1 {
		t.Fatalf("rotate API saw %d concurrent calls under cap 1, want <= 1", n)
	}
	for i, sim := range rt.sims {
		v := rotationView(t, g, sim)
		want := fmt.Sprintf("198.51.100.%d", i+10)
		if v.State != "idle" || v.LastIP != want {
			t.Fatalf("route %d view=%+v, want idle with lastIP %s", i, v, want)
		}
	}
	if !rt.api.SawToken.Load() {
		t.Fatal("rotate API never received the configured token header")
	}
}

func TestRotationPercentCapSerializes(t *testing.T) {
	skipShort(t)
	rt := newRotationTest(t, 3)
	rt.flipOnCall()
	cfg := defaultGatewayConfig(nil)
	for _, sim := range rt.sims {
		cfg.Manual = append(cfg.Manual, rt.entry(sim, "1h"))
	}
	cfg.Rotation = fastRotation(rt.trace)
	cfg.Rotation.MaxConcurrent = "25%" // ceil(3 * 0.25) = 1
	cfg.Rotation.RotateOnStart = true
	g := startRotationGateway(t, cfg, rt.trace)

	waitRotations(t, g, 3, 20*time.Second)
	if n := rt.api.MaxConcurrent(); n > 1 {
		t.Fatalf("rotate API saw %d concurrent calls under a 25%% cap of 3, want <= 1", n)
	}
}

func TestRotationDrainWaitsForInFlightRequest(t *testing.T) {
	skipShort(t)
	rt := newRotationTest(t, 1)
	rt.flipOnCall()
	slow := NewSlowBodyTarget(t, 2500*time.Millisecond)
	cfg := defaultGatewayConfig(nil)
	cfg.Manual = []ManualRouteConfig{rt.entry(rt.sims[0], "2s")}
	cfg.Rotation = fastRotation(rt.trace)
	g := startRotationGateway(t, cfg, rt.trace)

	// A request that straddles the 2s interval: picked before the rotation
	// begins, so the drain must let it finish rather than break it.
	time.Sleep(1200 * time.Millisecond)
	done := make(chan error, 1)
	go func() {
		resp, err := ProxyClient(g.MixedAddr).Get(slow.URL + "/slow")
		if err != nil {
			done <- err
			return
		}
		resp.Body.Close()
		done <- nil
	}()

	waitRotation(t, g, rt.sims[0], "to finish a verified rotation",
		func(v *RotationView) bool { return v.State == "idle" && v.LastIP == "198.51.100.10" }, 12*time.Second)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("in-flight request did not survive the drain window: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("slow request never completed")
	}
	if st, err := g.Status(); err != nil || st.Failovers != 0 || st.Rotations != 1 {
		t.Fatalf("failovers=%d rotations=%d err=%v, want 0/1", stFailovers(t, g), stRotations(t, g), err)
	}
}

func stFailovers(t *testing.T, g *Gateway) uint64 {
	t.Helper()
	st, err := g.Status()
	if err != nil {
		return 0
	}
	return st.Failovers
}

func stRotations(t *testing.T, g *Gateway) uint64 {
	t.Helper()
	st, err := g.Status()
	if err != nil {
		return 0
	}
	return st.Rotations
}

func TestRotationDrainTimeoutForceRotates(t *testing.T) {
	skipShort(t)
	rt := newRotationTest(t, 1)
	rt.flipOnCall()
	held := NewSlowBodyTarget(t, 6*time.Second)
	cfg := defaultGatewayConfig(nil)
	cfg.Manual = []ManualRouteConfig{rt.entry(rt.sims[0], "2s")}
	cfg.Rotation = fastRotation(rt.trace)
	cfg.Rotation.DrainTimeout = "1s"
	g := startRotationGateway(t, cfg, rt.trace)

	// The body stays open well past the 1s drain budget: expiry force-rotates
	// instead of waiting the full 6s, and the request still runs to
	// completion on the old egress.
	time.Sleep(1200 * time.Millisecond)
	done := make(chan error, 1)
	go func() {
		resp, err := ProxyClient(g.MixedAddr).Get(held.URL + "/held")
		if err != nil {
			done <- err
			return
		}
		resp.Body.Close()
		done <- nil
	}()
	start := time.Now()
	waitRotation(t, g, rt.sims[0], "to force-rotate past the drain timeout",
		func(v *RotationView) bool { return v.State == "idle" && v.LastIP == "198.51.100.10" }, 12*time.Second)
	// Waiting for the held body would push completion past 6s; a forced
	// rotation lands far earlier.
	if elapsed := time.Since(start); elapsed > 5500*time.Millisecond {
		t.Fatalf("rotation completed after %s, want a forced rotation inside the drain budget", elapsed)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("held request never completed after force-rotate: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("held request never completed")
	}
}

func TestRotationSameIPBacksOffThenSucceeds(t *testing.T) {
	skipShort(t)
	rt := newRotationTest(t, 1)
	// The provider answers 200 but hands back the same IP on the first call;
	// the second call rotates for real.
	var calls atomic.Int64
	rt.api.OnCall(func() {
		if calls.Add(1) >= 2 {
			rt.trace.SetIP(rt.source[rt.sims[0]], "198.51.100.10")
		}
	})
	echo := NewEchoTarget(t)
	cfg := defaultGatewayConfig(nil)
	cfg.Manual = []ManualRouteConfig{rt.entry(rt.sims[0], "1500ms")}
	cfg.Rotation = fastRotation(rt.trace)
	g := startRotationGateway(t, cfg, rt.trace)

	// First attempt: an unchanged IP ends in stale with a retry hint, and the
	// stale route keeps serving traffic.
	waitRotation(t, g, rt.sims[0], "to go stale after a same-IP rotation",
		func(v *RotationView) bool { return v.State == "stale" && v.ConsecutiveSameIP == 1 }, 8*time.Second)
	v := rotationView(t, g, rt.sims[0])
	if v.NextRetryIn == "" {
		t.Fatalf("stale view = %+v, want a retry hint", v)
	}
	GetVia(t, ProxyClient(g.MixedAddr), echo.URL+"/", "e2e-echo:/")

	waitRotation(t, g, rt.sims[0], "to recover to idle after a changed IP",
		func(v *RotationView) bool { return v.State == "idle" && v.LastIP == "198.51.100.10" }, 8*time.Second)
	if n := rt.api.Hits.Load(); n != 2 {
		t.Fatalf("rotate API calls=%d, want 2", n)
	}
	if got := stRotations(t, g); got != 1 {
		t.Fatalf("rotations=%d, want 1", got)
	}
}

func TestRotationAPIFailureSingleProbeThenStale(t *testing.T) {
	skipShort(t)
	rt := newRotationTest(t, 1)
	rt.api.Status.Store(http.StatusInternalServerError)
	cfg := defaultGatewayConfig(nil)
	cfg.Manual = []ManualRouteConfig{rt.entry(rt.sims[0], "1h")}
	cfg.Rotation = fastRotation(rt.trace)
	cfg.Rotation.RotateOnStart = true
	g := startRotationGateway(t, cfg, rt.trace)

	src := rt.source[rt.sims[0]]
	waitRotation(t, g, rt.sims[0], "to go stale after the failed API call",
		func(v *RotationView) bool { return v.State == "stale" }, 8*time.Second)
	if n := rt.api.Hits.Load(); n != 1 {
		t.Fatalf("rotate API calls=%d, want 1 (no in-band retries)", n)
	}
	// One baseline probe plus exactly one post-failure verification probe.
	if c := rt.trace.Calls(src); c != 2 {
		t.Fatalf("trace probes=%d, want 2", c)
	}
	time.Sleep(1500 * time.Millisecond)
	if c := rt.trace.Calls(src); c != 2 {
		t.Fatalf("trace probes grew to %d after the window, want a stable 2", c)
	}
}

func TestRotation429RetryAfterBoundsNextAttempt(t *testing.T) {
	skipShort(t)
	rt := newRotationTest(t, 1)
	rt.api.Status.Store(http.StatusTooManyRequests)
	rt.api.RetryAfter.Store("3")
	var calls atomic.Int64
	rt.api.OnCall(func() {
		if calls.Add(1) >= 2 {
			rt.api.Status.Store(http.StatusOK)
			rt.trace.SetIP(rt.source[rt.sims[0]], "198.51.100.10")
		}
	})
	cfg := defaultGatewayConfig(nil)
	cfg.Manual = []ManualRouteConfig{rt.entry(rt.sims[0], "500ms")}
	cfg.Rotation = fastRotation(rt.trace)
	g := startRotationGateway(t, cfg, rt.trace)

	waitRotations(t, g, 1, 15*time.Second)
	times := rt.api.Times()
	if len(times) != 2 {
		t.Fatalf("API calls=%d, want 2\nlogs:\n%s", len(times), g.Logs())
	}
	// The backoff would be ~500ms; the Retry-After floor must stretch the
	// gap to ~3s (jitter tolerance keeps the assert stable).
	if gap := times[1].Sub(times[0]); gap < 2500*time.Millisecond {
		t.Fatalf("second attempt %s after the 429, want >= the 3s Retry-After floor", gap)
	}
}

func TestRotationDeadRouteRotatesUnverified(t *testing.T) {
	skipShort(t)
	rt := newRotationTest(t, 1)
	rt.sims[0].Down.Store(true) // baseline probes observe a dead endpoint
	var calls atomic.Int64
	rt.api.OnCall(func() {
		if calls.Add(1) == 1 {
			rt.sims[0].Down.Store(false) // back up by verification time
			rt.trace.SetIP(rt.source[rt.sims[0]], "198.51.100.10")
		}
	})
	cfg := defaultGatewayConfig(nil)
	cfg.Manual = []ManualRouteConfig{rt.entry(rt.sims[0], "1h")}
	cfg.Rotation = fastRotation(rt.trace)
	cfg.Rotation.RotateOnStart = true
	g := startRotationGateway(t, cfg, rt.trace)

	waitRotation(t, g, rt.sims[0], "to record an unverified rotation",
		func(v *RotationView) bool { return v.State == "idle" && v.LastIP == "198.51.100.10" }, 15*time.Second)
	if got := stRotations(t, g); got != 1 {
		t.Fatalf("rotations=%d, want 1 unverified success\nlogs:\n%s", got, g.Logs())
	}
}

func TestRotationSingleManualRouteWindowReturns502(t *testing.T) {
	skipShort(t)
	rt := newRotationTest(t, 1)
	rt.flipOnCall()
	echo := NewEchoTarget(t)
	cfg := defaultGatewayConfig(nil)
	cfg.Manual = []ManualRouteConfig{rt.entry(rt.sims[0], "1h")}
	cfg.Rotation = fastRotation(rt.trace)
	cfg.Rotation.DrainTimeout = "500ms"
	cfg.Rotation.RotateOnStart = true
	rt.api.Hang = 2500 * time.Millisecond // widen the rotating window
	g := startRotationGateway(t, cfg, rt.trace)

	// While the only route is mid-rotation, requests get the ordinary
	// no-route 502; afterwards traffic flows again.
	client := ProxyClient(g.MixedAddr)
	deadline := time.Now().Add(6 * time.Second)
	saw502 := false
	for time.Now().Before(deadline) {
		resp, err := client.Get(echo.URL + "/")
		if err != nil {
			t.Fatalf("request during rotation: %v", err)
		}
		body := make([]byte, 64)
		_, _ = resp.Body.Read(body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusBadGateway {
			saw502 = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !saw502 {
		t.Fatal("never observed the ordinary no-route 502 during the rotating window")
	}
	waitRotation(t, g, rt.sims[0], "to return to serving after the window",
		func(v *RotationView) bool { return v.State == "idle" && v.LastIP == "198.51.100.10" }, 10*time.Second)
	GetVia(t, client, echo.URL+"/", "e2e-echo:/")
}

func TestRotationReloadRemovesRouteAbortsProcedure(t *testing.T) {
	skipShort(t)
	rt := newRotationTest(t, 1)
	dead := deadRouteValue(t)
	rt.api.Hang = 8 * time.Second // park the procedure inside the API call
	cfg := defaultGatewayConfig([]RouteConfig{{Proxy: dead, Kind: "v4"}})
	cfg.Manual = []ManualRouteConfig{rt.entry(rt.sims[0], "1s")}
	cfg.Rotation = fastRotation(rt.trace)
	g := startRotationGateway(t, cfg, rt.trace)

	deadline := time.Now().Add(8 * time.Second)
	for rt.api.Hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(30 * time.Millisecond)
	}
	if rt.api.Hits.Load() == 0 {
		t.Fatal("procedure never reached the rotate API")
	}
	g.ReloadConfig(defaultGatewayConfig([]RouteConfig{{Proxy: dead, Kind: "v4"}}),
		[]string{strings.TrimPrefix(dead, "socks5://")})

	time.Sleep(2 * time.Second) // outlast the parked API call
	if n := rt.api.Hits.Load(); n != 1 {
		t.Fatalf("rotate API calls=%d after removal, want a stable 1", n)
	}
	if got := stRotations(t, g); got != 0 {
		t.Fatalf("removed route still recorded a rotation: %d", got)
	}
	if logs := g.Logs(); strings.Contains(logs, "panic") {
		t.Fatalf("gateway panicked during removal:\n%s", logs)
	}
}

func TestRotationShutdownDuringProcedureExitsCleanly(t *testing.T) {
	skipShort(t)
	rt := newRotationTest(t, 1)
	rt.api.Hang = 30 * time.Second // park the procedure inside the API call
	cfg := defaultGatewayConfig(nil)
	cfg.Manual = []ManualRouteConfig{rt.entry(rt.sims[0], "1s")}
	cfg.Rotation = fastRotation(rt.trace)
	g := startRotationGateway(t, cfg, rt.trace)

	deadline := time.Now().Add(8 * time.Second)
	for rt.api.Hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(30 * time.Millisecond)
	}

	start := time.Now()
	if err := g.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal gateway: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- g.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		_ = g.cmd.Process.Kill()
		t.Fatalf("gateway ignored SIGTERM during a parked rotation\nlogs:\n%s", g.Logs())
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("shutdown took %s, want promptly after the engine cancel", elapsed)
	}
	if logs := g.Logs(); strings.Contains(logs, "panic") {
		t.Fatalf("shutdown produced a panic:\n%s", logs)
	}
	rt.api.ForceClose() // drop the parked rotate connection before cleanup
}

func TestRotationConfigRejectionsKeepLastGood(t *testing.T) {
	skipShort(t)
	rt := newRotationTest(t, 1)
	dead := deadRouteValue(t)
	base := func() GatewayConfig {
		cfg := defaultGatewayConfig([]RouteConfig{{Proxy: dead, Kind: "v4"}})
		cfg.Manual = []ManualRouteConfig{rt.entry(rt.sims[0], "1h")}
		cfg.Rotation = fastRotation(rt.trace)
		return cfg
	}
	g := startRotationGateway(t, base(), rt.trace)

	cases := []struct {
		name   string
		mutate func(*GatewayConfig)
	}{
		{"http ip-check-url", func(c *GatewayConfig) {
			c.Rotation.IPCheckURL = "http://127.0.0.1:1/trace"
		}},
		{"missing rotate-interval", func(c *GatewayConfig) {
			e := c.Manual[0]
			e.RotateInterval = ""
			c.Manual = []ManualRouteConfig{e}
		}},
		{"missing api url", func(c *GatewayConfig) {
			e := c.Manual[0]
			e.API.URL = ""
			c.Manual = []ManualRouteConfig{e}
		}},
		{"over-100 percent cap", func(c *GatewayConfig) {
			c.Rotation.MaxConcurrent = "150%"
		}},
		{"duplicate across pools", func(c *GatewayConfig) {
			c.Routes = append(c.Routes, RouteConfig{Proxy: rt.sims[0].RouteValue(), Kind: "v4"})
		}},
	}
	want := []string{strings.TrimPrefix(dead, "socks5://"), rt.sims[0].Addr} // auto first, then manual
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := base()
			tc.mutate(&bad)
			g.ReloadConfigRaw(renderConfig(bad))
			time.Sleep(2500 * time.Millisecond) // one poll cycle plus slack
			g.WaitForPool(want, 6*time.Second)  // last-good still serving
		})
	}
	if logs := g.Logs(); strings.Count(logs, "reload failed") < len(cases) {
		t.Fatalf("expected %d reload-failure warnings, logs:\n%s", len(cases), logs)
	}
}

func TestRotationLifecycleStatesVisibleInStatus(t *testing.T) {
	skipShort(t)
	rt := newRotationTest(t, 1)
	// Widen each phase so /status polling cannot miss it: the API call hangs
	// 300ms (rotating), and the provider only swaps the egress IP 800ms after
	// the call — 500ms after the answer — so verification polls repeatedly
	// before seeing the change (verifying).
	var flipped atomic.Bool
	rt.api.OnCall(func() {
		if flipped.CompareAndSwap(false, true) {
			time.AfterFunc(800*time.Millisecond, func() {
				rt.trace.SetIP(rt.source[rt.sims[0]], "198.51.100.10")
			})
		}
	})
	rt.api.Hang = 300 * time.Millisecond
	held := NewSlowBodyTarget(t, 2500*time.Millisecond)
	cfg := defaultGatewayConfig(nil)
	cfg.Manual = []ManualRouteConfig{rt.entry(rt.sims[0], "4s")}
	cfg.Rotation = fastRotation(rt.trace)
	cfg.Rotation.DrainTimeout = "5s"
	g := startRotationGateway(t, cfg, rt.trace)

	// A request held across the 4s mark keeps the route draining: at ~3.4s
	// the request is mid-flight (it ends ~5.9s), the interval fires at the
	// first tick past 4s, and the drain waits for it before rotating.
	time.Sleep(3400 * time.Millisecond)
	go func() {
		resp, err := ProxyClient(g.MixedAddr).Get(held.URL + "/held")
		if err == nil {
			resp.Body.Close()
		}
	}()

	seen := map[string]bool{}
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		v := rotationView(t, g, rt.sims[0])
		seen[v.State] = true
		if v.State == "idle" && v.LastIP == "198.51.100.10" {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	for _, want := range []string{"draining", "rotating", "verifying", "idle"} {
		if !seen[want] {
			t.Fatalf("lifecycle state %q never observed (seen=%v)\nlogs:\n%s", want, seen, g.Logs())
		}
	}
}
