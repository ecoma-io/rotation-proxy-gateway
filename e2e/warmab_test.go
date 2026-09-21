package e2e_test

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// Cold-vs-warm A/B benchmarks: one iteration runs the identical scenario
// against two fresh gateways — warm-pool disabled (control, today's behavior)
// and enabled (candidate) — and reports both windows under cold_/warm_
// prefixes, so benchstat over -count runs compares the pair under the same
// machine and load conditions:
//
//	go test ./e2e/ -run=NONE -bench=WarmAB -benchmem -count=5 | tee warmab.txt
//
// The upstream latency is the scenario axis: rtt=0ms is a free loopback hop
// (upstream setup is nearly free, the hardest case for any warm pool), while
// rtt=10ms/30ms shape the sims as remote endpoints whose greeting and CONNECT
// replies each cost one network round trip — the per-operation cost a parked
// half-handshake removes. The warm gateway additionally reports its borrow
// counters, proving the warm path actually served the window (borrow_ratio)
// instead of silently falling back to cold dials. Nothing here asserts
// correctness; the adversarial tests in warmpool_test.go own that.

// warmABRTTs are the upstream latency levels every A/B scenario runs at.
var warmABRTTs = []time.Duration{0, 10 * time.Millisecond, 30 * time.Millisecond}

// warmABConfig is one warm config for the paired scenarios: a per-route idle
// bound the steady traffic can actually consume and the default caps.
func warmABConfig() *WarmPoolConfig {
	return &WarmPoolConfig{
		Enabled:         true,
		MinIdlePerProxy: 2,
		MaxIdlePerProxy: 4,
		IdleTTL:         "45s",
	}
}

// warmABRoutes builds n v4 routes whose sims delay every protocol reply by
// rtt, modeling a remote endpoint.
func warmABRoutes(b *testing.B, n int, rtt time.Duration) []RouteConfig {
	b.Helper()
	sims, routes := haRoutes(b, n)
	for _, sim := range sims {
		sim.Latency.Store(int64(rtt))
	}
	return routes
}

// warmABGateway starts one gateway over routes; warm == nil keeps the pool
// disabled (the control side of the pair).
func warmABGateway(b *testing.B, routes []RouteConfig, warm *WarmPoolConfig) *Gateway {
	b.Helper()
	cfg := defaultGatewayConfig(routes)
	cfg.LogLevel = "error"
	cfg.WarmPool = warm
	g := NewGateway(b, cfg)
	if warm != nil {
		waitWarm(b, g, "fills to min-idle", func(v *WarmView) bool { return v.IdleTotal >= 2 }, 5*time.Second)
	} else {
		// Equalize the pair: the warm side spends its settle time filling,
		// so the control side idles the same wall-clock before measuring.
		time.Sleep(2 * time.Second)
	}
	return g
}

// reportWarmCounters publishes the warm pool's serving counters for one
// finished window: the share of operations served from a parked connection.
func reportWarmCounters(b *testing.B, prefix string, g *Gateway, ops float64) {
	b.Helper()
	st, err := g.Status()
	if err != nil {
		b.Fatalf("status: %v", err)
	}
	w := st.WarmPool
	if w == nil {
		b.Fatal("status has no warmPool section")
	}
	if ops > 0 {
		b.ReportMetric(float64(w.Borrowed)/ops, prefix+"borrow_ratio")
	}
	b.ReportMetric(float64(w.Borrowed), prefix+"borrowed_ops")
}

// countOK is the number of successful operations in one load window — the
// denominator for the warm borrow ratio.
func countOK(r *loadResult) float64 {
	var n int
	for _, s := range r.snapshot() {
		if s.ok {
			n++
		}
	}
	return float64(n)
}

// tunnelLoad drives one worker opening fresh inbound tunnels for window,
// closing each immediately: a sample's latency is pure tunnel setup — the
// exact cost a parked upstream connection can shorten. Payload round trips
// stay out of the measurement on purpose.
func tunnelLoad(tb testing.TB, proxyAddr, target string, window time.Duration) *loadResult {
	tb.Helper()
	res := &loadResult{window: window}
	start := time.Now()
	deadline := start.Add(window)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), haPerOp)
		setupStart := time.Now()
		conn, err := dialSocksTunnel(ctx, proxyAddr, target)
		cancel()
		ok := err == nil
		if ok {
			_ = conn.Close()
		}
		res.add(loadSample{at: time.Since(start), latency: time.Since(setupStart), ok: ok})
	}
	return res
}

// BenchmarkWarmAB_SteadyTunnels: two workers, each operation a fresh tunnel
// plus one small GET. This is the shape a warm pool is built for — steady,
// modest concurrency, where a parked half-handshake can absorb most of the
// per-operation upstream setup cost.
func BenchmarkWarmAB_SteadyTunnels(b *testing.B) {
	if testing.Short() {
		b.Skip("e2e")
	}
	target := NewEchoTarget(b)
	for _, rtt := range warmABRTTs {
		b.Run(fmt.Sprintf("rtt=%s", rtt), func(b *testing.B) {
			for b.Loop() {
				gCold := warmABGateway(b, warmABRoutes(b, 2, rtt), nil)
				resCold := runLoad(b, gCold.MixedAddr, target.Host, 2, 4*time.Second, haPerOp)
				reportLoad(b, "cold_", resCold)

				gWarm := warmABGateway(b, warmABRoutes(b, 2, rtt), warmABConfig())
				resWarm := runLoad(b, gWarm.MixedAddr, target.Host, 2, 4*time.Second, haPerOp)
				reportLoad(b, "warm_", resWarm)
				reportWarmCounters(b, "warm_", gWarm, countOK(resWarm))
			}
		})
	}
}

// BenchmarkWarmAB_BurstExhaust: low load, a 32-worker burst that outpaces any
// bounded pool, then low load again — the adversarial complement of the
// steady pair. The burst must fall back to cold dials without the low-load
// phases regressing; the borrow ratio makes the fallback visible instead of
// assumed.
func BenchmarkWarmAB_BurstExhaust(b *testing.B) {
	if testing.Short() {
		b.Skip("e2e")
	}
	target := NewEchoTarget(b)
	for _, rtt := range warmABRTTs {
		b.Run(fmt.Sprintf("rtt=%s", rtt), func(b *testing.B) {
			for b.Loop() {
				gCold := warmABGateway(b, warmABRoutes(b, 4, rtt), nil)
				reportLoad(b, "cold_low1_", runLoad(b, gCold.MixedAddr, target.Host, 2, 2*time.Second, haPerOp))
				reportLoad(b, "cold_burst_", runLoad(b, gCold.MixedAddr, target.Host, 32, 2*time.Second, haPerOp))
				reportLoad(b, "cold_low2_", runLoad(b, gCold.MixedAddr, target.Host, 2, 2*time.Second, haPerOp))

				gWarm := warmABGateway(b, warmABRoutes(b, 4, rtt), warmABConfig())
				resLow1 := runLoad(b, gWarm.MixedAddr, target.Host, 2, 2*time.Second, haPerOp)
				resBurst := runLoad(b, gWarm.MixedAddr, target.Host, 32, 2*time.Second, haPerOp)
				resLow2 := runLoad(b, gWarm.MixedAddr, target.Host, 2, 2*time.Second, haPerOp)
				reportLoad(b, "warm_low1_", resLow1)
				reportLoad(b, "warm_burst_", resBurst)
				reportLoad(b, "warm_low2_", resLow2)
				reportWarmCounters(b, "warm_", gWarm, countOK(resLow1)+countOK(resBurst)+countOK(resLow2))
			}
		})
	}
}

// BenchmarkWarmAB_TunnelSetupOnly: the pure setup signal. One worker opens
// fresh tunnels back to back — no payload round trip — so the measured cost
// is exactly the inbound handshake plus upstream establishment that a parked
// connection can shorten. The loop discards each tunnel immediately, which is
// the most borrow-friendly pattern any client could exhibit.
func BenchmarkWarmAB_TunnelSetupOnly(b *testing.B) {
	if testing.Short() {
		b.Skip("e2e")
	}
	target := NewEchoTarget(b)
	for _, rtt := range warmABRTTs {
		b.Run(fmt.Sprintf("rtt=%s", rtt), func(b *testing.B) {
			for b.Loop() {
				gCold := warmABGateway(b, warmABRoutes(b, 1, rtt), nil)
				reportLoad(b, "cold_", tunnelLoad(b, gCold.MixedAddr, target.Host, 2*time.Second))

				gWarm := warmABGateway(b, warmABRoutes(b, 1, rtt), warmABConfig())
				resWarm := tunnelLoad(b, gWarm.MixedAddr, target.Host, 2*time.Second)
				reportLoad(b, "warm_", resWarm)
				reportWarmCounters(b, "warm_", gWarm, countOK(resWarm))
			}
		})
	}
}
