package e2e_test

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// HA benchmarks: deterministic failure, rotation, and burst scenarios driven
// against the real binary, measured as traffic-level outcomes (success ratio,
// latency percentiles, failure counts) so behavior changes compare as
// distributions instead of single observations. Each iteration runs one full
// scenario window against a fresh gateway, sims, and target:
//
//	go test ./e2e/ -run=NONE -bench=HA -benchmem -count=5
//
// A/B usage: capture once with the feature under test disabled and once
// enabled on the same machine, then compare with benchstat per BENCH.md.
// These benchmarks never assert pool internals — /status assertions live in
// the functional tests; the benchmarks only measure what a client observes.

// Scenario shape: one 8s window, failure injection at 2.5s, recovery at 5s,
// so every iteration sees downtime and post-recovery phases of equal length.
const (
	haWindow  = 8 * time.Second
	haDownAt  = 2500 * time.Millisecond
	haUpAt    = 5 * time.Second
	haWorkers = 8
	haPerOp   = 2 * time.Second
)

// haRoutes builds n healthy v4 auto routes over distinct SOCKS sims.
func haRoutes(b *testing.B, n int) ([]*SocksSim, []RouteConfig) {
	b.Helper()
	sims := make([]*SocksSim, n)
	routes := make([]RouteConfig, n)
	for i := range n {
		sims[i] = NewSocksSim(b, SocksOK, "", "")
		routes[i] = RouteConfig{Proxy: sims[i].RouteValue(), Kind: "v4"}
	}
	return sims, routes
}

// haGateway starts a gateway for HA scenarios: fast cooldowns so a recovered
// route is re-admitted inside one window, and error-only logging so log
// volume stays out of the measurement.
func haGateway(b *testing.B, routes []RouteConfig) *Gateway {
	b.Helper()
	cfg := defaultGatewayConfig(routes)
	cfg.LogLevel = "error"
	cfg.CooldownBase = "1s"
	cfg.CooldownMax = "5s"
	return NewGateway(b, cfg)
}

// haDowntime flips sim down at haDownAt and healthy again at haUpAt.
func haDowntime(b *testing.B, sims ...*SocksSim) {
	b.Helper()
	go func() {
		time.Sleep(haDownAt)
		for _, sim := range sims {
			sim.Down.Store(true)
		}
		time.Sleep(haUpAt - haDownAt)
		for _, sim := range sims {
			sim.Down.Store(false)
		}
	}()
}

func reportHADowntime(b *testing.B, res *loadResult) {
	b.Helper()
	reportLoad(b, "", res)
	b.ReportMetric(res.successRatioBetween(haDownAt, haUpAt), "downtime_success_ratio")
	b.ReportMetric(res.percentileBetween(haDownAt, haUpAt, 0.95), "downtime_p95_ms")
	b.ReportMetric(res.percentileBetween(haDownAt, haUpAt, 0.99), "downtime_p99_ms")
	b.ReportMetric(res.successRatioBetween(haUpAt, time.Duration(1<<62)), "recovered_success_ratio")
}

// BenchmarkHA_SingleProxyDowntime: four healthy routes; one goes down for
// 2.5s mid-window and comes back. Downtime-window success ratio and tail
// latency are the HA numbers; the phases around it are the control.
func BenchmarkHA_SingleProxyDowntime(b *testing.B) {
	if testing.Short() {
		b.Skip("e2e")
	}
	target := NewEchoTarget(b)
	for b.Loop() {
		sims, routes := haRoutes(b, 4)
		g := haGateway(b, routes)
		haDowntime(b, sims[0])
		res := runLoad(b, g.MixedAddr, target.Host, haWorkers, haWindow, haPerOp)
		reportHADowntime(b, res)
	}
}

// BenchmarkHA_ConcurrentDowntime: two of four routes fail at the same
// instant — the shape that stresses fallback selection and any bounded
// background replenishment far harder than a single failure.
func BenchmarkHA_ConcurrentDowntime(b *testing.B) {
	if testing.Short() {
		b.Skip("e2e")
	}
	target := NewEchoTarget(b)
	for b.Loop() {
		sims, routes := haRoutes(b, 4)
		g := haGateway(b, routes)
		haDowntime(b, sims[0], sims[1])
		res := runLoad(b, g.MixedAddr, target.Host, haWorkers, haWindow, haPerOp)
		reportHADowntime(b, res)
	}
}

// BenchmarkHA_RotationUnderTraffic: two manual routes rotating continuously
// under steady load — a fresh egress IP per rotate call on a 1.5s cadence,
// serialized by the concurrency cap. Measures what rotation windows (drain,
// baseline, rotate, verify) cost a serving pool and its tail latency.
func BenchmarkHA_RotationUnderTraffic(b *testing.B) {
	if testing.Short() {
		b.Skip("e2e")
	}
	target := NewEchoTarget(b)
	for b.Loop() {
		trace := NewTraceSim(b, "203.0.113.1")
		api := NewRotateAPISim(b)
		sims := make([]*SocksSim, 2)
		manual := make([]ManualRouteConfig, 2)
		for i := range sims {
			sim := NewSocksSim(b, SocksOK, "", "")
			sim.Outbound = fmt.Sprintf("127.0.2.%d", i+1)
			sims[i] = sim
			manual[i] = ManualRouteConfig{
				Proxy:          sim.RouteValue(),
				Kind:           "v4",
				RotateInterval: "1500ms",
				API: ManualAPIConfig{
					URL:     api.URL,
					Method:  "POST",
					Timeout: "2s",
					Headers: map[string]string{"X-Api-Token": "e2e-ha-token"},
				},
			}
		}
		// Every rotate call moves that route's egress to a fresh unique
		// address, so each scheduled rotation verifies as changed and the
		// cycle never stalls on same-IP retries.
		var calls atomic.Int64
		api.OnCall(func() {
			n := int(calls.Add(1))
			sim := sims[(n-1)%len(sims)]
			trace.SetIP(sim.Outbound, fmt.Sprintf("198.51.100.%d", n+9))
		})
		cfg := defaultGatewayConfig(nil)
		cfg.LogLevel = "error"
		cfg.Manual = manual
		cfg.Rotation = &RotationConfig{
			MaxConcurrent:   "1",
			DrainTimeout:    "2s",
			IPCheckURL:      trace.URL,
			IPCheckTimeout:  "3s",
			IPCheckInterval: "100ms",
			RetryBackoffMax: "5s",
		}
		g := NewGatewayWithEnv(b, cfg, "SSL_CERT_FILE="+trace.CAFile)
		res := runLoad(b, g.MixedAddr, target.Host, haWorkers, haWindow, haPerOp)
		reportLoad(b, "", res)
		if st, err := g.Status(); err == nil {
			b.ReportMetric(float64(st.Rotations), "rotations")
		}
	}
}

// BenchmarkHA_BurstExhaust: steady low load, then a 32-worker burst that
// would exhaust any warm capacity, then low load again. Cold fallback must
// absorb the burst without breaking the low-load phases around it; warm
// refill afterward is asserted by functional tests, not here.
func BenchmarkHA_BurstExhaust(b *testing.B) {
	if testing.Short() {
		b.Skip("e2e")
	}
	target := NewEchoTarget(b)
	for b.Loop() {
		_, routes := haRoutes(b, 4)
		g := haGateway(b, routes)
		reportLoad(b, "low1_", runLoad(b, g.MixedAddr, target.Host, 2, 2*time.Second, haPerOp))
		reportLoad(b, "burst_", runLoad(b, g.MixedAddr, target.Host, 32, 2*time.Second, haPerOp))
		reportLoad(b, "low2_", runLoad(b, g.MixedAddr, target.Host, 2, 2*time.Second, haPerOp))
	}
}
