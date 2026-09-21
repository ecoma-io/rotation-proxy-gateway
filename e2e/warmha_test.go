package e2e_test

import (
	"testing"
	"time"
)

// HA scenarios with the warm pool armed: the adversarial complement of the
// latency A/B in warmab_test.go. Each benchmark runs one HA scenario against
// two fresh gateways — warm disabled (control) and enabled (candidate) — and
// reports both windows, so a regression in downtime-window success ratio or
// tail latency shows as a cold_/warm_ pair under benchstat:
//
//	TMPDIR=<dir-with-space> go test ./e2e/ -run=NONE -bench=WarmHA -count=5
//
// The question these answer is not "is warm faster" but "does keeping parked
// connections make failure handling worse": stale sockets meeting a dying
// endpoint, replenishment hammering a dead one, and recovery after the route
// returns. Failure windows here are the metric; borrow counters only prove
// which path served.
//
// Scenario shape is ha_test.go's: one 8s window, failure at 2.5s, recovery at
// 5s, fast cooldowns so a recovered route is re-admitted mid-window.

// warmHAGateway is haGateway with an optional warm-pool block.
func warmHAGateway(b *testing.B, routes []RouteConfig, warm *WarmPoolConfig) *Gateway {
	b.Helper()
	cfg := defaultGatewayConfig(routes)
	cfg.LogLevel = "error"
	cfg.CooldownBase = "1s"
	cfg.CooldownMax = "5s"
	cfg.WarmPool = warm
	g := NewGateway(b, cfg)
	if warm != nil {
		waitWarm(b, g, "fills to min-idle", func(v *WarmView) bool { return v.IdleTotal >= 2 }, 5*time.Second)
	} else {
		// Equalize the pair: the warm side spends its settle time filling.
		time.Sleep(2 * time.Second)
	}
	return g
}

// BenchmarkWarmHA_SingleProxyDowntime: four healthy routes, one dies for
// 2.5s mid-window and returns. Under warm, the dying route's parked
// connections meet the failure first on the borrow path — the discard and
// cold-dial fallback must keep the downtime window at least as good as the
// cold-only control.
func BenchmarkWarmHA_SingleProxyDowntime(b *testing.B) {
	if testing.Short() {
		b.Skip("e2e")
	}
	target := NewEchoTarget(b)
	for b.Loop() {
		simsCold, coldRoutes := haRoutes(b, 4)
		gCold := warmHAGateway(b, coldRoutes, nil)
		haDowntime(b, simsCold[0])
		reportLoad(b, "cold_", runLoad(b, gCold.MixedAddr, target.Host, haWorkers, haWindow, haPerOp))

		simsWarm, warmRoutes := haRoutes(b, 4)
		gWarm := warmHAGateway(b, warmRoutes, warmABConfig())
		haDowntime(b, simsWarm[0])
		res := runLoad(b, gWarm.MixedAddr, target.Host, haWorkers, haWindow, haPerOp)
		reportLoad(b, "warm_", res)
		reportWarmCounters(b, "warm_", gWarm, countOK(res))
	}
}

// BenchmarkWarmHA_ConcurrentDowntime: two of four routes fail at the same
// instant — half the pool — then both return. Under warm this halves the
// parked capacity too: borrowed connections from the dying pair must be
// discarded without leaking failures onto the surviving pair.
func BenchmarkWarmHA_ConcurrentDowntime(b *testing.B) {
	if testing.Short() {
		b.Skip("e2e")
	}
	target := NewEchoTarget(b)
	for b.Loop() {
		simsCold, coldRoutes := haRoutes(b, 4)
		gCold := warmHAGateway(b, coldRoutes, nil)
		haDowntime(b, simsCold[0], simsCold[1])
		reportLoad(b, "cold_", runLoad(b, gCold.MixedAddr, target.Host, haWorkers, haWindow, haPerOp))

		simsWarm, warmRoutes := haRoutes(b, 4)
		gWarm := warmHAGateway(b, warmRoutes, warmABConfig())
		haDowntime(b, simsWarm[0], simsWarm[1])
		res := runLoad(b, gWarm.MixedAddr, target.Host, haWorkers, haWindow, haPerOp)
		reportLoad(b, "warm_", res)
		reportWarmCounters(b, "warm_", gWarm, countOK(res))
	}
}
