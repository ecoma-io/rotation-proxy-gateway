package e2e_test

import (
	"testing"
	"time"
)

// The issue #5 incident, reproduced: an upstream that accepts the SOCKS
// greeting but refuses CONNECT to one destination used to cool the whole
// route pool, so a poisoned target denied every unrelated target for the
// backoff window. The refusal must land on the (route, target) pair instead:
// the route stays available, repeated traffic to the bad target escalates the
// pair's cooldown without touching route health, and an unrelated target
// keeps being served by the same route throughout.
func TestE2E_ConnectTargetRefusalKeepsPoolAvailable(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksRejectTarget, "", "")
	socks.RefuseHost = "blocked.example"
	target := NewEchoTarget(t)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}))

	// Traffic to the refused target fails visibly — with a single route the
	// pool exhausts to the no-route general-failure reply.
	failedSocksTunnel(t, g.MixedAddr, "blocked.example:80")

	st := g.WaitForCondition(5*time.Second, "pair cooldown recorded", func(st *Status) bool {
		return len(st.Pool) == 1 && st.Pool[0].TargetCooldowns == 1
	})
	pool0 := st.Pool[0]
	if !pool0.Available {
		t.Fatalf("route melted after one refused target: %+v", pool0)
	}
	if pool0.Failures != 0 || pool0.CooldownFor != "0s" {
		t.Fatalf("route-level health moved on a target-scoped refusal: %+v", pool0)
	}
	if pool0.TargetFailures != 1 {
		t.Fatalf("targetFailures = %d, want 1: %+v", pool0.TargetFailures, pool0)
	}
	recs := waitForLogRecord(t, g, map[string]string{"error_kind": "connect_target"}, 5*time.Second)
	rec, ok := findLogRecord(recs, map[string]string{"error_kind": "connect_target"})
	if !ok || !recordHasKey(rec, "cooldown") {
		t.Fatalf("connect_target record missing cooldown: %v", rec)
	}

	// The refusal rate-limits further attempts to the same target: the pair
	// is cooling, the sole route is handed out only by the all-cooling
	// fallback, and the upstream sees the escalated retries bounded by the
	// request's own retry chain — the route-level counters still never move.
	failedSocksTunnel(t, g.MixedAddr, "blocked.example:80")
	st = g.WaitForCondition(5*time.Second, "second refusal counted", func(st *Status) bool {
		return len(st.Pool) == 1 && st.Pool[0].TargetFailures == 2
	})
	if st.Pool[0].TargetCooldowns != 1 {
		t.Fatalf("targetCooldowns = %d, want 1 (one pair, escalating): %+v", st.Pool[0].TargetCooldowns, st.Pool[0])
	}

	// An unrelated target is served by the same route the whole time — the
	// property the incident showed the old scoping broke.
	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/", "e2e-echo:/")
	st = g.WaitForCondition(5*time.Second, "unrelated target served", func(st *Status) bool {
		return len(st.Pool) == 1 && st.Pool[0].Successes == 1
	})
	if !st.Pool[0].Available {
		t.Fatalf("route unavailable after serving an unrelated target: %+v", st.Pool[0])
	}
	// Failovers stay the two in-band fallbacks of the refused-target requests;
	// the successful request contributed none.
	if st.Failovers != 2 {
		t.Fatalf("failovers = %d, want the 2 refused-target fallbacks: %+v", st.Failovers, st)
	}
}
