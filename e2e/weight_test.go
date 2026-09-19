package e2e_test

import (
	"testing"
	"time"
)

// The weighted pass clock is deterministic end to end: 40 requests against a
// 1:3 weight split land exactly 10/30 when every request succeeds (one pick
// plus one success step per request).
func TestE2E_WeightedPickDistribution(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	light := NewSocksSim(t, SocksOK, "", "")
	heavy := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: light.RouteValue(), Kind: "v4", Weight: 1},
		{Proxy: heavy.RouteValue(), Kind: "v4", Weight: 3},
	}))

	client := ProxyClient(g.MixedAddr)
	for range 40 {
		GetVia(t, client, target.URL+"/w", "e2e-echo:/w")
	}

	st := g.WaitForCondition(5*time.Second, "all weighted picks recorded", func(st *Status) bool {
		return len(st.Pool) == 2 && st.Pool[0].Successes+st.Pool[1].Successes == 40
	})
	if st.Pool[0].Weight != 1 || st.Pool[1].Weight != 3 {
		t.Fatalf("status weights = %d/%d, want 1/3", st.Pool[0].Weight, st.Pool[1].Weight)
	}
	if st.Pool[0].Successes != 10 || st.Pool[1].Successes != 30 {
		t.Fatalf("success split = %d/%d, want exact 10/30 for weights 1:3",
			st.Pool[0].Successes, st.Pool[1].Successes)
	}
	if light.Hits.Load() != 10 || heavy.Hits.Load() != 30 {
		t.Fatalf("simulator hits = %d/%d, want 10/30", light.Hits.Load(), heavy.Hits.Load())
	}
}

// Reloading a weight retunes the retained route in place: the pool identity
// and its health counters survive, and the new ratio drives subsequent picks.
func TestE2E_ReloadRetunesWeightKeepingCounters(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	light := NewSocksSim(t, SocksOK, "", "")
	heavy := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	before := defaultGatewayConfig([]RouteConfig{
		{Proxy: light.RouteValue(), Kind: "v4", Weight: 1},
		{Proxy: heavy.RouteValue(), Kind: "v4", Weight: 1},
	})
	g := NewGateway(t, before)

	client := ProxyClient(g.MixedAddr)
	for range 4 {
		GetVia(t, client, target.URL+"/w", "e2e-echo:/w")
	}
	g.WaitForCondition(5*time.Second, "equal-weight picks recorded", func(st *Status) bool {
		return len(st.Pool) == 2 && st.Pool[0].Successes == 2 && st.Pool[1].Successes == 2
	})

	after := defaultGatewayConfig([]RouteConfig{
		{Proxy: light.RouteValue(), Kind: "v4", Weight: 1},
		{Proxy: heavy.RouteValue(), Kind: "v4", Weight: 3},
	})
	g.ReloadConfig(after, []string{light.Addr, heavy.Addr})
	st := g.WaitForCondition(reloadSettle, "retuned weights published", func(st *Status) bool {
		return len(st.Pool) == 2 && st.Pool[0].Weight == 1 && st.Pool[1].Weight == 3
	})
	if st.Pool[0].Successes != 2 || st.Pool[1].Successes != 2 {
		t.Fatalf("reload reset health counters: %+v", st.Pool)
	}

	for range 40 {
		GetVia(t, client, target.URL+"/w", "e2e-echo:/w")
	}
	st = g.WaitForCondition(5*time.Second, "post-reload picks recorded", func(st *Status) bool {
		return st.Pool[0].Successes+st.Pool[1].Successes == 44
	})
	if st.Pool[0].Successes != 12 || st.Pool[1].Successes != 32 {
		t.Fatalf("post-reload split = %d/%d, want 12/32 (2/2 kept + 10/30 for weights 1:3)",
			st.Pool[0].Successes, st.Pool[1].Successes)
	}
	if light.Hits.Load() != 12 || heavy.Hits.Load() != 32 {
		t.Fatalf("simulator hits = %d/%d, want 12/32", light.Hits.Load(), heavy.Hits.Load())
	}
}
