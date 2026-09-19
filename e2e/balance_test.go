package e2e_test

import (
	"testing"
	"time"
)

// The family split is exact end to end: 40 mixed requests against a 3:1
// balance land 30 v4 / 10 v6 (one pick plus one success step per request),
// while a dedicated listener keeps serving only its own family.
func TestE2E_BalancedFamilySplit(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	v4 := NewSocksSim(t, SocksOK, "", "")
	v6 := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	cfg := defaultGatewayConfig([]RouteConfig{
		{Proxy: v4.RouteValue(), Kind: "v4"},
		{Proxy: v6.RouteValue(), Kind: "v6"},
	})
	cfg.Balance = &BalanceConfig{V4: 3, V6: 1}
	g := NewGateway(t, cfg)

	client := ProxyClient(g.MixedAddr)
	for range 40 {
		GetVia(t, client, target.URL+"/b", "e2e-echo:/b")
	}
	st := g.WaitForCondition(5*time.Second, "all balanced picks recorded", func(st *Status) bool {
		return len(st.Pool) == 2 && st.Pool[0].Successes+st.Pool[1].Successes == 40
	})
	if st.Pool[0].Successes != 30 || st.Pool[1].Successes != 10 {
		t.Fatalf("family split = %d/%d, want exact 30/10 for balance 3:1",
			st.Pool[0].Successes, st.Pool[1].Successes)
	}
	if v4.Hits.Load() != 30 || v6.Hits.Load() != 10 {
		t.Fatalf("simulator hits = %d/%d, want 30/10", v4.Hits.Load(), v6.Hits.Load())
	}

	dedicated := ProxyClient(g.V4Addr)
	for range 10 {
		GetVia(t, dedicated, target.URL+"/d", "e2e-echo:/d")
	}
	st = g.WaitForCondition(5*time.Second, "dedicated picks recorded", func(st *Status) bool {
		return st.Pool[0].Successes == 40
	})
	if st.Pool[1].Successes != 10 {
		t.Fatalf("v4 listener leaked into v6: %+v", st.Pool)
	}
	if v6.Hits.Load() != 10 {
		t.Fatalf("v6 simulator hits = %d, want 10 (dedicated listener only used v4)", v6.Hits.Load())
	}
}

// Reloading a new ratio retunes the split in place: the family clocks carry
// over (the next pick continues the handoff, not a restart), health counters
// survive, and the new ratio drives subsequent mixed picks.
func TestE2E_ReloadFlipsBalance(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	v4 := NewSocksSim(t, SocksOK, "", "")
	v6 := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	even := defaultGatewayConfig([]RouteConfig{
		{Proxy: v4.RouteValue(), Kind: "v4"},
		{Proxy: v6.RouteValue(), Kind: "v6"},
	})
	even.Balance = &BalanceConfig{V4: 1, V6: 1}
	g := NewGateway(t, even)

	client := ProxyClient(g.MixedAddr)
	for range 4 {
		GetVia(t, client, target.URL+"/b", "e2e-echo:/b")
	}
	g.WaitForCondition(5*time.Second, "even-split picks recorded", func(st *Status) bool {
		return len(st.Pool) == 2 && st.Pool[0].Successes == 2 && st.Pool[1].Successes == 2
	})

	heavy := defaultGatewayConfig([]RouteConfig{
		{Proxy: v4.RouteValue(), Kind: "v4"},
		{Proxy: v6.RouteValue(), Kind: "v6"},
	})
	heavy.Balance = &BalanceConfig{V4: 1, V6: 3}
	g.ReloadConfig(heavy, []string{v4.Addr, v6.Addr})
	st := g.WaitForCondition(reloadSettle, "retuned balance published", func(st *Status) bool {
		return st.Balance != nil && st.Balance.V4 == 1 && st.Balance.V6 == 3
	})
	if st.Pool[0].Successes != 2 || st.Pool[1].Successes != 2 {
		t.Fatalf("reload reset health counters: %+v", st.Pool)
	}

	for range 40 {
		GetVia(t, client, target.URL+"/b", "e2e-echo:/b")
	}
	st = g.WaitForCondition(5*time.Second, "post-reload picks recorded", func(st *Status) bool {
		return st.Pool[0].Successes+st.Pool[1].Successes == 44
	})
	if st.Pool[0].Successes != 12 || st.Pool[1].Successes != 32 {
		t.Fatalf("post-reload split = %d/%d, want 12/32 (2/2 kept + 10/30 for balance 1:3)",
			st.Pool[0].Successes, st.Pool[1].Successes)
	}
	if v4.Hits.Load() != 12 || v6.Hits.Load() != 32 {
		t.Fatalf("simulator hits = %d/%d, want 12/32", v4.Hits.Load(), v6.Hits.Load())
	}
}
