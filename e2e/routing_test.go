package e2e_test

import (
	"strings"
	"testing"
)

// The routing e2e tests drive the real binary: a routing block narrows which
// upstream routes a domain target may use, the shared pool keeps its health
// semantics inside that scope, and a reload swaps policy and pool as one
// generation. Only domain targets can match a rule, so every routed request
// uses a name; the sims tunnel to a local echo instead of the named
// destination (the same trick as the address-type tests), so names are
// matched, never resolved.

func routingSims(t *testing.T) (openaiA, openaiB, kiloC *SocksSim, echo *TargetSim) {
	t.Helper()
	openaiA = NewSocksSim(t, SocksOK, "", "")
	openaiB = NewSocksSim(t, SocksOK, "", "")
	kiloC = NewSocksSim(t, SocksOK, "", "")
	echo = NewEchoTarget(t)
	openaiA.TunnelTo = echo.Host
	openaiB.TunnelTo = echo.Host
	kiloC.TunnelTo = echo.Host
	return openaiA, openaiB, kiloC, echo
}

func openaiRouting() *RoutingConfig {
	return &RoutingConfig{
		Rules: []RoutingRuleConfig{
			{Domains: []string{"*.openai.com"}, Routes: []string{"openai-a", "openai-b"}},
		},
	}
}

func labeledRoutes3(openaiA, openaiB, kiloC *SocksSim) []RouteConfig {
	return []RouteConfig{
		{ID: "openai-a", Proxy: openaiA.RouteValue(), Kind: "v4"},
		{ID: "openai-b", Proxy: openaiB.RouteValue(), Kind: "v4"},
		{ID: "kilo-c", Proxy: kiloC.RouteValue(), Kind: "v6"},
	}
}

func TestE2E_RoutingCandidateIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	openaiA, openaiB, kiloC, _ := routingSims(t)
	cfg := defaultGatewayConfig(labeledRoutes3(openaiA, openaiB, kiloC))
	cfg.Routing = openaiRouting()
	cfg.Routing.DefaultRoutes = []string{"kilo-c"}
	g := NewGateway(t, cfg)

	// The openai rule's candidates rotate between the two openai routes.
	for range 4 {
		GetVia(t, ProxyClient(g.MixedAddr), "http://api.openai.com/round", "e2e-echo:/round")
	}
	if openaiA.Hits.Load() == 0 || openaiB.Hits.Load() == 0 {
		t.Fatalf("openai candidate hits = a:%d b:%d, want both visited", openaiA.Hits.Load(), openaiB.Hits.Load())
	}
	if kiloC.Hits.Load() != 0 {
		t.Fatalf("kilo route hit %d times from openai-scoped targets", kiloC.Hits.Load())
	}

	// An unmatched domain falls to the default set: kilo-c only.
	GetVia(t, ProxyClient(g.MixedAddr), "http://api.kilo.ai/other", "e2e-echo:/other")
	if openaiA.Hits.Load()+openaiB.Hits.Load() != 4 {
		t.Fatalf("default-routes request leaked into the openai pair (hits a:%d b:%d)",
			openaiA.Hits.Load(), openaiB.Hits.Load())
	}

	st, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Pool) != 3 {
		t.Fatalf("pool has %d routes, want 3", len(st.Pool))
	}
	for i, want := range []string{"openai-a", "openai-b", "kilo-c"} {
		if st.Pool[i].ID != want {
			t.Fatalf("pool[%d].id = %q, want %q", i, st.Pool[i].ID, want)
		}
	}
}

func TestE2E_RoutingUnmatchedFailsClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	openaiA, openaiB, kiloC, _ := routingSims(t)
	cfg := defaultGatewayConfig(labeledRoutes3(openaiA, openaiB, kiloC))
	// A rule and no default-routes key: unmatched targets have no candidates.
	cfg.Routing = &RoutingConfig{
		Rules: []RoutingRuleConfig{
			{Domains: []string{"*.openai.com"}, Routes: []string{"openai-a"}},
		},
	}
	g := NewGateway(t, cfg)

	GetVia(t, ProxyClient(g.MixedAddr), "http://api.openai.com/", "e2e-echo:/")
	failedSocksTunnel(t, g.MixedAddr, "unmatched.example:80")
	// An IP target carries no hostname and can never match a rule.
	failedSocksTunnel(t, g.MixedAddr, "127.0.0.1:1")

	// Fail-closed targets leave route health untouched.
	st, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Failovers != 0 {
		t.Fatalf("failovers = %d with no in-scope failure", st.Failovers)
	}
	for _, entry := range st.Pool {
		if entry.Failures != 0 || entry.TargetFailures != 0 {
			t.Fatalf("route %s state = %+v, want untouched", entry.ID, entry)
		}
	}
}

func TestE2E_RoutingFailoverStaysInSet(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	openaiA := NewSocksSim(t, SocksRejectTarget, "", "")
	openaiA.RefuseHost = "api.openai.com"
	openaiB := NewSocksSim(t, SocksOK, "", "")
	kiloC := NewSocksSim(t, SocksOK, "", "")
	echo := NewEchoTarget(t)
	openaiB.TunnelTo = echo.Host
	kiloC.TunnelTo = echo.Host

	cfg := defaultGatewayConfig(labeledRoutes3(openaiA, openaiB, kiloC))
	cfg.Routing = openaiRouting()
	g := NewGateway(t, cfg)

	GetVia(t, ProxyClient(g.MixedAddr), "http://api.openai.com/", "e2e-echo:/")

	if openaiA.Hits.Load() != 1 || openaiB.Hits.Load() != 1 {
		t.Fatalf("hits = refuser:%d ok:%d, want one attempt each inside the set",
			openaiA.Hits.Load(), openaiB.Hits.Load())
	}
	if kiloC.Hits.Load() != 0 {
		t.Fatalf("failover escaped the candidate set (kilo hits = %d)", kiloC.Hits.Load())
	}
	st, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Failovers != 1 {
		t.Fatalf("failovers = %d, want 1", st.Failovers)
	}
	// The refusal is target-scoped: the refusing route itself stays available.
	for _, entry := range st.Pool {
		if entry.ID == "openai-a" && !entry.Available {
			t.Fatalf("refusing route left unavailable: %+v", entry)
		}
	}
}

func TestE2E_RoutingReloadSwapsPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	openaiA, openaiB, kiloC, _ := routingSims(t)
	cfg := defaultGatewayConfig(labeledRoutes3(openaiA, openaiB, kiloC))
	cfg.Routing = openaiRouting()
	cfg.Routing.DefaultRoutes = []string{"kilo-c"}
	g := NewGateway(t, cfg)

	GetVia(t, ProxyClient(g.MixedAddr), "http://api.openai.com/before", "e2e-echo:/before")
	if openaiA.Hits.Load() != 1 || kiloC.Hits.Load() != 0 {
		t.Fatalf("pre-reload hits = openai-a:%d kilo:%d", openaiA.Hits.Load(), kiloC.Hits.Load())
	}

	cfg.Routing.Rules[0].Routes = []string{"kilo-c"}
	cfg.Routing.DefaultRoutes = []string{"openai-a"}
	g.ReloadConfig(cfg, []string{openaiA.Addr, openaiB.Addr, kiloC.Addr})
	waitForLogRecord(t, g, map[string]string{"msg": "configuration reloaded", "source": "poll"}, reloadSettle)

	GetVia(t, ProxyClient(g.MixedAddr), "http://api.openai.com/after", "e2e-echo:/after")
	if openaiA.Hits.Load() != 1 || kiloC.Hits.Load() != 1 {
		t.Fatalf("post-reload hits = openai-a:%d kilo:%d, want the rule to have moved",
			openaiA.Hits.Load(), kiloC.Hits.Load())
	}
}

func TestE2E_RoutingInvalidReloadKeepsServing(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	openaiA, openaiB, kiloC, _ := routingSims(t)
	cfg := defaultGatewayConfig(labeledRoutes3(openaiA, openaiB, kiloC))
	cfg.Routing = openaiRouting()
	cfg.Routing.DefaultRoutes = []string{"kilo-c"}
	g := NewGateway(t, cfg)

	GetVia(t, ProxyClient(g.MixedAddr), "http://api.openai.com/before", "e2e-echo:/before")

	// A rule referencing a route id no route carries must reject the whole
	// reload and keep the last-known-good generation serving.
	broken := defaultGatewayConfig(labeledRoutes3(openaiA, openaiB, kiloC))
	broken.Routing = openaiRouting()
	broken.Routing.Rules[0].Routes = []string{"openai-a", "ghost-route"}
	g.ReloadConfigRaw(renderConfig(broken))
	g.WaitForCondition(reloadSettle, "a rejected routing reload to keep the previous policy serving",
		func(*Status) bool {
			return strings.Contains(g.Logs(), "references route id") &&
				strings.Contains(g.Logs(), "reload failed; keeping previous configuration")
		})

	GetVia(t, ProxyClient(g.MixedAddr), "http://api.openai.com/after", "e2e-echo:/after")
	if kiloC.Hits.Load() != 0 {
		t.Fatalf("rejected reload changed serving (kilo hits = %d)", kiloC.Hits.Load())
	}
	st, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Pool) != 3 {
		t.Fatalf("pool after the rejected reload has %d routes, want the last-known-good 3", len(st.Pool))
	}

	// A malformed pattern is rejected by the same load-time pass, not just
	// reference checks: the last-known-good policy keeps serving.
	malformed := defaultGatewayConfig(labeledRoutes3(openaiA, openaiB, kiloC))
	malformed.Routing = openaiRouting()
	malformed.Routing.Rules[0].Domains = []string{"*.*.openai.com"}
	g.ReloadConfigRaw(renderConfig(malformed))
	g.WaitForCondition(reloadSettle, "a rejected routing pattern to keep the previous policy serving",
		func(*Status) bool {
			return strings.Contains(g.Logs(), "invalid domain pattern") &&
				strings.Contains(g.Logs(), "reload failed; keeping previous configuration")
		})

	GetVia(t, ProxyClient(g.MixedAddr), "http://api.openai.com/after2", "e2e-echo:/after2")
	if kiloC.Hits.Load() != 0 {
		t.Fatalf("rejected pattern reload changed serving (kilo hits = %d)", kiloC.Hits.Load())
	}
}
