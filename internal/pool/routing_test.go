package pool

import (
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/routing"
	"rotation-proxy-gateway/internal/socksdial"
)

// namedRoute builds one auto route with an operator-facing routing label.
func namedRoute(t *testing.T, id, host string) config.RouteSpec {
	t.Helper()
	spec := config.RouteSpec{URL: mustURL(t, "socks5://TEST-user:TEST-pass@"+host+":1080"), Kind: config.EgressV4}
	if id != "" {
		spec.ID = id
	}
	return spec
}

func domainTarget(host string) socksdial.Target {
	return socksdial.Target{Host: host, Port: 443, Type: socksdial.AddrDomain}
}

// TestRouteIDRoundTrip pins the label's lifecycle: unnamed routes read empty,
// named routes read their id, /status carries it, and a reload that renames
// the route keeps the health state while swapping the label.
func TestRouteIDRoundTrip(t *testing.T) {
	pl := NewRoutes([]config.RouteSpec{
		namedRoute(t, "openai-a", "a.test"),
		namedRoute(t, "", "b.test"),
	}, 2*time.Second, time.Minute)

	first, second := pl.RoutePointers()[0], pl.RoutePointers()[1]
	if first.RouteID() != "openai-a" {
		t.Fatalf("RouteID() = %q, want openai-a", first.RouteID())
	}
	if second.RouteID() != "" {
		t.Fatalf("unnamed RouteID() = %q, want empty", second.RouteID())
	}
	snaps := pl.Snapshot()
	if snaps[0].ID != "openai-a" || snaps[1].ID != "" {
		t.Fatalf("/status ids = %q, %q; want openai-a, empty", snaps[0].ID, snaps[1].ID)
	}

	// Rename openai-a to openai-a2 without touching its URL+kind+origin: the
	// entry must be retained (success counter intact) with the new label.
	pl.ReportSuccess(first, "t.test")
	renamed := pl.Reconfigure([]config.RouteSpec{
		namedRoute(t, "openai-a2", "a.test"),
		namedRoute(t, "", "b.test"),
	}, 2*time.Second, time.Minute)
	entries := renamed.RoutePointers()
	if entries[0] != first {
		t.Fatal("Reconfigure rebuilt a renamed route; health state must be retained")
	}
	if entries[0].RouteID() != "openai-a2" {
		t.Fatalf("RouteID() after rename = %q, want openai-a2", entries[0].RouteID())
	}
	if got := renamed.Snapshot()[0].Successes; got != 1 {
		t.Fatalf("successes = %d after rename, want the retained 1", got)
	}
}

// TestPickForHonorsCandidateSet proves pool selection stays inside the
// candidate set the router computed: openai routes and the kilo route share
// one healthy pool, but a target routed to the openai pair can never be
// handed the kilo route, while round-robin continues inside the set.
func TestPickForHonorsCandidateSet(t *testing.T) {
	pl := NewRoutes([]config.RouteSpec{
		namedRoute(t, "openai-a", "a.test"),
		namedRoute(t, "openai-b", "b.test"),
		namedRoute(t, "kilo-a", "c.test"),
	}, 2*time.Second, time.Minute)

	router, err := routing.Compile(routing.Spec{
		Rules: []routing.RuleSpec{{Domains: []string{"api.openai.com"}, Routes: []string{"openai-a", "openai-b"}}},
	})
	if err != nil {
		t.Fatalf("routing.Compile(): %v", err)
	}
	inSet := func(candidates *routing.Set) func(*Proxy) bool {
		return func(p *Proxy) bool { return candidates.Allows(p.RouteID()) }
	}

	seen := map[string]int{}
	for range 10 {
		chosen := pl.PickFor(nil, inSet(router.Match(domainTarget("api.openai.com"))), "api.openai.com:443")
		if chosen == nil {
			t.Fatal("PickFor() = nil with two eligible candidates")
		}
		id := chosen.RouteID()
		if id != "openai-a" && id != "openai-b" {
			t.Fatalf("PickFor() leaked route %q outside the candidate set", id)
		}
		seen[id]++
		chosen.Release()
	}
	if seen["openai-a"] == 0 || seen["openai-b"] == 0 {
		t.Fatalf("candidate round-robin = %v, want both routes served", seen)
	}

	// The empty non-nil set fails closed: a target whose candidates match
	// nothing must not be handed any route from the shared pool.
	empty, err := routing.Compile(routing.Spec{
		Rules:         []routing.RuleSpec{{Domains: []string{"api.openai.com"}, Routes: []string{"openai-a"}}},
		DefaultRoutes: []string{"openai-a"},
	})
	if err != nil {
		t.Fatalf("routing.Compile(): %v", err)
	}
	routed := empty.Match(domainTarget("api.openai.com"))
	if !routed.Allows("openai-a") || routed.Allows("kilo-a") {
		t.Fatalf("candidates = %+v, want {openai-a}", routed)
	}

	// A nil set means unrestricted — the historical no-routing behavior — so
	// every route incl. kilo is reachable again.
	unrestricted := pl.PickFor(nil, nil, "other.example:443")
	if unrestricted == nil {
		t.Fatal("PickFor() = nil without routing")
	}
	unrestricted.Release()
}

// TestGenerationCarriesRouter pins the atomicity contract at the generation
// boundary: the router published is the configuration's compiled policy, and
// Publish swaps config, pool, and router as one snapshot.
func TestGenerationCarriesRouter(t *testing.T) {
	cfg := &config.RuntimeConfig{
		MaxRetries:   3,
		CooldownBase: 2 * time.Second,
		CooldownMax:  time.Minute,
		DialTimeout:  5 * time.Second,
		LogLevel:     "info",
		Routes: []config.RouteSpec{
			namedRoute(t, "openai-a", "a.test"),
			namedRoute(t, "kilo-a", "c.test"),
		},
		Routing: mustRouter(t, routing.Spec{
			Rules:         []routing.RuleSpec{{Domains: []string{"api.openai.com"}, Routes: []string{"openai-a"}}},
			DefaultRoutes: []string{"kilo-a"},
		}),
	}
	store := NewStore(cfg, NewRoutes(cfg.AllRoutes(), cfg.CooldownBase, cfg.CooldownMax))
	if store.Load().Router == nil {
		t.Fatal("Generation.Router = nil with a routing block configured")
	}
	if store.Load().Router != cfg.Routing {
		t.Fatal("Generation.Router is not the configured policy")
	}

	// A reload without a routing block publishes nil in the same atomic step.
	unrouted := *cfg
	unrouted.Routing = nil
	store.Publish(&unrouted)
	if store.Load().Router != nil {
		t.Fatal("Generation.Router != nil after publishing a config without routing")
	}
}

func mustRouter(t *testing.T, spec routing.Spec) *routing.Router {
	t.Helper()
	r, err := routing.Compile(spec)
	if err != nil {
		t.Fatalf("routing.Compile(): %v", err)
	}
	return r
}
