package proxyserver

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/routing"
)

// The routing tests pin the serving-path contract: the router narrows which
// routes a target may use, the pool stays the sole authority on health and
// order, failures retry inside the candidate set, and tunnel bytes stay
// opaque to health. Domain targets are used throughout because only
// ATYP=DOMAIN can match a rule; "localhost" is the one name that resolves
// locally, so fake upstreams can dial it for real when a test needs a live
// target behind the CONNECT.

func labeledRoute(id string, u *url.URL) config.RouteSpec {
	return config.RouteSpec{ID: id, URL: u, Kind: config.EgressV4}
}

func mustCompileRouter(t *testing.T, spec routing.Spec) *routing.Router {
	t.Helper()
	router, err := routing.Compile(spec)
	if err != nil {
		t.Fatalf("routing.Compile(): %v", err)
	}
	return router
}

// connectSuccessRaw answers CONNECT with success and closes, so a test can
// prove which upstream a domain target was routed to without any DNS.
var connectSuccessRaw = []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}

// deadAddr returns a loopback address whose listener is already closed, so
// dialing it is a refused TCP connect.
func deadAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// TestRoutingCandidateIsolation pins the core promise: a rule-scoped target
// rotates only inside its candidate set and never touches the other set's
// routes; an unmatched target with no default routes fails closed with the
// ordinary general-failure reply; an IP target never matches a rule.
func TestRoutingCandidateIsolation(t *testing.T) {
	openaiA := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	openaiB := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	kiloC := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	pl := pool.NewRoutes([]config.RouteSpec{
		labeledRoute("openai-a", openaiA.URL),
		labeledRoute("openai-b", openaiB.URL),
		labeledRoute("kilo-c", kiloC.URL),
	}, 30*time.Second, time.Minute)

	var logs safeLogBuffer
	rt := defaultRuntime()
	rt.Routing = mustCompileRouter(t, routing.Spec{
		Rules: []routing.RuleSpec{{Domains: []string{"*.openai.com"}, Routes: []string{"openai-a", "openai-b"}}},
	})
	srv := newRuntimeServer(pl, rt, captureLogger(&logs))
	addr := startServer(t, srv)

	// The openai pair serves the openai target; round-robin visits both.
	seen := map[string]int{}
	for range 4 {
		conn, code := socksConnectReply(t, addr, "api.openai.com:80", socksCmdConnect)
		if code != socksReplySuccess {
			t.Fatalf("CONNECT reply = 0x%02x, want success", code)
		}
		_ = conn.Close()
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(openaiA.hits) >= 1 && len(openaiB.hits) >= 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if len(openaiA.hits) == 0 || len(openaiB.hits) == 0 {
		t.Fatalf("openai candidate hits = a:%d b:%d, want both visited", len(openaiA.hits), len(openaiB.hits))
	}
	seen["a"], seen["b"] = len(openaiA.hits), len(openaiB.hits)
	if got := len(kiloC.hits); got != 0 {
		t.Fatalf("kilo route hit %d times from an openai-scoped target", got)
	}

	// The unmatched domain fails closed: general failure, no upstream contact,
	// no_route with the empty candidate count.
	conn, code := socksConnectReply(t, addr, "unmatched.example:80", socksCmdConnect)
	_ = conn.Close()
	if code != socksReplyGeneral {
		t.Fatalf("unmatched CONNECT reply = 0x%02x, want general failure", code)
	}
	if got := len(kiloC.hits) + len(openaiA.hits) + len(openaiB.hits); got != 4 {
		t.Fatalf("unmatched target contacted an upstream (%d total hits), want none new", got)
	}
	output := waitForRecord(t, &logs, map[string]string{
		"msg": "tunnel failed", "request_id": "5",
		"error_kind": "no_route", "routing_candidates": "0",
	})
	if _, ok := findRecord(output, map[string]string{"msg": "route selected", "request_id": "5"}); ok {
		t.Errorf("unmatched target picked a route:\n%s", output)
	}

	// An IPv4 literal target carries no hostname, so it can never match the
	// rule: it lands in the (empty) default set and fails closed too.
	conn, code = socksConnectReply(t, addr, "127.0.0.1:80", socksCmdConnect)
	_ = conn.Close()
	if code != socksReplyGeneral {
		t.Fatalf("IP-target CONNECT reply = 0x%02x, want general failure", code)
	}

	// None of the failures mutated route health.
	for i, snap := range pl.Snapshot() {
		if snap.Failures != 0 || (snap.Successes == 0 && i < 2) {
			t.Fatalf("route %d state = %+v", i, snap)
		}
		if snap.TargetCooldowns != 0 || snap.TargetFailures != 0 {
			t.Fatalf("route %d pair state = %+v, want untouched", i, snap)
		}
	}
	if status := srv.ListenerStatus(); status.Failovers != 0 {
		t.Fatalf("failovers = %d with no in-scope failure", status.Failovers)
	}
}

// Two independent two-route candidate sets isolate symmetrically: openai
// traffic round-robins its pair and never touches a kilo route, kilo traffic
// round-robins its pair and never touches an openai route.
func TestRoutingTwoRouteServingSets(t *testing.T) {
	openaiA := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	openaiB := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	kiloC := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	kiloD := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	pl := pool.NewRoutes([]config.RouteSpec{
		labeledRoute("openai-a", openaiA.URL),
		labeledRoute("openai-b", openaiB.URL),
		labeledRoute("kilo-c", kiloC.URL),
		labeledRoute("kilo-d", kiloD.URL),
	}, 30*time.Second, time.Minute)

	rt := defaultRuntime()
	rt.Routing = mustCompileRouter(t, routing.Spec{
		Rules: []routing.RuleSpec{
			{Domains: []string{"*.openai.com"}, Routes: []string{"openai-a", "openai-b"}},
			{Domains: []string{"*.kilo.ai"}, Routes: []string{"kilo-c", "kilo-d"}},
		},
	})
	srv := newRuntimeServer(pl, rt, testLogger())
	addr := startServer(t, srv)

	for i := range 6 {
		target := "api.openai.com:80"
		if i >= 3 {
			target = "api.kilo.ai:80"
		}
		conn, code := socksConnectReply(t, addr, target, socksCmdConnect)
		if code != socksReplySuccess {
			t.Fatalf("CONNECT reply = 0x%02x, want success", code)
		}
		_ = conn.Close()
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(openaiA.hits)+len(openaiB.hits) >= 3 && len(kiloC.hits)+len(kiloD.hits) >= 3 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if len(openaiA.hits) == 0 || len(openaiB.hits) == 0 {
		t.Fatalf("openai set hits = a:%d b:%d, want the pair round-robined", len(openaiA.hits), len(openaiB.hits))
	}
	if len(kiloC.hits) == 0 || len(kiloD.hits) == 0 {
		t.Fatalf("kilo set hits = c:%d d:%d, want the pair round-robined", len(kiloC.hits), len(kiloD.hits))
	}
	if leaked := len(openaiA.hits) + len(openaiB.hits); leaked != 3 {
		t.Fatalf("openai set served %d requests, want exactly its 3", leaked)
	}
	if leaked := len(kiloC.hits) + len(kiloD.hits); leaked != 3 {
		t.Fatalf("kilo set served %d requests, want exactly its 3", leaked)
	}
}

// A route-level failure inside the candidate set falls back to the next
// candidate — never to a route outside the set.
func TestRoutingFallbackStaysInCandidateSet(t *testing.T) {
	dead := &url.URL{Scheme: "socks5", Host: deadAddr(t)}
	good := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	kiloC := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	pl := pool.NewRoutes([]config.RouteSpec{
		labeledRoute("openai-a", dead),
		labeledRoute("openai-b", good.URL),
		labeledRoute("kilo-c", kiloC.URL),
	}, 30*time.Second, time.Minute)

	rt := defaultRuntime()
	rt.Routing = mustCompileRouter(t, routing.Spec{
		Rules: []routing.RuleSpec{{Domains: []string{"*.openai.com"}, Routes: []string{"openai-a", "openai-b"}}},
	})
	var logs safeLogBuffer
	srv := newRuntimeServer(pl, rt, captureLogger(&logs))
	addr := startServer(t, srv)

	conn := socksDialVia(t, addr, "api.openai.com:80")
	_ = conn.Close()

	snap := pl.Snapshot()
	if snap[0].Failures != 1 || snap[0].Available {
		t.Fatalf("dead candidate state = %+v", snap[0])
	}
	if snap[1].Successes != 1 || snap[1].Failures != 0 {
		t.Fatalf("in-set fallback state = %+v", snap[1])
	}
	if snap[2].Successes != 0 || snap[2].Failures != 0 || len(kiloC.hits) != 0 {
		t.Fatalf("out-of-set route touched: %+v hits=%d", snap[2], len(kiloC.hits))
	}
	if status := srv.ListenerStatus(); status.Requests != 1 || status.Failovers != 1 {
		t.Fatalf("listener status = %+v, want one in-set fallback", status)
	}
	_ = waitForRecord(t, &logs, map[string]string{
		"msg": "route selected", "request_id": "1", "route_id": "openai-b",
	})
}

// A target-refused CONNECT (connect_target) retries within the candidate set
// and the pair-scoped cooldown leaves the refusing route available for every
// other target — routing changes none of that.
func TestRoutingConnectTargetRetriesInSet(t *testing.T) {
	refuser := startSocks5Proxy(t, socksOptions{connectRep: 0x05, refuseHost: "localhost"})
	good := startSocks5Proxy(t, socksOptions{})
	target := startEchoTarget(t)
	pl := pool.NewRoutes([]config.RouteSpec{
		labeledRoute("openai-a", refuser.URL),
		labeledRoute("openai-b", good.URL),
	}, 30*time.Second, time.Minute)

	rt := defaultRuntime()
	// The rule names "localhost" because this test needs the surviving route
	// to dial a real local target through the CONNECT; both candidates are in
	// the set, which is what the in-set retry needs.
	rt.Routing = mustCompileRouter(t, routing.Spec{
		Rules: []routing.RuleSpec{{Domains: []string{"localhost"}, Routes: []string{"openai-a", "openai-b"}}},
	})
	_, addr := newSocksServer(t, pl, rt, testLogger())

	_, port, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("split echo target: %v", err)
	}
	conn := socksDialVia(t, addr, net.JoinHostPort("localhost", port))
	_ = conn.Close()

	snap := pl.Snapshot()
	if snap[0].Available == false {
		t.Fatalf("pair refusal must not cool the route itself: %+v", snap[0])
	}
	if snap[0].TargetCooldowns != 1 || snap[1].Successes != 1 {
		t.Fatalf("pool state after in-set connect_target retry = %+v", snap)
	}
}

// A 429 inside an established tunnel is application traffic: the gateway
// relays it opaquely, health stays clean, and no failover happens.
func TestRoutingTunnelHTTP429NeverMutatesHealth(t *testing.T) {
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, "slow down")
	}))
	t.Cleanup(httpSrv.Close)
	u, err := url.Parse(httpSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split test server address: %v", err)
	}

	upstream := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes([]config.RouteSpec{labeledRoute("openai-a", upstream.URL)}, 30*time.Second, time.Minute)
	rt := defaultRuntime()
	rt.Routing = mustCompileRouter(t, routing.Spec{
		Rules:         []routing.RuleSpec{{Domains: []string{"*.openai.com"}, Routes: []string{"openai-a"}}},
		DefaultRoutes: []string{"openai-a"},
	})
	srv, addr := newSocksServer(t, pl, rt, testLogger())

	conn := socksDialVia(t, addr, net.JoinHostPort("localhost", port))
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: localhost:%s\r\nConnection: close\r\n\r\n", port)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = conn.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 relayed opaquely", resp.StatusCode)
	}

	snap := pl.Snapshot()[0]
	if snap.Successes != 1 || snap.Failures != 0 || snap.TargetFailures != 0 || snap.TargetCooldowns != 0 || !snap.Available {
		t.Fatalf("tunnel bytes mutated health: %+v", snap)
	}
	if status := srv.ListenerStatus(); status.Requests != 1 || status.Failovers != 0 {
		t.Fatalf("listener status = %+v, want one request and no failover", status)
	}
}

// Listener kind filtering and routing intersect: a rule may name a route the
// listener would never serve, and the intersection — not the rule alone —
// decides.
func TestRoutingIntersectsWithListenerKind(t *testing.T) {
	openaiA := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	kiloC := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	pl := pool.NewRoutes([]config.RouteSpec{
		labeledRoute("openai-a", openaiA.URL),
		{ID: "kilo-c", URL: kiloC.URL, Kind: config.EgressV6},
	}, 30*time.Second, time.Minute)

	rt := defaultRuntime()
	rt.Routing = mustCompileRouter(t, routing.Spec{
		Rules: []routing.RuleSpec{
			{Domains: []string{"*.openai.com"}, Routes: []string{"openai-a", "kilo-c"}},
			{Domains: []string{"*.kilo.ai"}, Routes: []string{"kilo-c"}},
		},
	})
	// A v4-only listener: kilo-c is outside its kind view.
	srv := NewRuntime(pool.NewStore(rt, pl), testLogger(), "test", "v4", config.EgressV4)
	addr := startServer(t, srv)

	conn, code := socksConnectReply(t, addr, "api.openai.com:80", socksCmdConnect)
	_ = conn.Close()
	if code != socksReplySuccess {
		t.Fatalf("openai CONNECT reply = 0x%02x, want success through the v4 candidate", code)
	}
	if got := len(kiloC.hits); got != 0 {
		t.Fatalf("v6 route served a v4 listener %d times", got)
	}

	// The kilo rule names only the v6 route: the intersection is empty, and
	// the request fails closed instead of leaking into the other kind.
	conn, code = socksConnectReply(t, addr, "api.kilo.ai:80", socksCmdConnect)
	_ = conn.Close()
	if code != socksReplyGeneral {
		t.Fatalf("kilo CONNECT reply = 0x%02x, want general failure", code)
	}
	if snap := pl.Snapshot()[1]; snap.Successes != 0 || snap.Failures != 0 {
		t.Fatalf("v6 route state = %+v, want untouched", snap)
	}
}

// A reload swaps the routing policy with its pool as one generation: new
// sessions follow the new rules immediately, and retained routes keep their
// health state across the swap.
func TestRoutingReloadSwapsPolicyAtomically(t *testing.T) {
	openaiA := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	kiloC := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	routes := []config.RouteSpec{
		labeledRoute("openai-a", openaiA.URL),
		labeledRoute("kilo-c", kiloC.URL),
	}
	pl := pool.NewRoutes(routes, 30*time.Second, time.Minute)

	before := defaultRuntime()
	before.Routes = routes
	before.Routing = mustCompileRouter(t, routing.Spec{
		Rules:         []routing.RuleSpec{{Domains: []string{"*.openai.com"}, Routes: []string{"openai-a"}}},
		DefaultRoutes: []string{"kilo-c"},
	})
	store := pool.NewStore(before, pl)
	srv := NewRuntime(store, testLogger(), "test", "mixed")
	addr := startServer(t, srv)

	conn := socksDialVia(t, addr, "api.openai.com:80")
	_ = conn.Close()
	if got := len(openaiA.hits); got != 1 {
		t.Fatalf("pre-reload hits on openai-a = %d, want 1", got)
	}

	// The reload moves the openai rule to kilo-c. The pool snapshot is
	// rebuilt through Reconfigure, retaining both entries.
	after := defaultRuntime()
	after.Routes = routes
	after.Routing = mustCompileRouter(t, routing.Spec{
		Rules:         []routing.RuleSpec{{Domains: []string{"*.openai.com"}, Routes: []string{"kilo-c"}}},
		DefaultRoutes: []string{"openai-a"},
	})
	store.Publish(after)

	conn = socksDialVia(t, addr, "api.openai.com:80")
	_ = conn.Close()
	if got := len(openaiA.hits); got != 1 {
		t.Fatalf("post-reload hits on openai-a = %d, want still 1", got)
	}
	if got := len(kiloC.hits); got != 1 {
		t.Fatalf("post-reload hits on kilo-c = %d, want 1", got)
	}

	// Health survived the swap: openai-a keeps its earlier success.
	snaps := pl.Snapshot()
	if snaps[0].Successes != 1 || snaps[0].ID != "openai-a" {
		t.Fatalf("retained route state = %+v", snaps[0])
	}
}
