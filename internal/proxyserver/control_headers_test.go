package proxyserver

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/routing"
	"rotation-proxy-gateway/internal/socksdial"
)

// The two gateway-private control headers: x-ecoma-proxy-family narrows the
// eligible route set for one request, x-ecoma-request-id correlates its log
// lines. Neither is part of route identity, neither reaches an upstream, and
// the family composes by intersection with the listener's kind filter and the
// routing policy rather than becoming a second selection path.

// A CONNECT request carrying arbitrary extra header lines, so a test can pin
// a control header's ingress handling without hand-writing a request frame.
// The Host header repeats the tunnel authority, which is what a well-behaved
// client sends.
func connectWithHeaders(target string, headers ...string) []byte {
	var frame strings.Builder
	frame.WriteString("CONNECT " + target + " HTTP/1.1\r\n")
	frame.WriteString("Host: " + target + "\r\n")
	for _, header := range headers {
		frame.WriteString(header + "\r\n")
	}
	frame.WriteString("\r\n")
	return []byte(frame.String())
}

// familiesIn serves the same target once per named family and returns the
// gateway's status for each. A dead route is the pool, so every family sees an
// identical pool and any difference in the answer comes from the header alone.
func familiesIn(t *testing.T, addr string, families ...string) map[string]int {
	t.Helper()
	statuses := make(map[string]int, len(families))
	for _, family := range families {
		var headers []string
		if family != "" {
			headers = append(headers, headerProxyFamily+": "+family)
		}
		conn := dialGateway(t, addr)
		if _, err := conn.Write(connectWithHeaders("example.test:80", headers...)); err != nil {
			t.Fatalf("write CONNECT (%q): %v", family, err)
		}
		statuses[family] = readIngressResponse(t, bufio.NewReader(conn), http.MethodConnect).StatusCode
	}
	return statuses
}

// TestControlHeaderFamilyGrammarIsAClosedSet pins the whole family grammar
// from outside: the three accepted values, an absent header, and every refused
// spelling. A refused value is a local 400 answered before route selection, so
// it must not look like the 503 a pool with no route draws — otherwise a typo
// and an empty pool would be indistinguishable to a client.
func TestControlHeaderFamilyGrammarIsAClosedSet(t *testing.T) {
	u, err := url.Parse("socks5://u.test:1080")
	if err != nil {
		t.Fatal(err)
	}
	pl := pool.NewRoutes([]config.RouteSpec{{URL: u, Kind: config.EgressV4}}, time.Second, time.Minute)
	srv := newRuntimeServer(pl, defaultRuntime(), testLogger())
	addr := startServer(t, srv)

	// No route is dialable, so an accepted header always reaches selection and
	// answers 503; a refused one is rejected earlier with 400.
	for _, tc := range []struct {
		family     string
		wantStatus int
	}{
		{"v4", http.StatusServiceUnavailable},
		{"v6", http.StatusServiceUnavailable},
		{"mixed", http.StatusServiceUnavailable},
		{"", http.StatusServiceUnavailable},
		// Outside the closed set.
		{"V4", http.StatusBadRequest},
		{"V6", http.StatusBadRequest},
		{"ipv4", http.StatusBadRequest},
		{"4", http.StatusBadRequest},
		{"v5", http.StatusBadRequest},
		{"any", http.StatusBadRequest},
		{"all", http.StatusBadRequest},
		{"none", http.StatusBadRequest},
		{"v4,v6", http.StatusBadRequest},
		// Present but names no family: refused rather than read as absent.
		{":", http.StatusBadRequest},
		// Interior whitespace is a different string from "v4" and is not a
		// spelling of it; surrounding whitespace is trimmed by net/http before
		// the value ever reaches the gateway, so it is the same request.
		{"v 4", http.StatusBadRequest},
		{"v4 v6", http.StatusBadRequest},
		{" v4", http.StatusServiceUnavailable},
		{"v4 ", http.StatusServiceUnavailable},
		{"\tv4\t", http.StatusServiceUnavailable},
		// Quoting is not a spelling either.
		{`"v4"`, http.StatusBadRequest},
	} {
		t.Run("family="+tc.family, func(t *testing.T) {
			got := familiesIn(t, addr, tc.family)[tc.family]
			if got != tc.wantStatus {
				t.Fatalf("x-ecoma-proxy-family %q = %d, want %d", tc.family, got, tc.wantStatus)
			}
		})
	}

	// A repeated header is refused: the gateway cannot know which of the two
	// constraints the client meant, and picking one would let an intermediary
	// choose the egress family. The parser sees two values, however they were
	// spelled or cased.
	conn := dialGateway(t, addr)
	if _, err := conn.Write(connectWithHeaders("example.test:80",
		headerProxyFamily+": v4", headerProxyFamily+": v6")); err != nil {
		t.Fatalf("write repeated family: %v", err)
	}
	if status := readIngressResponse(t, bufio.NewReader(conn), http.MethodConnect).StatusCode; status != http.StatusBadRequest {
		t.Fatalf("repeated x-ecoma-proxy-family = %d, want 400", status)
	}

	// A protocol reject is a pre-selection local error: it must not advance the
	// listener `requests` counter, whose documented meaning is valid requests
	// that reached route selection. Only the accepted values counted, and the
	// repeated-header case is one more reject that must not have.
	if got, want := srv.ListenerStatus().Requests, uint64(7); got != want {
		t.Fatalf("listener requests = %d, want %d: a refused family must not reach selection", got, want)
	}
}

// parseProxyFamily is the same grammar at unit distance, including the one case
// a request frame cannot express: two header lines merged into a single field
// value by a proxy, which is one occurrence with a comma inside it.
func TestParseProxyFamilyRejectsOutsideTheClosedSet(t *testing.T) {
	for _, tc := range []struct {
		name    string
		header  http.Header
		want    proxyFamily
		wantErr bool
	}{
		{name: "absent", header: http.Header{}, want: familyMixed},
		{name: "mixed is the unconstrained request", header: http.Header{headerProxyFamily: {"mixed"}}, want: familyMixed},
		{name: "v4", header: http.Header{headerProxyFamily: {"v4"}}, want: familyV4},
		{name: "v6", header: http.Header{headerProxyFamily: {"v6"}}, want: familyV6},
		{name: "empty names no family", header: http.Header{headerProxyFamily: {""}}, wantErr: true},
		{name: "upper case", header: http.Header{headerProxyFamily: {"V4"}}, wantErr: true},
		{name: "interior space", header: http.Header{headerProxyFamily: {"v 4"}}, wantErr: true},
		{name: "quoted", header: http.Header{headerProxyFamily: {`"v4"`}}, wantErr: true},
		{name: "comma-merged pair", header: http.Header{headerProxyFamily: {"v4, v6"}}, wantErr: true},
		{name: "repeated", header: http.Header{headerProxyFamily: {"v4", "v6"}}, wantErr: true},
		{name: "repeated and identical", header: http.Header{headerProxyFamily: {"v4", "v4"}}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseProxyFamily(tc.header)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseProxyFamily(%q) accepted the value", tc.header.Values(headerProxyFamily))
				}
				return
			}
			if err != nil {
				t.Fatalf("parseProxyFamily(%q) = %v", tc.header.Values(headerProxyFamily), err)
			}
			if got != tc.want {
				t.Fatalf("parseProxyFamily(%q) = %v, want %v", tc.header.Values(headerProxyFamily), got, tc.want)
			}
		})
	}
}

// narrow must compose, never branch: for the unconstrained family it hands
// back the very predicate it was given — nil included, because a nil predicate
// is the no-filter fast path the whole serving path relies on — and for a
// constrained one it returns a predicate that is the intersection of both.
func TestProxyFamilyNarrowComposesWithAnExistingPredicate(t *testing.T) {
	v4Only := &pool.Proxy{Kind: config.EgressV4}
	v6Only := &pool.Proxy{Kind: config.EgressV6}

	if got := familyMixed.narrow(nil); got != nil {
		t.Fatal("familyMixed.narrow(nil) allocated a filter; the no-routing fast path lost its nil predicate")
	}
	listenerV4 := func(p *pool.Proxy) bool { return p.Kind == config.EgressV4 }
	if got := familyMixed.narrow(listenerV4); got == nil {
		t.Fatal("familyMixed.narrow dropped the listener predicate")
	} else if !got(v4Only) || got(v6Only) {
		t.Fatal("familyMixed.narrow changed the listener predicate it was handed")
	}

	// A v6 request on a v4-only listener: the intersection is empty, and the
	// composed predicate must say so rather than letting either filter win.
	composed := familyV6.narrow(listenerV4)
	if composed == nil {
		t.Fatal("familyV6.narrow(nil listener filter) returned no filter")
	}
	if composed(v4Only) || composed(v6Only) {
		t.Fatal("a v6 request matched a v4-only route under the composed predicate")
	}

	// Same family, narrowed: the route stays eligible, which is what proves the
	// composed predicate is an intersection and not a replacement.
	if !familyV4.narrow(listenerV4)(v4Only) {
		t.Fatal("a v4 request on a v4-only listener was excluded")
	}
	if familyV4.narrow(nil)(v6Only) {
		t.Fatal("a v4 request matched a v6-only route with no listener filter")
	}
}

// TestProxyFamilyRejectsBeforeRouteSelection pins where the reject happens. A
// refused family is answered locally, so it must cost the pool nothing: no
// upstream contacted, no route health moved, and the listener's request counter
// untouched.
func TestProxyFamilyRejectsBeforeRouteSelection(t *testing.T) {
	upstream := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	pl := pool.NewRoutes([]config.RouteSpec{{URL: upstream.URL, Kind: config.EgressV4}}, time.Second, time.Minute)
	var logs safeLogBuffer
	srv := newRuntimeServer(pl, defaultRuntime(), captureLogger(&logs))
	addr := startServer(t, srv)

	conn := dialGateway(t, addr)
	if _, err := conn.Write(connectWithHeaders("example.test:80", headerProxyFamily+": v9")); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	if status := readIngressResponse(t, bufio.NewReader(conn), http.MethodConnect).StatusCode; status != http.StatusBadRequest {
		t.Fatalf("invalid family = %d, want 400", status)
	}
	if got := len(upstream.hits); got != 0 {
		t.Fatalf("a refused family contacted an upstream %d times, want none", got)
	}
	if snap := pl.Snapshot()[0]; snap.Failures != 0 || snap.Successes != 0 || !snap.Available {
		t.Fatalf("a refused family mutated route health: %+v", snap)
	}
	if got := srv.ListenerStatus().Requests; got != 0 {
		t.Fatalf("listener requests = %d, want 0: the reject is pre-selection", got)
	}
	// The reject names the family header but never echoes the value back: the
	// value is untrusted, and the line is a debug record precisely so an
	// operator reading it sees which header was wrong, not what was sent.
	waitForRecord(t, &logs, map[string]string{"msg": "HTTP proxy request rejected", "error_kind": "bad_request"})
	if strings.Contains(logs.String(), "v9") {
		t.Fatalf("the refused family value reached the log:\n%s", logs.String())
	}
}

// The family constraint narrows candidates; it never creates a second selection
// path and never takes authority over health. A v4 request must reach a v4
// route, a v6 request a v6 route, and both on the mixed listener, with the pool
// still the only thing deciding order.
func TestControlHeaderFamilySelectsTheMatchingKindOnTheMixedListener(t *testing.T) {
	v4 := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	v6 := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	pl := pool.NewRoutes([]config.RouteSpec{
		{ID: "four", URL: v4.URL, Kind: config.EgressV4},
		{ID: "six", URL: v6.URL, Kind: config.EgressV6},
	}, 30*time.Second, time.Minute)
	srv := newRuntimeServer(pl, defaultRuntime(), testLogger())
	addr := startServer(t, srv)

	for _, tc := range []struct{ family, wantHits string }{
		{"v4", "four"},
		{"v6", "six"},
		{"mixed", ""},
		{"", ""},
	} {
		t.Run("family="+tc.family, func(t *testing.T) {
			v4Before, v6Before := len(v4.hits), len(v6.hits)
			conn := dialGateway(t, addr)
			var headers []string
			if tc.family != "" {
				headers = append(headers, headerProxyFamily+": "+tc.family)
			}
			if _, err := conn.Write(connectWithHeaders("example.test:80", headers...)); err != nil {
				t.Fatalf("write CONNECT: %v", err)
			}
			if status := readIngressResponse(t, bufio.NewReader(conn), http.MethodConnect).StatusCode; status != http.StatusOK {
				t.Fatalf("CONNECT with family %q = %d, want 200", tc.family, status)
			}
			switch tc.wantHits {
			case "four":
				if len(v4.hits) != v4Before+1 || len(v6.hits) != v6Before {
					t.Fatalf("a v4 request hit v4:%d v6:%d, want the v4 route only", len(v4.hits), len(v6.hits))
				}
			case "six":
				if len(v6.hits) != v6Before+1 || len(v4.hits) != v4Before {
					t.Fatalf("a v6 request hit v4:%d v6:%d, want the v6 route only", len(v4.hits), len(v6.hits))
				}
			default:
				// Unconstrained: exactly one route served the request, and it
				// was one of the two — round-robin chooses, the header does not.
				if total := len(v4.hits) - v4Before + len(v6.hits) - v6Before; total != 1 {
					t.Fatalf("an unconstrained request hit %d routes, want exactly 1", total)
				}
			}
		})
	}
}

// A pool holding only the other family is not a routing failure, it is an
// empty candidate set: the v6 request must fail closed with the ordinary 503
// after contacting nothing. Silently serving it from the v4 route is the leak
// this pins.
func TestControlHeaderFamilyFailsClosedWithNoMatchingKind(t *testing.T) {
	v4 := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	pl := pool.NewRoutes([]config.RouteSpec{{URL: v4.URL, Kind: config.EgressV4}}, 30*time.Second, time.Minute)
	var logs safeLogBuffer
	srv := newRuntimeServer(pl, defaultRuntime(), captureLogger(&logs))
	addr := startServer(t, srv)

	conn := dialGateway(t, addr)
	if _, err := conn.Write(connectWithHeaders("example.test:80", headerProxyFamily+": v6")); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	if status := readIngressResponse(t, bufio.NewReader(conn), http.MethodConnect).StatusCode; status != http.StatusServiceUnavailable {
		t.Fatalf("a v6 request on a v4-only pool = %d, want 503", status)
	}
	if got := len(v4.hits); got != 0 {
		t.Fatalf("a v6 request was served by a v4 route (%d hits), want none", got)
	}
	// kind_routes counts the composed candidate set, so a family constraint
	// that excluded every route must be visible as zero there.
	waitForRecord(t, &logs, map[string]string{
		"msg": "tunnel failed", "error_kind": "no_route", "kind_routes": "0", "attempts": "0",
	})
	if snap := pl.Snapshot()[0]; snap.Failures != 0 {
		t.Fatalf("an empty candidate set mutated route health: %+v", snap)
	}
}

// The family composes with a dedicated listener's own kind filter by
// intersection: a v6 request on the v4 listener has no candidate at all, and a
// v4 request on it is served. A dedicated listener must never leak into the
// other kind — including when the request asks for the other kind itself.
func TestControlHeaderFamilyIntersectsTheListenerKindFilter(t *testing.T) {
	v4 := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	v6 := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	pl := pool.NewRoutes([]config.RouteSpec{
		{URL: v4.URL, Kind: config.EgressV4},
		{URL: v6.URL, Kind: config.EgressV6},
	}, 30*time.Second, time.Minute)
	// One server, two listener views: the same shape the process runs with.
	srv := newRuntimeServer(pl, defaultRuntime(), testLogger(), config.EgressV4)
	addr := startServer(t, srv)

	// Asking for the listener's own family is served.
	conn := dialGateway(t, addr)
	if _, err := conn.Write(connectWithHeaders("example.test:80", headerProxyFamily+": v4")); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	if status := readIngressResponse(t, bufio.NewReader(conn), http.MethodConnect).StatusCode; status != http.StatusOK {
		t.Fatalf("a v4 request on the v4 listener = %d, want 200", status)
	}
	if got := len(v4.hits); got != 1 {
		t.Fatalf("v4 route hits = %d, want 1", got)
	}

	// Asking for the other family is empty: the intersection of the listener's
	// v4 view and the request's v6 constraint contains no route.
	conn = dialGateway(t, addr)
	if _, err := conn.Write(connectWithHeaders("example.test:80", headerProxyFamily+": v6")); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	if status := readIngressResponse(t, bufio.NewReader(conn), http.MethodConnect).StatusCode; status != http.StatusServiceUnavailable {
		t.Fatalf("a v6 request on the v4 listener = %d, want 503", status)
	}
	if len(v4.hits) != 1 || len(v6.hits) != 0 {
		t.Fatalf("hits = v4:%d v6:%d, want the v4 listener untouched by the v6 request", len(v4.hits), len(v6.hits))
	}
}

// The family composes with the routing policy by intersection too: the routing
// rule names one route and the family names a kind, so the effective set is
// their intersection, never their union and never a replacement.
func TestControlHeaderFamilyIntersectsTheRoutingPolicy(t *testing.T) {
	openaiV4 := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	openaiV6 := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	kiloV6 := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	pl := pool.NewRoutes([]config.RouteSpec{
		{ID: "openai-v4", URL: openaiV4.URL, Kind: config.EgressV4},
		{ID: "openai-v6", URL: openaiV6.URL, Kind: config.EgressV6},
		{ID: "kilo-v6", URL: kiloV6.URL, Kind: config.EgressV6},
	}, 30*time.Second, time.Minute)

	var logs safeLogBuffer
	rt := defaultRuntime()
	rt.Routing = mustCompileRouter(t, routing.Spec{
		Rules: []routing.RuleSpec{{Domains: []string{"*.openai.com"}, Routes: []string{"openai-v4", "openai-v6", "kilo-v6"}}},
	})
	srv := newRuntimeServer(pl, rt, captureLogger(&logs))
	addr := startServer(t, srv)

	// The rule admits three routes; a v4 request narrows that to the one v4
	// route inside the rule. Kilo is outside the rule, so it is not a
	// candidate no matter which family asked for it.
	conn := dialGateway(t, addr)
	if _, err := conn.Write(connectWithHeaders("api.openai.com:80", headerProxyFamily+": v4")); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	if status := readIngressResponse(t, bufio.NewReader(conn), http.MethodConnect).StatusCode; status != http.StatusOK {
		t.Fatalf("v4 request into the openai rule = %d, want 200", status)
	}
	if got := len(openaiV4.hits); got != 1 {
		t.Fatalf("openai v4 route hits = %d, want 1", got)
	}
	if got := len(openaiV6.hits) + len(kiloV6.hits); got != 0 {
		t.Fatalf("a v4 request inside the openai rule hit a v6 route %d times", got)
	}

	// A v6 request narrows the same rule to its two v6 routes, and the rule
	// still excludes kilo for this target.
	conn = dialGateway(t, addr)
	if _, err := conn.Write(connectWithHeaders("api.openai.com:80", headerProxyFamily+": v6")); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	if status := readIngressResponse(t, bufio.NewReader(conn), http.MethodConnect).StatusCode; status != http.StatusOK {
		t.Fatalf("v6 request into the openai rule = %d, want 200", status)
	}
	if got := len(openaiV6.hits); got != 1 {
		t.Fatalf("openai v6 route hits = %d, want 1", got)
	}
	if got := len(kiloV6.hits); got != 0 {
		t.Fatalf("a route outside the rule served a request inside it (%d hits)", got)
	}

	// The inverse intersection: a v4 request for a target only a v6 route may
	// serve has an empty set and fails closed, with the routing candidate count
	// still reporting the rule's own view.
	conn = dialGateway(t, addr)
	if _, err := conn.Write(connectWithHeaders("api.openai.com:80", headerProxyFamily+": v4")); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	if status := readIngressResponse(t, bufio.NewReader(conn), http.MethodConnect).StatusCode; status != http.StatusOK {
		t.Fatalf("second v4 request = %d, want 200", status)
	}
	waitForRecord(t, &logs, map[string]string{"msg": "route selected", "route_id": "openai-v4"})
}

// TestControlHeaderFamilyDoesNotLeakOnTheAllCoolingFallback is the leak pin.
// When every route is cooling, Pool.PickFor falls back to the soonest-recovering
// route and deliberately ignores cooldown — the pool would rather serve a cooling
// route than fail the client. That makes the fallback exactly where a candidate
// predicate that only narrowed the ordinary LRU collection would leak: a v6
// request would be handed the cooling v4 route. PickFor computes one `allowed`
// closure and guards both the available set and the fallback candidate with it,
// so the composed family predicate is on both paths.
//
// The test therefore drives the pool fully into the all-cooling state and then
// asks each family for the same target. Both must be served — by the route of
// their own family, dialed while cooling — and the selected-route records carry
// a remaining cooldown, which is what proves the fallback rather than the
// ordinary path served them.
func TestControlHeaderFamilyDoesNotLeakOnTheAllCoolingFallback(t *testing.T) {
	srv, pl, logs := newFamilyPoolServer(t, config.EgressV4, config.EgressV6)
	addr := startServer(t, srv)
	// The dial seam keeps both routes down and records which endpoint each
	// attempt reached. The gateway sees only the error type, so the health path
	// under test is the real one.
	var mu sync.Mutex
	dialed := map[string]int{}
	srv.dial = func(_ context.Context, pu *url.URL, _ socksdial.Target, _ time.Duration) (net.Conn, error) {
		mu.Lock()
		dialed[pu.Host]++
		mu.Unlock()
		return nil, (&socksdial.ProxyDialError{Err: errors.New("connect refused (TEST)")}).WithRetryAfter(cooldownHold)
	}

	// One request per family is enough to put both routes into route-scoped
	// cooldown: the retry budget is one attempt, so the request spends it,
	// the route cools for an hour, and the chain ends with no second attempt.
	for _, family := range []string{"v4", "v6"} {
		conn := dialGateway(t, addr)
		if _, err := conn.Write(connectWithHeaders("example.test:80", headerProxyFamily+": "+family)); err != nil {
			t.Fatalf("write %s CONNECT: %v", family, err)
		}
		if status := readIngressResponse(t, bufio.NewReader(conn), http.MethodConnect).StatusCode; status != http.StatusServiceUnavailable {
			t.Fatalf("a %s request against a refusing route = %d, want 503", family, status)
		}
	}
	// The state the fallback exists for: every route cooling, none auth-blocked,
	// none rotating.
	for _, snap := range pl.Snapshot() {
		if snap.Available {
			t.Fatalf("route %s is still available; the test never reached the all-cooling state", snap.ID)
		}
	}

	v4Host, v6Host := "127.0.0.1:1080", "127.0.0.1:1081"
	mu.Lock()
	dialed = map[string]int{}
	mu.Unlock()

	// Now the pin. A v6 request in the all-cooling state is still served — from
	// the cooling v6 route, never the cooling v4 one. A predicate that reached
	// only the available-route collection would hand back the v4 route here.
	conn := dialGateway(t, addr)
	if _, err := conn.Write(connectWithHeaders("example.test:80", headerProxyFamily+": v6")); err != nil {
		t.Fatalf("write all-cooling v6 CONNECT: %v", err)
	}
	if status := readIngressResponse(t, bufio.NewReader(conn), http.MethodConnect).StatusCode; status != http.StatusServiceUnavailable {
		t.Fatalf("a v6 request with every route cooling = %d, want 503 after being served the cooling v6 route", status)
	}
	mu.Lock()
	v6Dialed, v4Dialed := dialed[v6Host], dialed[v4Host]
	mu.Unlock()
	if v6Dialed == 0 {
		t.Fatal("the v6 request never reached the v6 route: the all-cooling fallback served it nothing")
	}
	if v4Dialed != 0 {
		t.Fatalf("a v6 request was served by the cooling v4 route %d times: the family predicate leaked past the fallback", v4Dialed)
	}
	mu.Lock()
	dialed = map[string]int{}
	mu.Unlock()
	// The selected route carried a remaining cooldown, which is what makes this
	// the fallback path and not the ordinary one. The v4 request above was the
	// first, so the v6 request is the second.
	waitForRecord(t, logs, map[string]string{
		"msg": "route selected", "upstream": v6Host, "request_id": "2",
	})
	if !strings.Contains(logs.String(), "cooldown_remaining") {
		t.Fatalf("no selected route carried a remaining cooldown; the fallback path was never reached:\n%s", logs.String())
	}

	// The mirror: a v4 request in the same state is served from the cooling v4
	// route, and never from the v6 one.
	conn = dialGateway(t, addr)
	if _, err := conn.Write(connectWithHeaders("example.test:80", headerProxyFamily+": v4")); err != nil {
		t.Fatalf("write all-cooling v4 CONNECT: %v", err)
	}
	if status := readIngressResponse(t, bufio.NewReader(conn), http.MethodConnect).StatusCode; status != http.StatusServiceUnavailable {
		t.Fatalf("a v4 request with every route cooling = %d, want 503 after being served the cooling v4 route", status)
	}
	mu.Lock()
	v6Dialed, v4Dialed = dialed[v6Host], dialed[v4Host]
	mu.Unlock()
	if v4Dialed == 0 || v6Dialed != 0 {
		t.Fatalf("a v4 request dialed v4:%d v6:%d, want the cooling v4 route only", v4Dialed, v6Dialed)
	}
}

// newFamilyPoolServer builds a gateway whose pool holds one route per named
// kind, with an hour-long cooldown so a route that fails once stays cooling for
// the rest of the test. The dial seam is the caller's to install.
func newFamilyPoolServer(t *testing.T, kinds ...config.EgressKind) (*Server, *pool.Pool, *safeLogBuffer) {
	t.Helper()
	specs := make([]config.RouteSpec, 0, len(kinds))
	for i, kind := range kinds {
		specs = append(specs, config.RouteSpec{
			ID:   fmt.Sprintf("route-%d-%s", i, kind),
			URL:  &url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", 1080+i)},
			Kind: kind,
		})
	}
	pl := pool.NewRoutes(specs, time.Hour, time.Hour)
	rt := defaultRuntime()
	rt.CooldownBase = time.Hour
	rt.CooldownMax = time.Hour
	logs := &safeLogBuffer{}
	return newRuntimeServer(pl, rt, captureLogger(logs)), pl, logs
}

// cooldownHold keeps a route that failed through the injected dial out of
// service for the rest of a test. The error states it rather than the test
// reaching into pool internals, so the scenario reads the way the real thing
// behaves: a route that is down stays down. A route-scoped failure class is what
// makes the hold last — a CONNECT the endpoint itself refuses cools only that
// (route, target) pair, which the next request for the same target would still
// be inside of.
const cooldownHold = time.Hour

// The family header is a request-scoped selection constraint, never part of
// route identity. Two requests for one target that differ only in the header
// must hit the very same pool.Proxy objects — no new route state, no second
// entry, and health accumulated by one visible to the other.
func TestControlHeaderFamilyIsNotPartOfRouteIdentity(t *testing.T) {
	v4 := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	v6 := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	pl := pool.NewRoutes([]config.RouteSpec{
		{URL: v4.URL, Kind: config.EgressV4},
		{URL: v6.URL, Kind: config.EgressV6},
	}, 30*time.Second, time.Minute)
	srv := newRuntimeServer(pl, defaultRuntime(), testLogger())
	addr := startServer(t, srv)

	before := pl.RoutePointers()
	if len(before) != 2 {
		t.Fatalf("pool routes = %d, want 2", len(before))
	}
	beforeIDs := make([]string, 0, len(before))
	for _, p := range before {
		beforeIDs = append(beforeIDs, p.RouteID())
	}

	// The same target, three different family headers, three requests. Each
	// must be served, and the pool must still hold exactly the two objects it
	// started with.
	for _, family := range []string{"v4", "v6", "mixed", "v4"} {
		conn := dialGateway(t, addr)
		if _, err := conn.Write(connectWithHeaders("example.test:80", headerProxyFamily+": "+family)); err != nil {
			t.Fatalf("write CONNECT: %v", err)
		}
		if status := readIngressResponse(t, bufio.NewReader(conn), http.MethodConnect).StatusCode; status != http.StatusOK {
			t.Fatalf("family %q = %d, want 200", family, status)
		}
	}

	after := pl.RoutePointers()
	if len(after) != len(before) {
		t.Fatalf("pool grew from %d to %d routes: the family header reached route identity", len(before), len(after))
	}
	for i, p := range after {
		if p != before[i] {
			t.Fatalf("route %d is a different object after family-scoped requests: identity changed", i)
		}
		if p.RouteID() != beforeIDs[i] {
			t.Fatalf("route %d id = %q, want %q: canonical identity is not stable", i, p.RouteID(), beforeIDs[i])
		}
	}
	// The successes all landed on the same two objects, which is only possible
	// if the header never forked identity.
	var successes uint64
	for _, snap := range pl.Snapshot() {
		successes += snap.Successes
	}
	if successes != 4 {
		t.Fatalf("route successes = %d, want 4 on the two original objects", successes)
	}
}

// --- x-ecoma-request-id -----------------------------------------------------

// resolveRequestID is the accept/replace grammar. A client id is echoed only
// when it is exactly one occurrence, inside the size bound, and inside the
// token alphabet; everything else is replaced by a minted id rather than
// refused, because the request is serviceable and only the diagnostic header
// was unusable.
func TestResolveRequestIDAcceptsOnlyAToken(t *testing.T) {
	for _, tc := range []struct {
		name      string
		header    http.Header
		want      string
		wantFresh bool
	}{
		{name: "absent", header: http.Header{}, wantFresh: true},
		{name: "plain token", header: http.Header{headerRequestID: {"abc123"}}, want: "abc123"},
		{name: "opaque id", header: http.Header{headerRequestID: {"01J8Z9RQ4M7N2K3P4T5V6W7X8Y"}}, want: "01J8Z9RQ4M7N2K3P4T5V6W7X8Y"},
		// The whole alphabet is one byte over the bound, so it is the size
		// rule that refuses it, not the grammar: the same characters at the
		// bound are accepted.
		{name: "the whole alphabet is one byte over the bound", header: http.Header{headerRequestID: {requestIDAlphabet}}, wantFresh: true},
		{name: "empty is not a token", header: http.Header{headerRequestID: {""}}, wantFresh: true},
		{name: "quoted", header: http.Header{headerRequestID: {`"abc"`}}, wantFresh: true},
		{name: "interior space", header: http.Header{headerRequestID: {"a b"}}, wantFresh: true},
		{name: "leading space survives the map; net/http trims it before us", header: http.Header{headerRequestID: {" abc"}}, wantFresh: true},
		{name: "newline", header: http.Header{headerRequestID: {"ab\nc"}}, wantFresh: true},
		{name: "carriage return", header: http.Header{headerRequestID: {"ab\rc"}}, wantFresh: true},
		{name: "tab", header: http.Header{headerRequestID: {"ab\tc"}}, wantFresh: true},
		{name: "NUL", header: http.Header{headerRequestID: {"ab\x00c"}}, wantFresh: true},
		{name: "ESC starts an ANSI sequence", header: http.Header{headerRequestID: {"\x1b[31mred\x1b[0m"}}, wantFresh: true},
		{name: "lone ESC", header: http.Header{headerRequestID: {"ab\x1bc"}}, wantFresh: true},
		{name: "DEL", header: http.Header{headerRequestID: {"ab\x7fc"}}, wantFresh: true},
		{name: "backslash", header: http.Header{headerRequestID: {`a\b`}}, wantFresh: true},
		{name: "slash", header: http.Header{headerRequestID: {"a/b"}}, wantFresh: true},
		{name: "comma-merged pair", header: http.Header{headerRequestID: {"abc, def"}}, wantFresh: true},
		{name: "repeated", header: http.Header{headerRequestID: {"abc", "def"}}, wantFresh: true},
		{name: "repeated and identical", header: http.Header{headerRequestID: {"abc", "abc"}}, wantFresh: true},
		{name: "multi-byte rune", header: http.Header{headerRequestID: {"abcé"}}, wantFresh: true},
		{name: "at the bound", header: http.Header{headerRequestID: {strings.Repeat("a", maxInboundRequestIDLength)}}, want: strings.Repeat("a", maxInboundRequestIDLength)},
		{name: "one past the bound", header: http.Header{headerRequestID: {strings.Repeat("a", maxInboundRequestIDLength+1)}}, wantFresh: true},
		{name: "far past the bound", header: http.Header{headerRequestID: {strings.Repeat("a", 64*1024)}}, wantFresh: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveRequestID(tc.header)
			if !tc.wantFresh {
				if got != tc.want {
					t.Fatalf("resolveRequestID = %q, want the client value %q", got, tc.want)
				}
				return
			}
			if got == "" {
				t.Fatal("resolveRequestID returned an empty id")
			}
			if tc.want != "" && got == tc.want {
				t.Fatalf("resolveRequestID echoed a value it should have replaced: %q", got)
			}
			// A minted id must be a well-formed token of the same shape an
			// accepted client id has, so a log reader never has to special-case
			// it, and it must never carry anything a log line would have to
			// escape.
			if !strings.HasPrefix(got, requestIDPrefix+"-") {
				t.Fatalf("minted id %q is not marked as generated", got)
			}
			if !isRequestIDToken(got) {
				t.Fatalf("minted id %q is not inside the token alphabet", got)
			}
			if len(got) > maxInboundRequestIDLength {
				t.Fatalf("minted id is %d bytes, past the %d bound", len(got), maxInboundRequestIDLength)
			}
		})
	}
}

// Two minted ids must differ: a correlation id that repeats is no correlation
// at all, and the whole reason for minting from crypto/rand rather than from
// the request counter.
func TestGenerateRequestIDIsUniquePerRequest(t *testing.T) {
	seen := make(map[string]struct{}, 512)
	for range 512 {
		id := generateRequestID()
		if _, dup := seen[id]; dup {
			t.Fatalf("generateRequestID repeated %q within 512 draws", id)
		}
		seen[id] = struct{}{}
	}
}

// A client-supplied id must be bounded and single-line in the log it lands in.
// The bound is what stops an untrusted value becoming an unbounded field written
// once per attempt, and the token grammar is what stops it needing a log reader
// to unpick. A 64 KiB id is replaced, not truncated: a truncated id would
// collide with other requests that share the prefix.
func TestRequestIDIsBoundedInTheLog(t *testing.T) {
	oversized := strings.Repeat("a", 64*1024)
	got := resolveRequestID(http.Header{headerRequestID: {oversized}})
	if got == oversized {
		t.Fatal("a 64 KiB client id was echoed into the log")
	}
	if len(got) > maxInboundRequestIDLength {
		t.Fatalf("replacement id is %d bytes, past the %d bound", len(got), maxInboundRequestIDLength)
	}
}

// The correlation id is resolved once, before selection, and carried by every
// line of one attempt chain — a dead route and the good one after it must
// produce the same id on both the fallback record and the success record. It is
// also not the request_id counter: that one must keep counting valid requests
// that reached selection, which is what the per-listener /status figure is.
func TestRequestIDSurvivesEveryRetryInOneChain(t *testing.T) {
	good := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	// One dead route, one live one, so the chain falls back exactly once.
	pl := pool.NewRoutes([]config.RouteSpec{
		{URL: &url.URL{Scheme: "socks5", Host: "127.0.0.1:1"}, Kind: config.EgressV4},
		{URL: good.URL, Kind: config.EgressV4},
	}, time.Minute, time.Minute)

	var logs safeLogBuffer
	rt := defaultRuntime()
	rt.MaxRetries = 3
	srv := newRuntimeServer(pl, rt, captureLogger(&logs))
	addr := startServer(t, srv)

	conn := dialGateway(t, addr)
	if _, err := conn.Write(connectWithHeaders("example.test:80", headerRequestID+": chain-42")); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	if status := readIngressResponse(t, bufio.NewReader(conn), http.MethodConnect).StatusCode; status != http.StatusOK {
		t.Fatalf("CONNECT with a dead first route = %d, want 200 after the fallback", status)
	}

	// Both the failed attempt and the eventual success carry the client's id,
	// and the process-local ordinal moved with them. The success record lands
	// after the client's 200, so poll for it instead of reading a snapshot that
	// may still be one record short.
	waitForRecord(t, &logs, map[string]string{"msg": "tunnel", "correlation_id": "chain-42"})
	output := logs.String()
	recs := decodeRecords(output)
	var sawFailure, sawSuccess bool
	for _, rec := range recs {
		if got := rec["correlation_id"]; got != "chain-42" {
			continue
		}
		switch rec["msg"] {
		case "upstream dial failed":
			sawFailure = true
			if rec["request_id"] != float64(1) {
				t.Fatalf("failure record request_id = %v, want the first request's ordinal 1", rec["request_id"])
			}
		case "tunnel":
			sawSuccess = true
		}
	}
	if !sawFailure {
		t.Fatalf("no failed-attempt record carried the client id:\n%s", output)
	}
	if !sawSuccess {
		t.Fatalf("no success record carried the client id:\n%s", output)
	}
	if status := srv.ListenerStatus(); status.Requests != 1 || status.Failovers != 1 {
		t.Fatalf("listener status = %+v, want one request and one in-band failover", status)
	}
}

// The request_id field stays the process-local ordinal a client cannot touch:
// /status reports it as the count of valid requests that reached selection, so
// a hostile or absent correlation id must change nothing about it.
func TestRequestIDFieldStaysTheProcessLocalOrdinal(t *testing.T) {
	upstream := startSocks5Proxy(t, socksOptions{connectRaw: connectSuccessRaw})
	pl := pool.NewRoutes([]config.RouteSpec{{URL: upstream.URL, Kind: config.EgressV4}}, 30*time.Second, time.Minute)
	var logs safeLogBuffer
	srv := newRuntimeServer(pl, defaultRuntime(), captureLogger(&logs))
	addr := startServer(t, srv)

	// Two requests with wildly different correlation ids, then one refused for
	// a bad family. The ordinals must be 1 and 2 with no gaps, and the refused
	// request must not have consumed one.
	for i, id := range []string{"", "not/a/token"} {
		var headers []string
		if id != "" {
			headers = append(headers, headerRequestID+": "+id)
		}
		conn := dialGateway(t, addr)
		if _, err := conn.Write(connectWithHeaders("example.test:80", headers...)); err != nil {
			t.Fatalf("write CONNECT: %v", err)
		}
		if status := readIngressResponse(t, bufio.NewReader(conn), http.MethodConnect).StatusCode; status != http.StatusOK {
			t.Fatalf("request %d = %d, want 200", i+1, status)
		}
	}
	conn := dialGateway(t, addr)
	if _, err := conn.Write(connectWithHeaders("example.test:80", headerProxyFamily+": v9")); err != nil {
		t.Fatalf("write refused CONNECT: %v", err)
	}
	if status := readIngressResponse(t, bufio.NewReader(conn), http.MethodConnect).StatusCode; status != http.StatusBadRequest {
		t.Fatalf("refused family = %d, want 400", status)
	}

	if got, want := srv.ListenerStatus().Requests, uint64(2); got != want {
		t.Fatalf("listener requests = %d, want %d", got, want)
	}
	// One request, one id: the two requests' records carry different ordinals
	// and two different minted ids, and neither client value was echoed.
	ordinals := map[float64]bool{}
	minted := map[string]bool{}
	for _, rec := range decodeRecords(logs.String()) {
		if rec["msg"] != "tunnel" {
			continue
		}
		ordinals[rec["request_id"].(float64)] = true
		id, _ := rec["correlation_id"].(string)
		if id == "not/a/token" {
			t.Fatalf("an invalid client id was echoed: %q", id)
		}
		minted[id] = true
	}
	if len(ordinals) != 2 || !ordinals[1] || !ordinals[2] {
		t.Fatalf("tunnel records carry ordinals %v, want exactly 1 and 2", ordinals)
	}
	if len(minted) != 2 {
		t.Fatalf("the two requests share a correlation id: %v", minted)
	}
}

// Neither control header may reach an upstream, whatever it carries. The
// forward path strips the whole x-ecoma- namespace, so a client-supplied
// correlation id is as invisible to the target as an internal one — which is
// the only reason a client-controlled value can be echoed into a log at all.
func TestControlHeadersNeverReachTheOrigin(t *testing.T) {
	seen := make(chan http.Header, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(origin.Close)
	upstream := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes([]config.RouteSpec{{URL: upstream.URL, Kind: config.EgressV4}}, 30*time.Second, time.Minute)
	_, addr := newProxyServer(t, pl, defaultRuntime(), testLogger())

	// Both control headers, one accepted and one supplied by the client, plus a
	// namespace member this gateway has never heard of: the whole prefix is
	// gateway-private, so the target must see none of it.
	resp := httpForward(t, addr, httpForwardRequest(http.MethodGet, origin.URL+"/probe",
		"Host: "+origin.Listener.Addr().String(),
		headerProxyFamily+": v4",
		headerRequestID+": client-supplied-id",
		"X-Ecoma-Unknown: sneaky",
	), http.MethodGet)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("forwarded request = %d, want 200", resp.StatusCode)
	}

	var observed http.Header
	select {
	case observed = <-seen:
	case <-time.After(2 * time.Second):
		t.Fatal("the origin never saw the request")
	}
	for name := range observed {
		if strings.HasPrefix(strings.ToLower(name), "x-ecoma-") {
			t.Fatalf("the origin saw the gateway-private header %s: %v", name, observed[name])
		}
	}
}

// stripEcomaControlHeaders removes the entire namespace, case-insensitively, so
// a client cannot smuggle a differently-cased control header past the strip.
func TestStripEcomaControlHeadersRemovesTheWholeNamespace(t *testing.T) {
	header := http.Header{
		headerProxyFamily:            {"v4"},
		headerRequestID:              {"client-id"},
		"X-Ecoma-Whatever":           {"x"},
		"x-ecoma-lower":              {"y"},
		"X-EcOmA-MiXeD":              {"z"},
		"X-Forwarded-For":            {"1.2.3.4"},
		"Content-Type":               {"text/plain"},
		"Authorization":              {"Bearer token"},
		"X-Not-Ecoma-Prefixed-Other": {"keep"},
	}
	stripEcomaControlHeaders(header)
	for name := range header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-ecoma-") {
			t.Fatalf("x-ecoma header %q survived the strip", name)
		}
	}
	// The strip is a namespace delete and nothing else: unrelated headers the
	// forwarder needs survive untouched.
	if header.Get("Content-Type") != "text/plain" || header.Get("X-Not-Ecoma-Prefixed-Other") != "keep" {
		t.Fatalf("the strip touched headers outside the namespace: %v", header)
	}
}

// The correlation id travels on the same events that already carry a
// request_id, so an operator can join a client's id to the gateway's own
// ordinal, and the id is present on the terminal records — not just the
// attempts.
func TestCorrelationIDIsOnEveryRequestRecord(t *testing.T) {
	// The upstream refuses the target, so one request produces a start record,
	// a selection, a target refusal, and a terminal failure — every one of them
	// on the same request and every one of them carrying the client's id.
	upstream := startSocks5Proxy(t, socksOptions{connectRep: 0x05})
	pl := pool.NewRoutes([]config.RouteSpec{{URL: upstream.URL, Kind: config.EgressV4}}, time.Minute, time.Minute)
	var logs safeLogBuffer
	srv := newRuntimeServer(pl, defaultRuntime(), captureLogger(&logs))
	addr := startServer(t, srv)

	conn := dialGateway(t, addr)
	if _, err := conn.Write(connectWithHeaders("example.test:80", headerRequestID+": every-line")); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	if status := readIngressResponse(t, bufio.NewReader(conn), http.MethodConnect).StatusCode; status != http.StatusServiceUnavailable {
		t.Fatalf("CONNECT = %d, want 503", status)
	}
	waitForRecord(t, &logs, map[string]string{"msg": "tunnel start", "correlation_id": "every-line", "request_id": "1"})
	waitForRecord(t, &logs, map[string]string{"msg": "upstream refused connect target", "correlation_id": "every-line", "request_id": "1"})
	waitForRecord(t, &logs, map[string]string{"msg": "tunnel failed", "correlation_id": "every-line", "request_id": "1"})
	for _, rec := range decodeRecords(logs.String()) {
		if rec["request_id"] == float64(1) && rec["correlation_id"] != "every-line" {
			t.Fatalf("a record of request 1 carries a different correlation id: %v", rec)
		}
	}
}

// A family-constrained request that reaches the origin still gets the ordinary
// absolute-form treatment: the header never changes the target or the bytes on
// the wire, only which route carried them.
func TestControlHeaderFamilyDoesNotChangeTheForwardedTarget(t *testing.T) {
	seen := make(chan string, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Method + " " + r.URL.RequestURI() + " " + r.Proto
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(origin.Close)
	upstream := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes([]config.RouteSpec{{URL: upstream.URL, Kind: config.EgressV4}}, 30*time.Second, time.Minute)
	_, addr := newProxyServer(t, pl, defaultRuntime(), testLogger())

	resp := httpForward(t, addr, httpForwardRequest(http.MethodGet, origin.URL+"/family",
		"Host: "+origin.Listener.Addr().String(), headerProxyFamily+": v4"), http.MethodGet)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("forwarded request = %d, want 200", resp.StatusCode)
	}
	var requestLine string
	select {
	case requestLine = <-seen:
	case <-time.After(2 * time.Second):
		t.Fatal("the origin never saw the request")
	}
	// The header chose the route and nothing else: the origin still receives
	// the ordinary rewritten origin-form request line.
	if requestLine != "GET /family HTTP/1.1" {
		t.Fatalf("origin saw request line %q, want the rewritten origin-form", requestLine)
	}
}
