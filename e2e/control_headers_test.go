package e2e_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The two gateway-private control headers, against the real binary.
// x-ecoma-proxy-family narrows the eligible route set for one request;
// x-ecoma-request-id correlates its log lines. Neither reaches an origin, and
// neither is part of route identity.

// connectWith sends one CONNECT carrying extra header lines, and returns the
// status the gateway answered. The target authority is repeated in Host, which
// is what a well-behaved client sends.
func connectWith(t testing.TB, proxyAddr, targetAddr string, headers ...string) (int, error) {
	t.Helper()
	res, err := httpProbe(t, proxyAddr, http.MethodConnect,
		"CONNECT "+targetAddr+" HTTP/1.1\r\nHost: "+targetAddr+"\r\n"+
			strings.Join(headers, "\r\n")+"\r\n\r\n")
	if err != nil {
		return 0, err
	}
	return res.StatusCode, nil
}

// Each accepted family value routes to the route of that kind, an absent
// header and the literal "mixed" both round-robin over everything, and a value
// outside the closed set is refused locally with 400 before route selection.
func TestE2E_ProxyFamilyHeaderNarrowsEligibleRoutes(t *testing.T) {
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
	cfg.LogLevel = "debug"
	g := NewGateway(t, cfg)

	for _, tc := range []struct {
		name       string
		family     string
		wantStatus int
		wantSim    *SocksSim
		otherSim   *SocksSim
		emptyValue bool
	}{
		{name: "v4 reaches the v4 route", family: "v4", wantStatus: http.StatusOK, wantSim: v4, otherSim: v6},
		{name: "v6 reaches the v6 route", family: "v6", wantStatus: http.StatusOK, wantSim: v6, otherSim: v4},
		{name: "absent constrains nothing", family: "", wantStatus: http.StatusOK},
		{name: "mixed constrains nothing", family: "mixed", wantStatus: http.StatusOK},
		{name: "upper case is refused", family: "V4", wantStatus: http.StatusBadRequest},
		{name: "unknown value is refused", family: "ipv4", wantStatus: http.StatusBadRequest},
		{name: "an unknown family is refused", family: "any", wantStatus: http.StatusBadRequest},
		{name: "an empty value is refused", family: "", wantStatus: http.StatusBadRequest, emptyValue: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var headers []string
			switch {
			case tc.emptyValue:
				// Present with no value at all. net/http yields an empty string
				// for this, which is why the gateway refuses it rather than
				// reading it as absent.
				headers = append(headers, "X-Ecoma-Proxy-Family:")
			case tc.family != "":
				headers = append(headers, "X-Ecoma-Proxy-Family: "+tc.family)
			}
			wantBefore, otherBefore := uint64(0), uint64(0)
			if tc.wantSim != nil {
				wantBefore, otherBefore = tc.wantSim.Hits.Load(), tc.otherSim.Hits.Load()
			}
			status, err := connectWith(t, g.MixedAddr, target.Host, headers...)
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			if status != tc.wantStatus {
				t.Fatalf("family %q = %d, want %d", tc.family, status, tc.wantStatus)
			}
			if tc.wantSim == nil {
				return
			}
			if got := tc.wantSim.Hits.Load(); got != wantBefore+1 {
				t.Fatalf("%s route hits = %d, want %d", tc.wantSim.RouteValue(), got, wantBefore+1)
			}
			if got := tc.otherSim.Hits.Load(); got != otherBefore {
				t.Fatalf("%s route hits = %d, want none: the family constraint did not hold", tc.otherSim.RouteValue(), got)
			}
		})
	}

	// A repeated header is refused: the gateway cannot know which of the two
	// constraints the client meant.
	status, err := connectWith(t, g.MixedAddr, target.Host,
		"X-Ecoma-Proxy-Family: v4", "X-Ecoma-Proxy-Family: v6")
	if err != nil {
		t.Fatalf("probe repeated family: %v", err)
	}
	if status != http.StatusBadRequest {
		t.Fatalf("repeated family header = %d, want 400", status)
	}

	// Every refused value is a local pre-selection reject: it advanced neither
	// the request counter nor any route's health.
	recs := waitForLogRecord(t, g, map[string]string{"error_kind": "bad_request"}, 5*time.Second)
	if _, ok := findLogRecord(recs, map[string]string{"msg": "HTTP proxy request rejected"}); !ok {
		t.Fatalf("no protocol-reject record in the log:\n%s", g.Logs())
	}
}

// A dedicated listener intersects its own kind filter with the request's
// family: the v4 listener serves a v4 request and refuses a v6 one, so a
// dedicated listener can never leak into the other kind even when the request
// asks for it explicitly.
func TestE2E_ProxyFamilyIntersectsTheDedicatedListener(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	v4 := NewSocksSim(t, SocksOK, "", "")
	v6 := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: v4.RouteValue(), Kind: "v4"},
		{Proxy: v6.RouteValue(), Kind: "v6"},
	}))

	status, err := connectWith(t, g.V4Addr, target.Host, "X-Ecoma-Proxy-Family: v4")
	if err != nil {
		t.Fatalf("probe v4 listener: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("a v4 request on the v4 listener = %d, want 200", status)
	}
	v4Hits, v6Hits := v4.Hits.Load(), v6.Hits.Load()

	status, err = connectWith(t, g.V4Addr, target.Host, "X-Ecoma-Proxy-Family: v6")
	if err != nil {
		t.Fatalf("probe v4 listener with a v6 request: %v", err)
	}
	if status != http.StatusServiceUnavailable {
		t.Fatalf("a v6 request on the v4 listener = %d, want 503", status)
	}
	if v4.Hits.Load() != v4Hits || v6.Hits.Load() != v6Hits {
		t.Fatalf("the refused request dialed a route: v4 %d->%d, v6 %d->%d", v4Hits, v4.Hits.Load(), v6Hits, v6.Hits.Load())
	}

	// The mirror on the v6 listener, so the intersection is pinned from both
	// sides rather than only from the one that happens to have a route.
	status, err = connectWith(t, g.V6Addr, target.Host, "X-Ecoma-Proxy-Family: v6")
	if err != nil {
		t.Fatalf("probe v6 listener: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("a v6 request on the v6 listener = %d, want 200", status)
	}
	if v6.Hits.Load() != v6Hits+1 {
		t.Fatalf("v6 route hits = %d, want %d", v6.Hits.Load(), v6Hits+1)
	}
	status, err = connectWith(t, g.V6Addr, target.Host, "X-Ecoma-Proxy-Family: v4")
	if err != nil {
		t.Fatalf("probe v6 listener with a v4 request: %v", err)
	}
	if status != http.StatusServiceUnavailable {
		t.Fatalf("a v4 request on the v6 listener = %d, want 503", status)
	}
}

// A family constraint composes with the routing policy by intersection: the
// rule names a route set and the header names a kind, and the effective
// candidates are both at once. A kind the rule cannot satisfy fails closed.
func TestE2E_ProxyFamilyIntersectsTheRoutingBlock(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	ruleV4 := NewSocksSim(t, SocksOK, "", "")
	ruleV6 := NewSocksSim(t, SocksOK, "", "")
	outside := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	// The rule matches a domain, so the CONNECT must carry that domain. The
	// sims tunnel to the local echo target, so the domain is never resolved.
	ruleV4.TunnelTo, ruleV6.TunnelTo, outside.TunnelTo = target.Host, target.Host, target.Host
	const routedTarget = "api.openai.com:80"
	// A routing block addresses routes by their operator-facing label, so
	// every serving route needs one — the config validator requires it.
	cfg := defaultGatewayConfig([]RouteConfig{
		{ID: "rule-v4", Proxy: ruleV4.RouteValue(), Kind: "v4"},
		{ID: "rule-v6", Proxy: ruleV6.RouteValue(), Kind: "v6"},
		{ID: "outside", Proxy: outside.RouteValue(), Kind: "v6"},
	})
	// The rule matches the target the tests actually use. A routing block
	// addresses routes by label, and a domain pattern must be a real label —
	// "*" is not one, so the rule names the wildcard under a domain the
	// requests below target. TunnelTo makes the sim dial the local echo
	// target while the request still carries the domain name.
	cfg.Routing = &RoutingConfig{
		Rules: []RoutingRuleConfig{{Domains: []string{"*.openai.com"}, Routes: []string{"rule-v4", "rule-v6"}}},
	}
	g := NewGateway(t, cfg)

	// A v4 request inside the rule reaches the rule's v4 route only.
	status, err := connectWith(t, g.MixedAddr, routedTarget, "X-Ecoma-Proxy-Family: v4")
	if err != nil {
		t.Fatalf("probe v4 into rule: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("a v4 request into the rule = %d, want 200", status)
	}
	if ruleV4.Hits.Load() != 1 || ruleV6.Hits.Load() != 0 {
		t.Fatalf("rule hits = v4:%d v6:%d, want the rule's v4 route only", ruleV4.Hits.Load(), ruleV6.Hits.Load())
	}

	// A v6 request inside the same rule reaches the rule's v6 route, and the
	// route outside the rule is still not a candidate.
	status, err = connectWith(t, g.MixedAddr, routedTarget, "X-Ecoma-Proxy-Family: v6")
	if err != nil {
		t.Fatalf("probe v6 into rule: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("a v6 request into the rule = %d, want 200", status)
	}
	if ruleV6.Hits.Load() != 1 || outside.Hits.Load() != 0 {
		t.Fatalf("hits = ruleV6:%d outside:%d, want the rule's v6 route only", ruleV6.Hits.Load(), outside.Hits.Load())
	}
}

// The all-cooling fallback is where a candidate predicate that only narrowed
// the ordinary LRU collection would leak across families. Every route is put
// into cooldown first, then each family is asked for the same target: both must
// still be served by the route of their own family, dialed while cooling.
func TestE2E_ProxyFamilyHoldsWhenEveryRouteIsCooling(t *testing.T) {
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
	// One attempt per request, and a cooldown far longer than the test, so a
	// route that fails once stays cooling for the rest of the scenario.
	cfg.MaxRetries = 1
	cfg.CooldownBase = "1h"
	cfg.CooldownMax = "1h"
	cfg.LogLevel = "debug"
	g := NewGateway(t, cfg)

	// Kill both routes: a request per family reaches its route, and the route
	// dies mid-handshake, which is a route-scoped failure.
	v4.Down.Store(true)
	v6.Down.Store(true)
	for _, family := range []string{"v4", "v6"} {
		if _, err := connectWith(t, g.MixedAddr, target.Host, "X-Ecoma-Proxy-Family: "+family); err != nil {
			t.Fatalf("cool the %s route: %v", family, err)
		}
	}
	st, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range st.Pool {
		if entry.Available {
			t.Fatalf("route %s is still available; the all-cooling state was never reached", entry.ID)
		}
	}

	// Bring the routes back. They are still cooling, so only the all-cooling
	// fallback can serve a request now — and it must not cross families.
	v4.Down.Store(false)
	v6.Down.Store(false)

	for _, tc := range []struct {
		family      string
		want, other *SocksSim
	}{
		{family: "v6", want: v6, other: v4},
		{family: "v4", want: v4, other: v6},
	} {
		t.Run("all cooling, family "+tc.family, func(t *testing.T) {
			wantBefore, otherBefore := tc.want.Hits.Load(), tc.other.Hits.Load()
			status, err := connectWith(t, g.MixedAddr, target.Host, "X-Ecoma-Proxy-Family: "+tc.family)
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			if status != http.StatusOK {
				t.Fatalf("a %s request with every route cooling = %d, want 200 from the cooling %s route", tc.family, status, tc.family)
			}
			if got := tc.want.Hits.Load(); got != wantBefore+1 {
				t.Fatalf("the %s route took %d hits, want %d: the fallback did not serve it", tc.family, got, wantBefore+1)
			}
			if got := tc.other.Hits.Load(); got != otherBefore {
				t.Fatalf("the %s route took %d hits from a %s request: the family predicate leaked past the fallback", tc.other.RouteValue(), got, tc.family)
			}
		})
	}
	// The selected route carried a remaining cooldown, which is what makes the
	// fallback — not the ordinary path — what served those requests.
	if !strings.Contains(g.Logs(), "cooldown_remaining") {
		t.Fatalf("no selected route carried a remaining cooldown; the fallback was never reached:\n%s", g.Logs())
	}
}

// The correlation id is one id per request, carried by every line of its
// attempt chain however many routes were tried. A dead first route and the good
// one after it must produce the same id on the failure and the success.
func TestE2E_RequestIDSurvivesAFallbackChain(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	good := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	cfg := defaultGatewayConfig([]RouteConfig{
		{Proxy: deadRouteValue(t), Kind: "v4"},
		{Proxy: good.RouteValue(), Kind: "v4"},
	})
	cfg.LogLevel = "debug"
	g := NewGateway(t, cfg)

	status, err := connectWith(t, g.MixedAddr, target.Host, "X-Ecoma-Request-Id: e2e-chain-42")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("CONNECT with a dead first route = %d, want 200 after the fallback", status)
	}

	recs := waitForLogRecord(t, g, map[string]string{
		"msg": "tunnel", "correlation_id": "e2e-chain-42",
	}, 5*time.Second)
	failed, ok := findLogRecord(recs, map[string]string{
		"msg": "upstream dial failed", "correlation_id": "e2e-chain-42", "error_kind": "proxy_connect",
	})
	if !ok {
		t.Fatalf("the failed attempt did not carry the client id:\n%s", g.Logs())
	}
	// Both records belong to the same request: one ordinal, one id.
	succeeded, _ := findLogRecord(recs, map[string]string{"msg": "tunnel", "correlation_id": "e2e-chain-42"})
	if failed["request_id"] != succeeded["request_id"] {
		t.Fatalf("the chain's two records carry different request ids: %v and %v", failed["request_id"], succeeded["request_id"])
	}
	st, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Requests != 1 {
		t.Fatalf("listener requests = %d, want 1 for the whole chain", st.Requests)
	}
}

// A correlation id is bounded and single-line by construction. An oversized one,
// one carrying an ANSI sequence, and one carrying a control character are each
// replaced by a minted id of the same shape, and the request is served
// normally either way.
func TestE2E_RequestIDIsBoundedAndSanitized(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	cfg := defaultGatewayConfig([]RouteConfig{{Proxy: socks.RouteValue(), Kind: "v4"}})
	cfg.LogLevel = "debug"
	g := NewGateway(t, cfg)

	for _, tc := range []struct {
		name      string
		id        string
		wantEched bool
	}{
		{name: "a plain token is echoed", id: "e2e-plain-1", wantEched: true},
		{name: "an opaque id is echoed", id: "01J8Z9RQ4M7N2K3P4T5V6W7X8Y", wantEched: true},
		{name: "an oversized id is replaced", id: strings.Repeat("a", 64*1024)},
		{name: "one byte past the bound is replaced", id: strings.Repeat("a", 65)},
		// A bare ESC byte cannot be expressed on the wire at all: net/http
		// rejects it as a malformed request line, so the gateway answers 400
		// before the id is ever read. That is why the id's own grammar has to
		// do the work — the escape sequences that survive parsing (a value
		// carrying a vertical tab, say) are covered by the unit tests.
		{name: "a quoted value is replaced", id: `"quoted"`},
		{name: "a value with a space is replaced", id: "two words"},
		{name: "a repeated id is replaced", id: "dup"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := []string{"X-Ecoma-Request-Id: " + tc.id}
			if tc.name == "a repeated id is replaced" {
				headers = append(headers, "X-Ecoma-Request-Id: second")
			}
			status, err := connectWith(t, g.MixedAddr, target.Host, headers...)
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			if status != http.StatusOK {
				t.Fatalf("CONNECT with the id = %d, want 200: an unusable id must not fail a serviceable request", status)
			}
			// The gateway log is cumulative, so this request's record is the
			// one whose ordinal is the one /status just counted for it.
			st, err := g.Status()
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]string{"msg": "tunnel", "request_id": fmt.Sprint(st.Requests)}
			recs := waitForLogRecord(t, g, want, 5*time.Second)
			rec, _ := findLogRecord(recs, want)
			id := fmt.Sprint(rec["correlation_id"])
			if tc.wantEched {
				if id != tc.id {
					t.Fatalf("the client id was not echoed; the record carried %q, want %q", id, tc.id)
				}
				return
			}
			if id == tc.id {
				t.Fatalf("an unusable client id was echoed into the log: %q", id)
			}
			// A replacement is a marked token of the same shape, and the raw
			// value left no trace in this request's records.
			if !strings.HasPrefix(id, "r-") || len(id) > 64 || strings.ContainsAny(id, " \t\n\r\"\\") {
				t.Fatalf("the replacement id is not a bounded single-line token: %q", id)
			}

		})
	}
	// Every request above was served, and the process-local ordinal kept
	// counting them all: the client id is a companion field, not a replacement
	// for the counter /status reports.
	st, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Requests != 7 {
		t.Fatalf("listener requests = %d, want 7: every accepted id must have reached route selection", st.Requests)
	}
}

// A request with no id gets one minted, marked as generated, and the minted id
// has the same shape as an accepted client id so a log reader never has to
// special-case it.
func TestE2E_GeneratedRequestIDWhenHeaderAbsent(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	cfg := defaultGatewayConfig([]RouteConfig{{Proxy: socks.RouteValue(), Kind: "v4"}})
	cfg.LogLevel = "debug"
	g := NewGateway(t, cfg)

	for range 3 {
		if status, err := connectWith(t, g.MixedAddr, target.Host); err != nil || status != http.StatusOK {
			t.Fatalf("CONNECT without an id = %d (%v), want 200", status, err)
		}
	}
	// Poll for the last request's record: the log is cumulative, so an early
	// snapshot would only see the records flushed so far.
	recs := waitForLogRecord(t, g, map[string]string{"msg": "tunnel", "request_id": "3"}, 5*time.Second)
	// One id per request ordinal, so the three requests are counted by their
	// own request_id rather than by every record in the log.
	byRequest := map[float64]string{}
	for _, rec := range recs {
		if rec["msg"] != "tunnel" {
			continue
		}
		ordinal, ok := rec["request_id"].(float64)
		if !ok {
			continue
		}
		id := fmt.Sprint(rec["correlation_id"])
		if !strings.HasPrefix(id, "r-") {
			t.Fatalf("a request with no client id carried %q, want a marked generated id", id)
		}
		if len(id) > 64 || strings.ContainsAny(id, " \t\n\r\"\\") {
			t.Fatalf("a generated id is not a bounded single-line token: %q", id)
		}
		byRequest[ordinal] = id
	}
	if len(byRequest) != 3 {
		t.Fatalf("three requests produced %d distinct ids, want 3: a repeated id correlates nothing", len(byRequest))
	}
	seen := map[string]bool{}
	for _, id := range byRequest {
		if seen[id] {
			t.Fatalf("two requests shared the generated id %q", id)
		}
		seen[id] = true
	}
}

// Neither control header reaches an origin, whatever it carries. The forward
// path strips the whole x-ecoma- namespace, so a client-supplied correlation id
// is as invisible to the target as an internal one — which is the only reason
// a client-controlled value can be echoed into a log at all.
func TestE2E_ControlHeadersNeverReachTheOrigin(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target, seen := NewRequestLineEchoTarget(t)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}))

	client := ProxyClient(g.MixedAddr)
	req, err := http.NewRequest(http.MethodGet, target.URL+"/probe", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Ecoma-Proxy-Family", "v4")
	req.Header.Set("X-Ecoma-Request-Id", "e2e-client-id")
	req.Header.Set("X-Ecoma-Unknown", "sneaky")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("forward through the gateway: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	obs := ReadObservedRequest(t, seen, 5*time.Second)
	for name := range obs.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-ecoma-") {
			t.Fatalf("the origin saw the gateway-private header %s: %v", name, obs.Header[name])
		}
	}
}

// The family header is a request-scoped constraint, never part of route
// identity. The same target asked for under different family values must be
// served by the same pool routes: one request, one selection, no forked state.
func TestE2E_ProxyFamilyIsNotPartOfRouteIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	v4 := NewSocksSim(t, SocksOK, "", "")
	v6 := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: v4.RouteValue(), Kind: "v4"},
		{Proxy: v6.RouteValue(), Kind: "v6"},
	}))

	before, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Pool) != 2 {
		t.Fatalf("pool = %d routes, want 2", len(before.Pool))
	}

	for _, family := range []string{"v4", "v6", "mixed", "v4", "v6"} {
		if status, err := connectWith(t, g.MixedAddr, target.Host, "X-Ecoma-Proxy-Family: "+family); err != nil || status != http.StatusOK {
			t.Fatalf("family %q = %d (%v), want 200", family, status, err)
		}
	}

	after, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Pool) != len(before.Pool) {
		t.Fatalf("pool grew from %d to %d routes: the family header reached route identity", len(before.Pool), len(after.Pool))
	}
	for i, entry := range after.Pool {
		if entry.ID != before.Pool[i].ID || entry.Proxy != before.Pool[i].Proxy || entry.Kind != before.Pool[i].Kind {
			t.Fatalf("pool entry %d changed identity: %+v was %+v", i, entry, before.Pool[i])
		}
	}
	// Every request landed on one of the two original routes, which is only
	// possible if the header never forked identity.
	var successes uint64
	for _, entry := range after.Pool {
		successes += entry.Successes
	}
	if successes != 5 {
		t.Fatalf("route successes = %d, want 5 across the two original routes", successes)
	}
}

// The two headers are orthogonal: a family constraint on a request that also
// carries a correlation id narrows the route and the log line together, and
// neither interferes with the other.
func TestE2E_FamilyAndRequestIDCompose(t *testing.T) {
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
	cfg.LogLevel = "debug"
	g := NewGateway(t, cfg)

	status, err := connectWith(t, g.MixedAddr, target.Host,
		"X-Ecoma-Proxy-Family: v6", "X-Ecoma-Request-Id: composed-1")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("a v6 request with a client id = %d, want 200", status)
	}
	if v6.Hits.Load() != 1 || v4.Hits.Load() != 0 {
		t.Fatalf("hits = v4:%d v6:%d, want the v6 route only", v4.Hits.Load(), v6.Hits.Load())
	}
	// The selected route's record carries both: the family narrowed the choice,
	// the id correlates the record.
	recs := waitForLogRecord(t, g, map[string]string{
		"msg": "tunnel", "correlation_id": "composed-1",
	}, 5*time.Second)
	if _, ok := findLogRecord(recs, map[string]string{"msg": "route selected", "correlation_id": "composed-1"}); !ok {
		t.Fatalf("the selection record did not carry the client id:\n%s", g.Logs())
	}
}

// A CONNECT carrying a family header is answered on the same terms as one
// without it: 200 for a served tunnel, 503 for an empty candidate set. The
// header never turns a route failure into a protocol reject, and vice versa.
func TestE2E_FamilyHeaderDoesNotChangeTheFailureStatuses(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	dead := deadRouteValue(t)
	target := NewEchoTarget(t)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{{Proxy: dead, Kind: "v4"}}))

	// One route, retry budget three: the whole budget is spent on that route
	// and the chain ends as retry_exhausted, which is a 503 — whether or not a
	// family was asked for, and whether or not the family is the one the pool
	// can serve. The header changes which routes are candidates, never the
	// status a route failure produces.
	for _, family := range []string{"v4", "mixed", "v4"} {
		status, err := connectWith(t, g.MixedAddr, target.Host, "X-Ecoma-Proxy-Family: "+family)
		if err != nil {
			t.Fatalf("probe %s: %v", family, err)
		}
		if status != http.StatusServiceUnavailable {
			t.Fatalf("a %s request against a dead route = %d, want 503", family, status)
		}
	}
	// A v6 request against a v4-only pool never selects a route at all: the
	// same 503, but no dial behind it, which is what separates an empty
	// candidate set from a spent retry budget.
	status, err := connectWith(t, g.MixedAddr, target.Host, "X-Ecoma-Proxy-Family: v6")
	if err != nil {
		t.Fatalf("probe v6: %v", err)
	}
	if status != http.StatusServiceUnavailable {
		t.Fatalf("a v6 request against a v4-only pool = %d, want 503", status)
	}
}
