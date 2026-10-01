package e2e_test

import (
	"strings"
	"testing"
)

// Route lines carry no scheme: every route is a SOCKS5H endpoint. All three
// documented bare forms must serve traffic through the same dial path.
func TestBareRouteFormsServeTraffic(t *testing.T) {
	target := NewEchoTarget(t)
	for _, tc := range []struct {
		name  string
		route func(addr string) string
		auth  bool
	}{
		{"host:port", func(addr string) string { return addr }, false},
		{"host:port:user:pass", func(addr string) string { return addr + ":route-user:route-pass" }, true},
		{"user:pass@host:port", func(addr string) string { return "route-user:route-pass@" + addr }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sim *SocksSim
			if tc.auth {
				sim = NewSocksSim(t, SocksAuthRequired, "route-user", "route-pass")
			} else {
				sim = NewSocksSim(t, SocksOK, "", "")
			}
			gw := NewGateway(t, defaultGatewayConfig([]RouteConfig{
				{Proxy: tc.route(sim.Addr), Kind: "v4"},
			}))
			code, body := GetVia(t, ProxyClient(gw.MixedAddr), target.URL+"/route", "e2e-echo:/route")
			if code != 200 {
				t.Fatalf("GET via %q route: status %d body %q", tc.name, code, body)
			}
			if sim.Hits.Load() == 0 {
				t.Fatal("the route simulator saw no connection")
			}
		})
	}
}

// A scheme'd route line is rejected outright — the endpoint protocol is not
// configurable — and a rejected config must leave the last-known-good pool
// serving untouched. The second route exists to make the surviving pool
// distinguishable from a hypothetical cold start.
func TestSchemedRouteLineRejectedKeepsServing(t *testing.T) {
	target := NewEchoTarget(t)
	sim := NewSocksSim(t, SocksOK, "", "")
	other := NewSocksSim(t, SocksOK, "", "")
	gw := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: sim.Addr, Kind: "v4"},
		{Proxy: other.Addr, Kind: "v4"},
	}))

	GetVia(t, ProxyClient(gw.MixedAddr), target.URL+"/before", "e2e-echo:/before")

	cfg := defaultGatewayConfig([]RouteConfig{
		{Proxy: "socks5://" + sim.Addr, Kind: "v4"},
		{Proxy: other.Addr, Kind: "v4"},
	})
	gw.ReloadConfigRaw(renderConfig(cfg))
	gw.WaitForCondition(reloadSettle, "a rejected reload to keep the previous configuration serving",
		func(*Status) bool {
			return strings.Contains(gw.Logs(), "carry no scheme") &&
				strings.Contains(gw.Logs(), "reload failed; keeping previous configuration")
		})
	st, err := gw.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Pool) != 2 {
		t.Fatalf("pool after the rejected reload has %d routes, want the last-known-good 2", len(st.Pool))
	}
	if st.Pool[0].Proxy != sim.Addr || st.Pool[1].Proxy != other.Addr {
		t.Fatalf("pool after the rejected reload = [%s, %s], want the last-known-good routes [%s, %s]",
			st.Pool[0].Proxy, st.Pool[1].Proxy, sim.Addr, other.Addr)
	}
	if got := st.Pool[0].Successes; got != 1 {
		t.Fatalf("successes after the rejected reload = %d, want the serving state preserved (1)", got)
	}
	GetVia(t, ProxyClient(gw.MixedAddr), target.URL+"/after", "e2e-echo:/after")
}
