package e2e_test

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func proxyAddrs(st *Status) []string {
	out := make([]string, 0, len(st.Pool))
	for _, e := range st.Pool {
		out = append(out, e.Proxy)
	}
	return out
}

func TestE2E_ReloadAddsRoute(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	first := NewSocksSim(t, SocksOK, "", "")
	second := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	cfg := defaultGatewayConfig([]RouteConfig{{Proxy: first.RouteValue(), Kind: "v4"}})
	g := NewGateway(t, cfg)

	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/", "e2e-echo:/")

	cfg.Routes = append(cfg.Routes, RouteConfig{Proxy: second.RouteValue(), Kind: "v6"})
	g.ReloadConfig(cfg, []string{first.Addr, second.Addr})
	waitForLog(t, g, `source=poll`, reloadSettle)

	// Both families now serve through their dedicated listeners.
	GetVia(t, ProxyClient(g.V4Addr), target.URL+"/", "e2e-echo:/")
	GetVia(t, ProxyClient(g.V6Addr), target.URL+"/", "e2e-echo:/")
	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/", "e2e-echo:/")
}

func TestE2E_ReloadRemovesRoute(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	keep := NewSocksSim(t, SocksOK, "", "")
	drop := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	cfg := defaultGatewayConfig([]RouteConfig{
		{Proxy: keep.RouteValue(), Kind: "v4"},
		{Proxy: drop.RouteValue(), Kind: "v4"},
	})
	g := NewGateway(t, cfg)

	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/", "e2e-echo:/")
	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/", "e2e-echo:/")

	cfg.Routes = cfg.Routes[:1]
	g.ReloadConfig(cfg, []string{keep.Addr})

	// The survivor keeps serving; shrinking 2->1 does not break the pool.
	for range 5 {
		GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/", "e2e-echo:/")
	}
}

func TestE2E_ReloadShrinksToOtherFamily(t *testing.T) {
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
	g := NewGateway(t, cfg)

	GetVia(t, ProxyClient(g.V4Addr), target.URL+"/", "e2e-echo:/")

	// Drop the v4 route entirely: mixed and v6 keep working, v4 returns the
	// ordinary no-route 502 while staying live.
	cfg.Routes = []RouteConfig{{Proxy: v6.RouteValue(), Kind: "v6"}}
	g.ReloadConfig(cfg, []string{v6.Addr})

	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/", "e2e-echo:/")
	GetVia(t, ProxyClient(g.V6Addr), target.URL+"/", "e2e-echo:/")
	resp, err := ProxyClient(g.V4Addr).Get(target.URL + "/")
	if err != nil {
		t.Fatalf("v4 GET: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("v4 status=%d, want 502", resp.StatusCode)
	}
}

func TestE2E_InvalidConfigKeepsServing(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	cfg := defaultGatewayConfig([]RouteConfig{{Proxy: socks.RouteValue(), Kind: "v4"}})
	g := NewGateway(t, cfg)

	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/", "e2e-echo:/")
	before, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"malformed yaml": "log-level: [unclosed\nmax-retries: nope\n",
		"duplicate route": fmt.Sprintf(`log-level: info
max-retries: 3
cooldown: {base: 5s, max: 1m}
dial-timeout: 5s
global: {target-tls-insecure: false, max-body-buffer: 67108864}
proxies:
  auto:
    - {proxy: '%s', kind: v4}
    - {proxy: '%s', kind: v4}
  manual: []
`, socks.RouteValue(), socks.RouteValue()),
		"missing kind": fmt.Sprintf(`log-level: info
max-retries: 3
cooldown: {base: 5s, max: 1m}
dial-timeout: 5s
global: {target-tls-insecure: false, max-body-buffer: 67108864}
proxies:
  auto:
    - {proxy: '%s'}
  manual: []
`, socks.RouteValue()),
		"empty pool": `log-level: info
max-retries: 3
cooldown: {base: 5s, max: 1m}
dial-timeout: 5s
global: {target-tls-insecure: false, max-body-buffer: 67108864}
proxies:
  auto: []
  manual: []
`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			g.ReloadConfigRaw(raw)
			// The poller must reject the file within one poll cycle and log the
			// sanitized warning while the old generation keeps serving.
			waitForLog(t, g, "reload failed", reloadSettle)
			GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/", "e2e-echo:/")
		})
	}

	// Restore the valid config through the same hot-reload path.
	g.ReloadConfig(cfg, []string{socks.Addr})
	st, _ := g.Status()
	if len(st.Pool) != len(before.Pool) || st.Pool[0].Proxy != before.Pool[0].Proxy {
		t.Fatalf("pool changed after invalid reloads: %+v", st.Pool)
	}
}

func TestE2E_ReloadChangedCredsResetState(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksAuthRequired, "e2e-user", "e2e-right-pass")
	target := NewEchoTarget(t)
	right := fmt.Sprintf("socks5://e2e-user:e2e-right-pass@%s", socks.Addr)
	cfg := defaultGatewayConfig([]RouteConfig{
		{Proxy: fmt.Sprintf("socks5://e2e-user:e2e-wrong-pass@%s", socks.Addr), Kind: "v4"},
		{Proxy: deadRouteValue(t), Kind: "v4"},
	})
	g := NewGateway(t, cfg)

	// Request until the wrong-creds route is auth-blocked. The dead second
	// route cools down, so the auth fallback exhausts and returns 502; both
	// outcomes burn the block into pool state, which is what we assert on.
	g.WaitForCondition(15*time.Second, "auth block on wrong-creds route", func(st *Status) bool {
		resp, err := ProxyClient(g.MixedAddr).Get(target.URL + "/")
		if err == nil {
			_, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}
		for _, e := range st.Pool {
			if e.AuthBlocked {
				return true
			}
		}
		return false
	})

	// Fix the password: same host:port but different userinfo is a new route
	// identity with fresh state, so requests succeed again. The address list
	// is unchanged, so wait on the zeroed counters that prove the swap.
	cfg.Routes = []RouteConfig{{Proxy: right, Kind: "v4"}}
	g.ReloadConfig(cfg, []string{socks.Addr})
	g.WaitForCondition(reloadSettle, "userinfo swap reset route state", func(st *Status) bool {
		return len(st.Pool) == 1 && !st.Pool[0].AuthBlocked && st.Pool[0].AuthFailures == 0
	})

	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/", "e2e-echo:/")
	st, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Pool[0].AuthBlocked || st.Pool[0].Successes < 1 {
		t.Fatalf("fixed-creds route should be fresh and successful: %+v", st.Pool[0])
	}
}

func TestE2E_ReloadChangedKindResetsState(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	cfg := defaultGatewayConfig([]RouteConfig{{Proxy: socks.RouteValue(), Kind: "v4"}})
	g := NewGateway(t, cfg)

	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/", "e2e-echo:/")
	before, _ := g.Status()
	if before.Pool[0].Successes != 1 {
		t.Fatalf("pool=%+v", before.Pool)
	}

	// Same URL, new kind: the proxy address is unchanged, so wait on the kind
	// flip itself rather than the address list.
	cfg.Routes = []RouteConfig{{Proxy: socks.RouteValue(), Kind: "v6"}}
	g.ReloadConfig(cfg, []string{socks.Addr})
	g.WaitForCondition(reloadSettle, "kind change reset route state", func(st *Status) bool {
		return len(st.Pool) == 1 && st.Pool[0].Kind == "v6" && st.Pool[0].Successes == 0
	})

	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/", "e2e-echo:/")
	st, _ := g.Status()
	if st.Pool[0].Kind != "v6" || st.Pool[0].Successes != 1 {
		t.Fatalf("serving after kind change broken: %+v", st.Pool[0])
	}
}

func TestE2E_ReloadPreservesHealthForUnchangedRoutes(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	good := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	cfg := defaultGatewayConfig([]RouteConfig{
		{Proxy: deadRouteValue(t), Kind: "v4"},
		{Proxy: good.RouteValue(), Kind: "v4"},
	})
	g := NewGateway(t, cfg)

	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/", "e2e-echo:/")
	st := g.WaitForCondition(5*time.Second, "dial failure recorded", func(st *Status) bool {
		return len(st.Pool) == 2 && st.Pool[0].Failures == 1
	})
	deadFailures := st.Pool[0].Failures

	// Same URL+kind routes, only log-level changes: health must survive.
	cfg.LogLevel = "debug"
	g.ReloadConfig(cfg, proxyAddrs(st))

	st, _ = g.Status()
	if st.Pool[0].Failures != deadFailures || st.Pool[0].CooldownFor == "0s" {
		t.Fatalf("reload dropped dial health: %+v", st.Pool[0])
	}
	if st.Pool[1].Successes != 1 {
		t.Fatalf("reload dropped success counters: %+v", st.Pool[1])
	}
}

// log-level is one of the settings that applies to new operations without a
// restart: after a reload to debug, fresh requests must emit debug lines that
// info level suppressed.
func TestE2E_ReloadAppliesLogLevel(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	cfg := defaultGatewayConfig([]RouteConfig{{Proxy: socks.RouteValue(), Kind: "v4"}})
	g := NewGateway(t, cfg)

	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/", "e2e-echo:/")
	if out := g.Logs(); strings.Contains(out, `msg="request start"`) {
		t.Fatalf("debug line present at info level:\n%s", out)
	}

	cfg.LogLevel = "debug"
	g.ReloadConfig(cfg, []string{socks.Addr})
	// This reload leaves the pool unchanged, so ReloadConfig cannot wait for
	// it to apply; wait for the reload log instead of the pool snapshot.
	waitForLog(t, g, `msg="configuration reloaded"`, reloadSettle)
	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/", "e2e-echo:/")
	waitForLog(t, g, `msg="request start"`, reloadSettle)
}

func TestE2E_ReloadDoesNotDropInFlight(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	first := NewSocksSim(t, SocksOK, "", "")
	second := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	cfg := defaultGatewayConfig([]RouteConfig{{Proxy: first.RouteValue(), Kind: "v4"}})
	g := NewGateway(t, cfg)

	var failures atomic.Uint64
	var done atomic.Bool
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := ProxyClient(g.MixedAddr)
			for !done.Load() {
				resp, err := client.Get(target.URL + "/load")
				if err != nil {
					failures.Add(1)
					continue
				}
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK || string(body) != "e2e-echo:/load" {
					failures.Add(1)
				}
			}
		}()
	}

	// Rewrite the file several times (grow, shrink, grow) while load is in
	// flight. Reloads happen purely through the gateway's config poller.
	time.Sleep(200 * time.Millisecond)
	cfg.Routes = append(cfg.Routes, RouteConfig{Proxy: second.RouteValue(), Kind: "v4"})
	g.ReloadConfig(cfg, []string{first.Addr, second.Addr})
	cfg.Routes = cfg.Routes[:1]
	g.ReloadConfig(cfg, []string{first.Addr})
	cfg.Routes = append(cfg.Routes, RouteConfig{Proxy: second.RouteValue(), Kind: "v4"})
	g.ReloadConfig(cfg, []string{first.Addr, second.Addr})
	done.Store(true)
	wg.Wait()

	if got := failures.Load(); got != 0 {
		t.Fatalf("reload dropped %d in-flight requests; logs:\n%s", got, g.Logs())
	}
}
