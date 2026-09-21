package proxyserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/logging"
	"rotation-proxy-gateway/internal/pool"
)

func TestSettingsFollowPublishedGeneration(t *testing.T) {
	a, err := url.Parse("socks5://a.test:1080")
	if err != nil {
		t.Fatal(err)
	}
	initial := &config.RuntimeConfig{
		MaxRetries:   1,
		DialTimeout:  3 * time.Second,
		CooldownBase: time.Second,
		CooldownMax:  time.Minute,
		Routes:       []config.RouteSpec{{URL: a, Kind: config.EgressV4}},
	}
	store := pool.NewStore(initial, pool.NewRoutes(initial.Routes, time.Second, time.Minute, config.KindBalance{}))
	server := NewRuntime(store, logging.Nop(), "test", "mixed", config.EgressV4, config.EgressV6)

	b, err := url.Parse("socks5://b.test:1080")
	if err != nil {
		t.Fatal(err)
	}
	next := &config.RuntimeConfig{
		MaxRetries:   4,
		DialTimeout:  6 * time.Second,
		CooldownBase: time.Second,
		CooldownMax:  time.Minute,
		Routes:       []config.RouteSpec{{URL: b, Kind: config.EgressV4}},
	}
	// Publish exercises the real reload path: validated config plus a
	// reconfigured pool snapshot become visible as one generation.
	store.Publish(next)

	if got, want := server.settings(), (sessionSettings{maxRetries: 4, dialTimeout: 6 * time.Second}); got != want {
		t.Fatalf("settings = %+v, want %+v", got, want)
	}
	if picked := server.pick(server.generation(), nil, "t:443"); picked == nil || picked.URL.Host != "b.test:1080" {
		t.Fatalf("published pool pick = %+v, want b.test:1080", picked)
	}
}

// TestGenerationIsolatesInFlightWork proves settings and pool selection come
// from one loaded generation: work holding the pre-publish snapshot keeps its
// original settings and routes after a reload publishes a new generation.
func TestGenerationIsolatesInFlightWork(t *testing.T) {
	a, err := url.Parse("socks5://a.test:1080")
	if err != nil {
		t.Fatal(err)
	}
	b, err := url.Parse("socks5://b.test:1080")
	if err != nil {
		t.Fatal(err)
	}
	initial := &config.RuntimeConfig{
		MaxRetries:   1,
		DialTimeout:  3 * time.Second,
		CooldownBase: time.Second,
		CooldownMax:  time.Minute,
		Routes:       []config.RouteSpec{{URL: a, Kind: config.EgressV4}},
	}
	store := pool.NewStore(initial, pool.NewRoutes(initial.Routes, time.Second, time.Minute, config.KindBalance{}))
	server := NewRuntime(store, logging.Nop(), "test", "mixed", config.EgressV4, config.EgressV6)

	inFlight := server.generation()
	inFlightSettings := generationSettings(inFlight)

	next := &config.RuntimeConfig{
		MaxRetries:   5,
		DialTimeout:  7 * time.Second,
		CooldownBase: time.Second,
		CooldownMax:  time.Minute,
		Routes:       []config.RouteSpec{{URL: b, Kind: config.EgressV4}},
	}
	store.Publish(next)

	if got := generationSettings(inFlight); got != inFlightSettings {
		t.Fatalf("in-flight settings changed: got %+v, want %+v", got, inFlightSettings)
	}
	if picked := server.pick(inFlight, nil, "t:443"); picked == nil || picked.URL.Host != "a.test:1080" {
		t.Fatalf("in-flight pool pick = %+v, want a.test:1080", picked)
	}
	current := server.generation()
	if current == inFlight {
		t.Fatal("server still serves pre-publish generation after Publish")
	}
	if current.Config.MaxRetries != 5 {
		t.Fatalf("current settings = %+v, want MaxRetries 5", current.Config)
	}
	if picked := server.pick(current, nil, "t:443"); picked == nil || picked.URL.Host != "b.test:1080" {
		t.Fatalf("current pool pick = %+v, want b.test:1080", picked)
	}
}

// Each dedicated listener must use only routes of its own egress family: a
// v4-only listener never picks a v6 route and vice versa.
func TestListenerSelectsOnlyAllowedEgressKind(t *testing.T) {
	v4 := startSocks5Proxy(t, socksOptions{})
	v6 := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes([]config.RouteSpec{
		{URL: v4.URL, Kind: config.EgressV4},
		{URL: v6.URL, Kind: config.EgressV6},
	}, time.Second, time.Minute, config.KindBalance{})
	runtime := pool.NewStore(&config.RuntimeConfig{
		MaxRetries:  2,
		DialTimeout: time.Second,
	}, pl)

	v4Srv := NewRuntime(runtime, testLogger(), "test", "v4", config.EgressV4)
	v4Addr := startServer(t, v4Srv)
	v6Srv := NewRuntime(runtime, testLogger(), "test", "v6", config.EgressV6)
	v6Addr := startServer(t, v6Srv)
	target := startRawEchoTarget(t)

	for _, tc := range []struct {
		name   string
		addr   string
		expect *fakeSocks
		other  *fakeSocks
	}{
		{name: "v4", addr: v4Addr, expect: v4, other: v6},
		{name: "v6", addr: v6Addr, expect: v6, other: v4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := socksDialVia(t, tc.addr, target)
			readBanner(t, conn)
			_ = conn.Close()

			select {
			case <-tc.expect.hits:
			default:
				t.Fatalf("%s listener did not use the %s route", tc.name, tc.name)
			}
			select {
			case <-tc.other.hits:
				t.Fatalf("%s listener leaked into the other kind", tc.name)
			default:
			}
		})
	}
}

func TestListenerLogsItsNameAndAdminAggregatesStatus(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes([]config.RouteSpec{{URL: fs.URL, Kind: config.EgressV4}}, time.Second, time.Minute, config.KindBalance{})
	runtime := pool.NewStore(&config.RuntimeConfig{MaxRetries: 1, DialTimeout: time.Second}, pl)
	var logs safeLogBuffer
	srv := NewRuntime(runtime, captureLogger(&logs), "test", "v4", config.EgressV4)
	addr := startServer(t, srv)

	conn := socksDialVia(t, addr, startRawEchoTarget(t))
	readBanner(t, conn)
	_ = conn.Close()
	if got := waitForRecord(t, &logs, map[string]string{"msg": "tunnel", "listener": "v4"}); got == "" {
		t.Fatal("listener tunnel record missing")
	}

	admin := httptest.NewServer(AdminMux("test", time.Now(), runtime, map[string]*Server{"v4": srv}, nil, nil))
	defer admin.Close()
	status, err := http.Get(admin.URL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = status.Body.Close() }()
	var response struct {
		Listeners map[string]ListenerStatus `json:"listeners"`
		Pool      []pool.Status             `json:"pool"`
	}
	if err := json.NewDecoder(status.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Listeners["v4"].Requests != 1 || len(response.Pool) != 1 || response.Pool[0].Kind != config.EgressV4 {
		t.Fatalf("status = %+v", response)
	}
}

// A dedicated listener without a matching route stays live and answers the
// ordinary no-route failure without touching the other kind's routes.
func TestListenerNoEligibleRouteRepliesGeneralFailure(t *testing.T) {
	u, err := url.Parse("socks5://v4.test:1080")
	if err != nil {
		t.Fatal(err)
	}
	pl := pool.NewRoutes([]config.RouteSpec{{URL: u, Kind: config.EgressV4}}, time.Second, time.Minute, config.KindBalance{})
	runtime := pool.NewStore(&config.RuntimeConfig{MaxRetries: 1, DialTimeout: time.Second}, pl)
	srv := NewRuntime(runtime, testLogger(), "test", "v6", config.EgressV6)
	addr := startServer(t, srv)

	conn, code := socksConnectReply(t, addr, "example.test:80", socksCmdConnect)
	_ = conn.Close()
	if code != socksReplyGeneral {
		t.Fatalf("reply = 0x%02x, want general failure 0x01", code)
	}
	if snap := pl.Snapshot()[0]; snap.Failures != 0 || snap.Successes != 0 {
		t.Fatalf("no-route changed health: %+v", snap)
	}
	if status := srv.ListenerStatus(); status.Requests != 1 || status.Failovers != 0 {
		t.Fatalf("listener status = %+v", status)
	}
}
