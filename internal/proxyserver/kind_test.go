package proxyserver

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
)

func TestRuntimeSettingsSnapshotUsesOneGeneration(t *testing.T) {
	a, err := url.Parse("socks5://a.test:1080")
	if err != nil {
		t.Fatal(err)
	}
	initial := &config.RuntimeConfig{
		MaxRetries:        1,
		MaxBodyBuffer:     2,
		DialTimeout:       3 * time.Second,
		TargetTLSInsecure: false,
		Routes:            []config.RouteSpec{{URL: a, Kind: config.EgressV4}},
	}
	store := pool.NewStore(initial, pool.NewRoutes(initial.Routes, time.Second, time.Minute, config.KindBalance{}))
	server := NewRuntime(store, slog.New(slog.NewTextHandler(io.Discard, nil)), "test", "mixed", config.EgressV4, config.EgressV6)

	b, err := url.Parse("socks5://b.test:1080")
	if err != nil {
		t.Fatal(err)
	}
	next := &config.RuntimeConfig{
		MaxRetries:        4,
		MaxBodyBuffer:     5,
		DialTimeout:       6 * time.Second,
		TargetTLSInsecure: true,
		CooldownBase:      time.Second,
		CooldownMax:       time.Minute,
		Routes:            []config.RouteSpec{{URL: b, Kind: config.EgressV4}},
	}
	// Publish exercises the real reload path: validated config plus a
	// reconfigured pool snapshot become visible as one generation.
	store.Publish(next)

	got := server.settings()
	want := requestSettings{maxRetries: 4, maxBodyBuffer: 5, dialTimeout: 6 * time.Second, targetTLSInsecure: true}
	if got != want {
		t.Fatalf("settings = %+v, want %+v", got, want)
	}
	if picked := server.generation().Pool.PickFor(nil, nil); picked == nil || picked.URL.Host != "b.test:1080" {
		t.Fatalf("published pool pick = %+v, want b.test:1080", picked)
	}
}

// TestRuntimeGenerationIsolatesInFlightWork proves settings and pool selection
// come from one loaded generation: work holding the pre-publish snapshot keeps
// its original settings and routes after a reload publishes a new generation.
func TestRuntimeGenerationIsolatesInFlightWork(t *testing.T) {
	a, err := url.Parse("socks5://a.test:1080")
	if err != nil {
		t.Fatal(err)
	}
	b, err := url.Parse("socks5://b.test:1080")
	if err != nil {
		t.Fatal(err)
	}
	initial := &config.RuntimeConfig{
		MaxRetries:    1,
		MaxBodyBuffer: 2,
		DialTimeout:   3 * time.Second,
		Routes:        []config.RouteSpec{{URL: a, Kind: config.EgressV4}},
	}
	store := pool.NewStore(initial, pool.NewRoutes(initial.Routes, time.Second, time.Minute, config.KindBalance{}))
	server := NewRuntime(store, slog.New(slog.NewTextHandler(io.Discard, nil)), "test", "mixed", config.EgressV4, config.EgressV6)

	inFlight := server.generation()
	inFlightSettings := generationSettings(inFlight)

	next := &config.RuntimeConfig{
		MaxRetries:    5,
		MaxBodyBuffer: 6,
		DialTimeout:   7 * time.Second,
		CooldownBase:  time.Second,
		CooldownMax:   time.Minute,
		Routes:        []config.RouteSpec{{URL: b, Kind: config.EgressV4}},
	}
	store.Publish(next)

	if got := generationSettings(inFlight); got != inFlightSettings {
		t.Fatalf("in-flight settings changed: got %+v, want %+v", got, inFlightSettings)
	}
	if picked := inFlight.Pool.PickFor(nil, nil); picked == nil || picked.URL.Host != "a.test:1080" {
		t.Fatalf("in-flight pool pick = %+v, want a.test:1080", picked)
	}
	current := server.generation()
	if current == inFlight {
		t.Fatal("server still serves pre-publish generation after Publish")
	}
	if current.Config.MaxRetries != 5 {
		t.Fatalf("current settings = %+v, want MaxRetries 5", current.Config)
	}
	if picked := current.Pool.PickFor(nil, nil); picked == nil || picked.URL.Host != "b.test:1080" {
		t.Fatalf("current pool pick = %+v, want b.test:1080", picked)
	}
}

func TestRuntimeListenerSelectsOnlyAllowedEgressKind(t *testing.T) {
	v4 := startSocks5Proxy(t, socksOptions{})
	v6 := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes([]config.RouteSpec{
		{URL: v4.URL, Kind: config.EgressV4},
		{URL: v6.URL, Kind: config.EgressV6},
	}, time.Second, time.Minute, config.KindBalance{})
	runtime := pool.NewStore(&config.RuntimeConfig{
		MaxRetries:    2,
		DialTimeout:   time.Second,
		MaxBodyBuffer: 64 << 20,
		Routes:        nil,
	}, pl)

	v4Proxy := httptest.NewServer(NewRuntime(runtime, testLogger(), "test", "v4", config.EgressV4))
	defer v4Proxy.Close()
	v6Proxy := httptest.NewServer(NewRuntime(runtime, testLogger(), "test", "v6", config.EgressV6))
	defer v6Proxy.Close()
	target := startEchoTarget(t)

	for name, proxyURL := range map[string]string{"v4": v4Proxy.URL, "v6": v6Proxy.URL} {
		t.Run(name, func(t *testing.T) {
			resp, err := proxiedClient(t, proxyURL).Get("http://" + target + "/")
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d", resp.StatusCode)
			}
		})
	}

	select {
	case <-v4.hits:
	default:
		t.Fatal("v4 listener did not use v4 route")
	}
	select {
	case <-v6.hits:
	default:
		t.Fatal("v6 listener did not use v6 route")
	}
}

func TestListenerLogsItsNameAndAdminAggregatesStatus(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes([]config.RouteSpec{{URL: fs.URL, Kind: config.EgressV4}}, time.Second, time.Minute, config.KindBalance{})
	runtime := pool.NewStore(&config.RuntimeConfig{MaxRetries: 1, DialTimeout: time.Second, MaxBodyBuffer: 1 << 20}, pl)
	var logs safeLogBuffer
	srv := NewRuntime(runtime, captureLogger(&logs, slog.LevelDebug), "test", "v4", config.EgressV4)
	proxy := httptest.NewServer(srv)
	defer proxy.Close()

	resp, err := proxiedClient(t, proxy.URL).Get("http://" + startEchoTarget(t) + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := waitForLog(t, &logs, "listener=v4"); got == "" {
		t.Fatal("listener log missing")
	}

	admin := httptest.NewServer(AdminMux("test", time.Now(), runtime, map[string]*Server{"v4": srv}, nil))
	defer admin.Close()
	status, err := http.Get(admin.URL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer status.Body.Close()
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

func TestRuntimeListenerNoEligibleRouteReturns502(t *testing.T) {
	u, err := url.Parse("socks5://v4.test:1080")
	if err != nil {
		t.Fatal(err)
	}
	pl := pool.NewRoutes([]config.RouteSpec{{URL: u, Kind: config.EgressV4}}, time.Second, time.Minute, config.KindBalance{})
	runtime := pool.NewStore(&config.RuntimeConfig{MaxRetries: 1, DialTimeout: time.Second, MaxBodyBuffer: 1 << 20}, pl)
	srv := httptest.NewServer(NewRuntime(runtime, testLogger(), "test", "v6", config.EgressV6))
	defer srv.Close()
	resp, err := proxiedClient(t, srv.URL).Get("http://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if snap := pl.Snapshot()[0]; snap.Failures != 0 || snap.Successes != 0 {
		t.Fatalf("no-route changed health: %+v", snap)
	}
}
