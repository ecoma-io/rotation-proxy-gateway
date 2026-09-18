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

	"proxy-auto-rotate-forwarder/internal/config"
	"proxy-auto-rotate-forwarder/internal/pool"
)

func TestRuntimeSettingsSnapshotUsesOneGeneration(t *testing.T) {
	initial := &config.RuntimeConfig{
		MaxRetries:        1,
		MaxBodyBuffer:     2,
		DialTimeout:       3 * time.Second,
		TargetTLSInsecure: false,
	}
	store := config.NewStore(initial)
	server := NewRuntime(pool.NewRoutes(nil, time.Second, time.Minute), store, slog.New(slog.NewTextHandler(io.Discard, nil)), "test", "mixed", config.EgressV4, config.EgressV6)

	next := &config.RuntimeConfig{
		MaxRetries:        4,
		MaxBodyBuffer:     5,
		DialTimeout:       6 * time.Second,
		TargetTLSInsecure: true,
	}
	store.Store(next)

	got := server.settings()
	want := requestSettings{maxRetries: 4, maxBodyBuffer: 5, dialTimeout: 6 * time.Second, targetTLSInsecure: true}
	if got != want {
		t.Fatalf("settings = %+v, want %+v", got, want)
	}
}

func TestRuntimeListenerSelectsOnlyAllowedEgressKind(t *testing.T) {
	v4 := startSocks5Proxy(t, socksOptions{})
	v6 := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes([]config.RouteSpec{
		{URL: v4.URL, Kind: config.EgressV4},
		{URL: v6.URL, Kind: config.EgressV6},
	}, time.Second, time.Minute)
	runtime := config.NewStore(&config.RuntimeConfig{
		MaxRetries:    2,
		DialTimeout:   time.Second,
		MaxBodyBuffer: 64 << 20,
		Routes:        nil,
	})

	v4Proxy := httptest.NewServer(NewRuntime(pl, runtime, testLogger(), "test", "v4", config.EgressV4))
	defer v4Proxy.Close()
	v6Proxy := httptest.NewServer(NewRuntime(pl, runtime, testLogger(), "test", "v6", config.EgressV6))
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
	pl := pool.NewRoutes([]config.RouteSpec{{URL: fs.URL, Kind: config.EgressV4}}, time.Second, time.Minute)
	runtime := config.NewStore(&config.RuntimeConfig{MaxRetries: 1, DialTimeout: time.Second, MaxBodyBuffer: 1 << 20})
	var logs safeLogBuffer
	srv := NewRuntime(pl, runtime, captureLogger(&logs, slog.LevelDebug), "test", "v4", config.EgressV4)
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

	admin := httptest.NewServer(AdminMux("test", time.Now(), pl, map[string]*Server{"v4": srv}))
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
	pl := pool.NewRoutes([]config.RouteSpec{{URL: u, Kind: config.EgressV4}}, time.Second, time.Minute)
	runtime := config.NewStore(&config.RuntimeConfig{MaxRetries: 1, DialTimeout: time.Second, MaxBodyBuffer: 1 << 20})
	srv := httptest.NewServer(NewRuntime(pl, runtime, testLogger(), "test", "v6", config.EgressV6))
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
