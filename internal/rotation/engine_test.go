package rotation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
)

// fastSettings keeps procedure tests quick while staying internally valid.
func fastSettings() config.RotationSettings {
	return config.RotationSettings{
		MaxConcurrentFixed: ptrInt(1),
		DrainTimeout:       2 * time.Second,
		IPCheckURL:         "https://example.com/trace",
		IPCheckTimeout:     600 * time.Millisecond,
		IPCheckInterval:    50 * time.Millisecond,
		RetryBackoffMax:    time.Minute,
	}
}

func ptrInt(v int) *int { return &v }

func mustSpecURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

func manualRoute(t *testing.T, host string, interval time.Duration, api config.RotateAPI) config.ManualRouteSpec {
	t.Helper()
	return config.ManualRouteSpec{
		RouteSpec:      config.RouteSpec{URL: mustSpecURL(t, "socks5://"+host+":1080"), Kind: config.EgressV6, Origin: config.RouteOriginManual},
		RotateInterval: interval,
		API:            api,
	}
}

// ipServer serves key=value trace bodies over TLS whose ip= entry flips under
// test control (or is unique per request in unique mode). The engine's probe
// always TLS-verifies, so tests inject the server certificate into the probe
// trust pool.
type ipServer struct {
	srv     *httptest.Server
	rootCAs *x509.CertPool
	static  atomic.Value // string
	unique  atomic.Bool
	counter atomic.Int32
}

func newIPServer(t *testing.T, initial string) *ipServer {
	t.Helper()
	s := &ipServer{}
	s.static.Store(initial)
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if s.unique.Load() {
			n := int(s.counter.Add(1))
			fmt.Fprintf(w, "loc=XX\nip=10.%d.%d.%d\n", (n>>16)&255, (n>>8)&255, n&255)
			return
		}
		fmt.Fprintf(w, "loc=XX\nip=%s\ntls=1.3\n", s.static.Load())
	}))
	t.Cleanup(s.srv.Close)
	s.rootCAs = x509.NewCertPool()
	s.rootCAs.AddCert(s.srv.Certificate())
	return s
}

func (s *ipServer) set(ip string) { s.static.Store(ip) }

// testEngine wires an Engine whose probe dials straight into ips and trusts
// its test certificate. Production keeps socksdial.Dial and a fully verifying
// TLS configuration; only these two seams change. routeFail, when non-nil,
// makes every route dial fail (baseline probes observe a dead route).
func testEngine(t *testing.T, ips *ipServer, store *pool.Store, routeFail *atomic.Bool) *Engine {
	t.Helper()
	e := New(store, discardLogger())
	e.dial = func(ctx context.Context, pu *url.URL, target string, timeout time.Duration) (net.Conn, error) {
		if routeFail != nil && routeFail.Load() {
			return nil, errors.New("route endpoint unreachable (TEST)")
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ips.srv.Listener.Addr().String())
	}
	e.probeTLS = func(host string) *tls.Config {
		return &tls.Config{ServerName: host, RootCAs: ips.rootCAs, MinVersion: tls.VersionTLS12}
	}
	return e
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, nil))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func testPool(t *testing.T, cfg *config.RuntimeConfig) *pool.Pool {
	t.Helper()
	specs := make([]config.RouteSpec, 0, len(cfg.ManualRoutes))
	for _, m := range cfg.ManualRoutes {
		specs = append(specs, m.RouteSpec)
	}
	return pool.NewRoutes(specs, 30*time.Second, time.Minute)
}

// setup builds the config/pool/generation trio and an engine over them. All
// procedure tests share it so the procedure mutates the same pool the test
// inspects.
type setup struct {
	cfg *config.RuntimeConfig
	pl  *pool.Pool
	gen *pool.Generation
	e   *Engine
}

func newSetup(t *testing.T, cfg *config.RuntimeConfig, routeFail *atomic.Bool, ips *ipServer) *setup {
	t.Helper()
	pl := testPool(t, cfg)
	s := &setup{
		cfg: cfg,
		pl:  pl,
		gen: pool.NewGeneration(cfg, pl),
		e:   testEngine(t, ips, pool.NewStore(cfg, pl), routeFail),
	}
	return s
}

// runOne runs one procedure for spec through the shared generation.
func (s *setup) runOne(spec config.ManualRouteSpec) {
	s.e.runProcedure(context.Background(), s.gen, spec,
		s.pl.Lookup(routeID(spec.RouteSpec)), routeID(spec.RouteSpec))
}

func snapshotHost(t *testing.T, pl *pool.Pool, host string) pool.Status {
	t.Helper()
	for _, s := range pl.Snapshot() {
		if s.Proxy == host+":1080" {
			return s
		}
	}
	t.Fatalf("route %q missing from snapshot", host)
	return pool.Status{}
}

func TestBackoffFor(t *testing.T) {
	interval := 90 * time.Second
	max := 15 * time.Minute
	for _, tc := range []struct {
		name        string
		consecutive int
		wantMin     time.Duration
		wantMax     time.Duration
	}{
		// ±10% jitter around the doubling base; the cap clamps the top.
		{"first failure waits one interval", 1, interval * 9 / 10, interval * 11 / 10},
		{"second failure doubles", 2, interval * 2 * 9 / 10, interval * 2 * 11 / 10},
		{"third failure quadruples", 3, interval * 4 * 9 / 10, interval * 4 * 11 / 10},
		{"grows but stays sane", 10, max * 9 / 10, max},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for range 20 {
				got := BackoffFor(interval, tc.consecutive, max)
				if got < tc.wantMin || got > tc.wantMax {
					t.Fatalf("BackoffFor(consecutive=%d) = %s, want within [%s, %s]",
						tc.consecutive, got, tc.wantMin, tc.wantMax)
				}
			}
		})
	}
	t.Run("jitter never exceeds the cap", func(t *testing.T) {
		for i := 1; i <= 30; i++ {
			if got := BackoffFor(interval, i, max); got > max {
				t.Fatalf("BackoffFor(%d) = %s above cap", i, got)
			}
		}
	})
}

func TestParseIPLine(t *testing.T) {
	for _, tc := range []struct {
		body, want string
	}{
		{"loc=XX\nip=203.0.113.7\ntls=1.3\n", "203.0.113.7"},
		{"ip=2001:db8::1\n", "2001:db8::1"},
		{"  ip=198.51.100.4  \n", "198.51.100.4"},
		{"no ip here\nloc=ZZ\n", ""},
		{"", ""},
	} {
		if got := parseIPLine(tc.body); got != tc.want {
			t.Fatalf("parseIPLine(%q) = %q, want %q", tc.body, got, tc.want)
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Duration
	}{
		{"30", 30 * time.Second},
		{" 5 ", 5 * time.Second},
		{"0", 0},
		{"-3", 0},
		{"Wed, 21 Oct 2026 07:28:00 GMT", 0},
		{"", 0},
	} {
		if got := parseRetryAfter(tc.in); got != tc.want {
			t.Fatalf("parseRetryAfter(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

// apiServer records concurrent calls; its behavior is switched per test.
type apiServer struct {
	srv      *httptest.Server
	calls    atomic.Int64
	maxFast  atomic.Int64 // max simultaneously in-flight calls
	inFlight atomic.Int64
	status   atomic.Int64 // 0 means 200
}

func newAPIServer(t *testing.T) *apiServer {
	t.Helper()
	a := &apiServer{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		a.calls.Add(1)
		cur := a.inFlight.Add(1)
		defer a.inFlight.Add(-1)
		for {
			max := a.maxFast.Load()
			if cur <= max || a.maxFast.CompareAndSwap(max, cur) {
				break
			}
		}
		if st := a.status.Load(); st != 0 {
			w.WriteHeader(int(st))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func apiSpec(api *apiServer) config.RotateAPI {
	return config.RotateAPI{
		URL:     mustURLStatic(api.srv.URL),
		Method:  http.MethodPost,
		Headers: map[string]string{"X-Api-Token": "rot-token-TEST"},
		Body:    `{"proxy_id": 7}`,
		Timeout: 2 * time.Second,
	}
}

func mustURLStatic(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

func TestCallRotateAPIClassifiesResponses(t *testing.T) {
	setup := func(t *testing.T) (*apiServer, config.RotateAPI) {
		a := newAPIServer(t)
		return a, apiSpec(a)
	}

	t.Run("200 succeeds", func(t *testing.T) {
		a, api := setup(t)
		if _, err := New(nil, discardLogger()).callRotateAPI(context.Background(), api); err != nil {
			t.Fatalf("callRotateAPI: %v", err)
		}
		if a.calls.Load() != 1 {
			t.Fatalf("calls = %d, want 1", a.calls.Load())
		}
	})
	t.Run("500 fails without retry", func(t *testing.T) {
		a, api := setup(t)
		a.status.Store(500)
		_, err := New(nil, discardLogger()).callRotateAPI(context.Background(), api)
		if err == nil || !strings.Contains(err.Error(), "status 500") {
			t.Fatalf("err = %v, want status 500", err)
		}
		if a.calls.Load() != 1 {
			t.Fatalf("calls = %d, want 1", a.calls.Load())
		}
	})
	t.Run("429 surfaces retry hint", func(t *testing.T) {
		a, api := setup(t)
		a.status.Store(429)
		a.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "12")
			w.WriteHeader(http.StatusTooManyRequests)
		})
		hint, err := New(nil, discardLogger()).callRotateAPI(context.Background(), api)
		if err == nil {
			t.Fatal("want error for 429")
		}
		if hint != 12*time.Second {
			t.Fatalf("retry hint = %s, want 12s", hint)
		}
	})
	t.Run("transport error hides the URL", func(t *testing.T) {
		a, api := setup(t)
		api.URL = mustURLStatic(a.srv.URL + "?token=rot-token-TEST")
		api.Timeout = 50 * time.Millisecond
		a.srv.Close() // force a transport failure
		_, err := New(nil, discardLogger()).callRotateAPI(context.Background(), api)
		if err == nil {
			t.Fatal("want transport error")
		}
		if strings.Contains(err.Error(), "rot-token-TEST") || strings.Contains(err.Error(), a.srv.URL) {
			t.Fatalf("error leaked the API URL or token: %v", err)
		}
	})
	t.Run("redirects are never followed", func(t *testing.T) {
		a, api := setup(t)
		var targetHits atomic.Int64
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			targetHits.Add(1)
		}))
		defer target.Close()
		a.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", target.URL)
			w.WriteHeader(http.StatusFound)
		})
		_, err := New(nil, discardLogger()).callRotateAPI(context.Background(), api)
		if err == nil || !strings.Contains(err.Error(), "status 302") {
			t.Fatalf("err = %v, want status 302", err)
		}
		if targetHits.Load() != 0 {
			t.Fatalf("redirect target was contacted %d times", targetHits.Load())
		}
	})
}

func TestProbeIPParsesTrace(t *testing.T) {
	ips := newIPServer(t, "203.0.113.7")
	cfg := &config.RuntimeConfig{Rotation: fastSettings()}
	pl := testPool(t, cfg)
	store := pool.NewStore(cfg, pl)
	e := testEngine(t, ips, store, nil)
	spec := manualRoute(t, "m1.test", time.Minute, apiSpec(newAPIServer(t)))

	ip, err := e.probeIP(context.Background(), pool.NewGeneration(cfg, pl), spec, time.Second)
	if err != nil {
		t.Fatalf("probeIP: %v", err)
	}
	if ip != "203.0.113.7" {
		t.Fatalf("probeIP = %q, want 203.0.113.7", ip)
	}
}

func TestProcedureSuccessRecordsNewIP(t *testing.T) {
	ips := newIPServer(t, "203.0.113.7")
	api := newAPIServer(t)
	spec := manualRoute(t, "m1.test", 90*time.Second, apiSpec(api))
	cfg := &config.RuntimeConfig{Rotation: fastSettings(), ManualRoutes: []config.ManualRouteSpec{spec}}
	s := newSetup(t, cfg, nil, ips)

	api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ips.set("198.51.100.9") // the provider rotates on the API call
		w.WriteHeader(http.StatusOK)
	})

	s.runOne(spec)

	if got := s.e.Rotations(); got != 1 {
		t.Fatalf("Rotations = %d, want 1", got)
	}
	st := snapshotHost(t, s.pl, "m1.test")
	if !st.Available || st.Rotation.State != "idle" || st.Rotation.LastIP != "198.51.100.9" ||
		st.Rotation.LastRotationAt == "" || st.Rotation.ConsecutiveSameIP != 0 {
		t.Fatalf("post-rotation status = %+v", st.Rotation)
	}
}

func TestProcedureSameIPGoesStaleThenRecovers(t *testing.T) {
	ips := newIPServer(t, "203.0.113.7")
	api := newAPIServer(t)
	spec := manualRoute(t, "m1.test", time.Second, apiSpec(api)) // 1s backoff keeps the test quick
	cfg := &config.RuntimeConfig{Rotation: fastSettings(), ManualRoutes: []config.ManualRouteSpec{spec}}
	s := newSetup(t, cfg, nil, ips)

	// The API answers 200 but the provider hands back the same IP.
	s.runOne(spec)

	if got := s.e.Rotations(); got != 0 {
		t.Fatalf("Rotations = %d, want 0", got)
	}
	st := snapshotHost(t, s.pl, "m1.test")
	if !st.Available || st.Rotation.State != "stale" || st.Rotation.ConsecutiveSameIP != 1 ||
		st.Rotation.NextRetryIn == "" || st.Rotation.LastIP != "" {
		t.Fatalf("same-IP status = %+v", st.Rotation)
	}
	s.e.mu.Lock()
	due := s.e.due[routeID(spec.RouteSpec)]
	s.e.mu.Unlock()
	if wait := time.Until(due); wait < 800*time.Millisecond || wait > 1100*time.Millisecond {
		t.Fatalf("retry scheduled in %s, want ~1s (one interval, jittered)", wait)
	}

	// The provider eventually yields a new IP; the next attempt recovers and
	// clears the stale mark. The flip happens on the rotate API call, so the
	// baseline still sees the old address.
	api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ips.set("198.51.100.9")
		w.WriteHeader(http.StatusOK)
	})
	s.runOne(spec)
	if got := s.e.Rotations(); got != 1 {
		t.Fatalf("Rotations after recovery = %d, want 1", got)
	}
	st = snapshotHost(t, s.pl, "m1.test")
	if st.Rotation.State != "idle" || st.Rotation.ConsecutiveSameIP != 0 || st.Rotation.LastIP != "198.51.100.9" {
		t.Fatalf("recovered status = %+v", st.Rotation)
	}
}

func TestProcedureDeadRouteRotatesUnverified(t *testing.T) {
	ips := newIPServer(t, "198.51.100.9")
	api := newAPIServer(t)
	spec := manualRoute(t, "m1.test", time.Minute, apiSpec(api))
	cfg := &config.RuntimeConfig{Rotation: fastSettings(), ManualRoutes: []config.ManualRouteSpec{spec}}
	s := newSetup(t, cfg, nil, ips)

	// The first three route dials fail (dead route during baseline probing);
	// after the API call the route is reachable again and the first
	// non-colliding IP counts as the new one.
	var dials atomic.Int64
	s.e.dial = func(ctx context.Context, pu *url.URL, target string, timeout time.Duration) (net.Conn, error) {
		if dials.Add(1) <= 3 {
			return nil, errors.New("route endpoint unreachable (TEST)")
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ips.srv.Listener.Addr().String())
	}

	s.runOne(spec)

	if got := s.e.Rotations(); got != 1 {
		t.Fatalf("Rotations = %d, want 1 (unverified success)", got)
	}
	st := snapshotHost(t, s.pl, "m1.test")
	if st.Rotation.State != "idle" || st.Rotation.LastIP != "198.51.100.9" {
		t.Fatalf("unverified status = %+v", st.Rotation)
	}
}

func TestProcedureAPIFailureStillChecksForARotation(t *testing.T) {
	ips := newIPServer(t, "203.0.113.7")
	api := newAPIServer(t)
	api.status.Store(500)
	spec := manualRoute(t, "m1.test", time.Minute, apiSpec(api))
	cfg := &config.RuntimeConfig{Rotation: fastSettings(), ManualRoutes: []config.ManualRouteSpec{spec}}
	s := newSetup(t, cfg, nil, ips)

	t.Run("IP unchanged ends in stale", func(t *testing.T) {
		s.runOne(spec)
		st := snapshotHost(t, s.pl, "m1.test")
		if st.Rotation.State != "stale" || s.e.Rotations() != 0 {
			t.Fatalf("failed API with same IP: %+v rotations=%d", st.Rotation, s.e.Rotations())
		}
	})
	t.Run("IP changed despite 500 counts", func(t *testing.T) {
		// The provider rotated even though the call errored; the single
		// post-failure probe must still catch the change.
		api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			ips.set("198.51.100.9")
			w.WriteHeader(http.StatusInternalServerError)
		})
		s.runOne(spec)
		if got := s.e.Rotations(); got != 1 {
			t.Fatalf("Rotations = %d, want 1", got)
		}
	})
}

func TestProcedureRejectsCrossRouteCollision(t *testing.T) {
	ips := newIPServer(t, "203.0.113.7")
	api := newAPIServer(t)
	spec := manualRoute(t, "m2.test", time.Minute, apiSpec(api))
	other := manualRoute(t, "m1.test", time.Minute, apiSpec(api))
	cfg := &config.RuntimeConfig{Rotation: fastSettings(), ManualRoutes: []config.ManualRouteSpec{other, spec}}
	s := newSetup(t, cfg, nil, ips)

	// The "new" IP is m1's current address: rotating into a collision does not
	// count, and the window ends in stale.
	if p := s.pl.Lookup(routeID(other.RouteSpec)); p == nil {
		t.Fatal("m1 missing")
	} else {
		p.SetBaselineIP("198.51.100.9")
	}
	api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ips.set("198.51.100.9")
		w.WriteHeader(http.StatusOK)
	})

	s.runOne(spec)

	if got := s.e.Rotations(); got != 0 {
		t.Fatalf("Rotations = %d, want 0 (collision)", got)
	}
	st := snapshotHost(t, s.pl, "m2.test")
	if st.Rotation.State != "stale" {
		t.Fatalf("collision status = %+v", st.Rotation)
	}
}

func TestProcedureDrainForcesAfterTimeout(t *testing.T) {
	ips := newIPServer(t, "203.0.113.7")
	api := newAPIServer(t)
	spec := manualRoute(t, "m1.test", time.Minute, apiSpec(api))
	cfg := &config.RuntimeConfig{Rotation: fastSettings(), ManualRoutes: []config.ManualRouteSpec{spec}}
	cfg.Rotation.DrainTimeout = 300 * time.Millisecond
	s := newSetup(t, cfg, nil, ips)
	api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ips.set("198.51.100.9")
		w.WriteHeader(http.StatusOK)
	})

	held := s.pl.PickFor(nil, nil) // one in-flight request that never finishes
	start := time.Now()
	s.runOne(spec)
	elapsed := time.Since(start)
	if elapsed < 250*time.Millisecond {
		t.Fatalf("procedure returned in %s, want at least the drain timeout", elapsed)
	}
	if got := s.e.Rotations(); got != 1 {
		t.Fatalf("Rotations = %d, want 1 (force-rotated)", got)
	}
	held.Release()
}

func TestProcedureAbortsOnShutdown(t *testing.T) {
	ips := newIPServer(t, "203.0.113.7")
	api := newAPIServer(t)
	spec := manualRoute(t, "m1.test", time.Minute, apiSpec(api))
	cfg := &config.RuntimeConfig{Rotation: fastSettings(), ManualRoutes: []config.ManualRouteSpec{spec}}
	cfg.Rotation.DrainTimeout = 30 * time.Second
	s := newSetup(t, cfg, nil, ips)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	held := s.pl.PickFor(nil, nil) // drain would wait for the full timeout
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.e.runProcedure(ctx, s.gen, spec, s.pl.Lookup(routeID(spec.RouteSpec)), routeID(spec.RouteSpec))
	}()
	time.Sleep(150 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("procedure ignored cancellation")
	}
	st := snapshotHost(t, s.pl, "m1.test")
	if st.Rotation.State != "idle" || api.calls.Load() != 0 {
		t.Fatalf("aborted procedure state = %+v api calls = %d", st.Rotation, api.calls.Load())
	}
	held.Release()
}

func TestProcedureAbortsForRemovedRoute(t *testing.T) {
	ips := newIPServer(t, "203.0.113.7")
	api := newAPIServer(t)
	spec := manualRoute(t, "m1.test", time.Minute, apiSpec(api))
	cfg := &config.RuntimeConfig{Rotation: fastSettings(), ManualRoutes: []config.ManualRouteSpec{spec}}
	s := newSetup(t, cfg, nil, ips)

	// The generation's pool no longer contains the route (removed by a
	// reload): the procedure must return without touching anything.
	emptyGen := pool.NewGeneration(cfg, pool.NewRoutes(nil, 30*time.Second, time.Minute))
	s.e.runProcedure(context.Background(), emptyGen, spec, nil, routeID(spec.RouteSpec))
	if api.calls.Load() != 0 {
		t.Fatalf("removed route still called the API %d times", api.calls.Load())
	}
}

// TestSchedulerAppliesConcurrencyCap runs the real loop with two routes and a
// unique-IP endpoint so both procedures succeed; the rotate API must never
// observe more than the cap procedures at once.
func TestSchedulerAppliesConcurrencyCap(t *testing.T) {
	ips := newIPServer(t, "")
	ips.unique.Store(true)

	for _, tc := range []struct {
		name       string
		cap        int
		wantAtOnce int64
	}{
		{"fixed 1 serializes", 1, 1},
		{"fixed 2 allows both", 2, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := newAPIServer(t)
			api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				time.Sleep(100 * time.Millisecond) // widen the overlap window
				w.WriteHeader(http.StatusOK)
			})
			settings := fastSettings()
			settings.MaxConcurrentFixed = ptrInt(tc.cap)
			settings.RotateOnStart = true
			cfg := &config.RuntimeConfig{
				Rotation: settings,
				ManualRoutes: []config.ManualRouteSpec{
					manualRoute(t, "m1.test", time.Hour, apiSpec(api)),
					manualRoute(t, "m2.test", time.Hour, apiSpec(api)),
				},
			}
			store := pool.NewStore(cfg, testPool(t, cfg))
			e := testEngine(t, ips, store, nil)

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer close(done)
				e.Run(ctx)
			}()
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("engine Run did not return after cancel")
				}
			}()

			deadline := time.Now().Add(8 * time.Second)
			for e.Rotations() < 2 && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			if e.Rotations() != 2 {
				t.Fatalf("Rotations = %d, want 2", e.Rotations())
			}
			if got := api.maxFast.Load(); got > tc.wantAtOnce {
				t.Fatalf("max concurrent API calls = %d, want <= %d", got, tc.wantAtOnce)
			}
		})
	}
}
