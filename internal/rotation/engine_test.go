package rotation

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/logging"
	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/socksdial"

	"github.com/rs/zerolog"
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
	hang    atomic.Int64 // handler delay, exercising probe timeouts
}

func newIPServer(t *testing.T, initial string) *ipServer {
	t.Helper()
	s := &ipServer{}
	s.static.Store(initial)
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if d := time.Duration(s.hang.Load()); d > 0 {
			time.Sleep(d)
		}
		if s.unique.Load() {
			n := int(s.counter.Add(1))
			_, _ = fmt.Fprintf(w, "loc=XX\nip=10.%d.%d.%d\n", (n>>16)&255, (n>>8)&255, n&255)
			return
		}
		_, _ = fmt.Fprintf(w, "loc=XX\nip=%s\ntls=1.3\n", s.static.Load())
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
	e.dial = func(ctx context.Context, pu *url.URL, target socksdial.Target, timeout time.Duration) (net.Conn, error) {
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

func discardLogger() zerolog.Logger {
	return logging.Nop()
}

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
		// Non-literal values must fail the probe, never become route state.
		{"ip=not-an-address\n", ""},
		{"ip=999.1.1.1\n", ""},
		{"ip=provider.example\n", ""},
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
	srv               *httptest.Server
	calls             atomic.Int64
	maxFast           atomic.Int64 // max simultaneously in-flight calls
	inFlight          atomic.Int64
	status            atomic.Int64 // 0 means 200
	retryAfterSeconds atomic.Int64 // sent as Retry-After when status is set
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
			if ra := a.retryAfterSeconds.Load(); ra > 0 {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", ra))
			}
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

	t.Run("transport dials direct, never the ambient proxy", func(t *testing.T) {
		// The rotate API's headers and body are credentials: they must never
		// reach an ambient HTTP(S)_PROXY. A nil Proxy func on a Transport
		// means no proxy; the danger is the Client falling back to
		// http.DefaultTransport (ProxyFromEnvironment) when Transport is
		// unset. Loopback targets are exempt from proxying in net/http, so
		// asserting the wiring is the only hermetic check here.
		if rotateAPITransport.Proxy != nil {
			t.Fatal("rotateAPITransport.Proxy set; want the nil func = no proxy, ever")
		}
		if got := rotateClient(config.RotateAPI{Timeout: time.Second}).Transport; got != http.RoundTripper(rotateAPITransport) {
			t.Fatalf("rotate client transport = %v, want rotateAPITransport", got)
		}
		if got := rotateAPITransport.TLSClientConfig.MinVersion; got != tls.VersionTLS12 {
			t.Fatalf("rotate TLS MinVersion = %v, want TLS 1.2", got)
		}
	})
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

func TestProbeIPTimeoutBoundsConn(t *testing.T) {
	ips := newIPServer(t, "203.0.113.7")
	ips.hang.Store(int64(2 * time.Second)) // the answer would arrive, but late
	cfg := &config.RuntimeConfig{Rotation: fastSettings()}
	pl := testPool(t, cfg)
	store := pool.NewStore(cfg, pl)
	e := testEngine(t, ips, store, nil)
	spec := manualRoute(t, "m1.test", time.Minute, apiSpec(newAPIServer(t)))
	gen := pool.NewGeneration(cfg, pl)

	// The caller's context outlives the probe budget: the connection must
	// still be bounded by the timeout parameter, not the context deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := e.probeIP(ctx, gen, spec, 300*time.Millisecond); err == nil {
		t.Fatal("probeIP succeeded past its timeout")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("probeIP returned after %s, want bounded by the 300ms timeout", elapsed)
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

// A provider Retry-After hint extends the same-IP backoff when it sits under
// rotation.retry-backoff-max, but is clamped to that ceiling: an unbounded
// hint must not let one response silence a route's rotation retries for days.
func TestProcedureRetryAfterClampedToBackoffMax(t *testing.T) {
	ips := newIPServer(t, "203.0.113.7")
	api := newAPIServer(t)
	api.status.Store(http.StatusTooManyRequests)
	spec := manualRoute(t, "m1.test", time.Second, apiSpec(api))
	cfg := &config.RuntimeConfig{Rotation: fastSettings(), ManualRoutes: []config.ManualRouteSpec{spec}}
	s := newSetup(t, cfg, nil, ips)

	scheduledIn := func() time.Duration {
		t.Helper()
		s.e.mu.Lock()
		due := s.e.due[routeID(spec.RouteSpec)]
		s.e.mu.Unlock()
		return time.Until(due)
	}

	t.Run("hint under the ceiling is honored", func(t *testing.T) {
		api.retryAfterSeconds.Store(30)
		s.runOne(spec)
		if got := s.e.Rotations(); got != 0 {
			t.Fatalf("Rotations = %d, want 0", got)
		}
		if wait := scheduledIn(); wait < 25*time.Second || wait > 35*time.Second {
			t.Fatalf("retry scheduled in %s, want the 30s hint", wait)
		}
	})

	t.Run("hint above the ceiling is clamped", func(t *testing.T) {
		api.retryAfterSeconds.Store(172800) // 48h, far past any sane wait
		s.runOne(spec)
		if wait := scheduledIn(); wait < 55*time.Second || wait > 61*time.Second {
			t.Fatalf("retry scheduled in %s, want the 1m configured ceiling, not the 48h hint", wait)
		}
	})
}

// An unverified rotation must not count the route's own current address as a
// changed IP: with the baseline unknown, a provider that hands back the
// address the route already serves is declining to rotate, and counting it
// would inflate the rotations metric.
func TestProcedureUnverifiedDoesNotCountCurrentIP(t *testing.T) {
	ips := newIPServer(t, "203.0.113.7")
	api := newAPIServer(t)
	spec := manualRoute(t, "m1.test", time.Minute, apiSpec(api))
	cfg := &config.RuntimeConfig{Rotation: fastSettings(), ManualRoutes: []config.ManualRouteSpec{spec}}
	s := newSetup(t, cfg, nil, ips)

	// First procedure: the provider rotates on the API call, and the new
	// address 198.51.100.9 is verified.
	api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ips.set("198.51.100.9")
		w.WriteHeader(http.StatusOK)
	})
	s.runOne(spec)
	if got := s.e.Rotations(); got != 1 {
		t.Fatalf("Rotations after first procedure = %d, want 1", got)
	}
	if st := snapshotHost(t, s.pl, "m1.test"); st.Rotation.LastIP != "198.51.100.9" {
		t.Fatalf("first procedure LastIP = %q, want 198.51.100.9", st.Rotation.LastIP)
	}

	// Second procedure: the baseline probes fail (route dead), the API call
	// succeeds, and the route serves the SAME address it already had. No
	// baseline exists, but the outcome is still not a rotation.
	var dials atomic.Int64
	s.e.dial = func(ctx context.Context, pu *url.URL, target socksdial.Target, timeout time.Duration) (net.Conn, error) {
		if dials.Add(1) <= 3 {
			return nil, errors.New("route endpoint unreachable (TEST)")
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ips.srv.Listener.Addr().String())
	}
	s.runOne(spec)

	if got := s.e.Rotations(); got != 1 {
		t.Fatalf("Rotations = %d, want the same-IP answer not counted", got)
	}
	st := snapshotHost(t, s.pl, "m1.test")
	if st.Rotation.State != "stale" || st.Rotation.ConsecutiveSameIP != 1 || st.Rotation.LastIP != "198.51.100.9" {
		t.Fatalf("unverified same-IP status = %+v", st.Rotation)
	}
}

// The probe budget is measured from the moment the probe starts, not from
// whenever its dial finishes: a slow dial eats into the caller's window
// instead of extending the attempt past it.
func TestProbeIPBudgetMeasuredFromEntry(t *testing.T) {
	ips := newIPServer(t, "203.0.113.7")
	cfg := &config.RuntimeConfig{Rotation: fastSettings()}
	s := newSetup(t, cfg, nil, ips)

	const timeout = 300 * time.Millisecond
	deadlineSeen := make(chan time.Time, 1)
	start := time.Now()
	s.e.dial = func(ctx context.Context, _ *url.URL, _ socksdial.Target, _ time.Duration) (net.Conn, error) {
		time.Sleep(200 * time.Millisecond) // the slow dial under test
		conn, err := net.Dial("tcp", ips.srv.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return &deadlineRecorder{Conn: conn, seen: deadlineSeen}, nil
	}
	spec := manualRoute(t, "m1.test", time.Minute, config.RotateAPI{})
	ip, err := s.e.probeIP(context.Background(), s.gen, spec, timeout)
	if err != nil {
		t.Fatalf("probeIP: %v", err)
	}
	if ip != "203.0.113.7" {
		t.Fatalf("ip = %q, want the served address", ip)
	}
	select {
	case dl := <-deadlineSeen:
		if budget := dl.Sub(start); budget <= 0 || budget > timeout+50*time.Millisecond {
			t.Fatalf("conn deadline %s after probe start, want the %s budget measured from entry", budget, timeout)
		}
	case <-time.After(time.Second):
		t.Fatal("probe never armed a conn deadline")
	}
}

// deadlineRecorder captures the deadline the probe arms on the connection.
type deadlineRecorder struct {
	net.Conn
	seen chan<- time.Time
}

func (d *deadlineRecorder) SetDeadline(t time.Time) error {
	select {
	case d.seen <- t:
	default:
	}
	return d.Conn.SetDeadline(t)
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
	s.e.dial = func(ctx context.Context, pu *url.URL, target socksdial.Target, timeout time.Duration) (net.Conn, error) {
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

	held := s.pl.PickFor(nil, nil, "t:443") // one in-flight request that never finishes
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
	held := s.pl.PickFor(nil, nil, "t:443") // drain would wait for the full timeout
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

// TestProcedureAbortsMidFlightWhenReloadRemovesRoute parks a procedure inside
// its drain, publishes a reload that removes the route, and releases the
// drain. The abandoned procedure must stop at its next checkpoint: the
// provider rotate API is never called and no outcome is recorded.
func TestProcedureAbortsMidFlightWhenReloadRemovesRoute(t *testing.T) {
	ips := newIPServer(t, "203.0.113.7")
	api := newAPIServer(t)
	api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ips.set("198.51.100.9") // a completed rotation would be observable
		w.WriteHeader(http.StatusOK)
	})
	spec := manualRoute(t, "m1.test", time.Minute, apiSpec(api))
	cfg := &config.RuntimeConfig{Rotation: fastSettings(), ManualRoutes: []config.ManualRouteSpec{spec}}
	s := newSetup(t, cfg, nil, ips)

	held := s.pl.PickFor(nil, nil, "t:443") // park the procedure in the drain loop
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.e.runProcedure(context.Background(), s.gen, spec,
			s.pl.Lookup(routeID(spec.RouteSpec)), routeID(spec.RouteSpec))
	}()
	waitRotationState(t, s.pl, "m1.test", "draining")

	// A reload publishes a generation whose pool no longer contains the
	// route. The procedure still holds the pre-reload generation, so its own
	// removal check must consult the store's current pool.
	empty := &config.RuntimeConfig{Rotation: fastSettings()}
	s.e.store.Publish(empty)
	held.Release()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("procedure kept running after the route was removed")
	}
	if calls := api.calls.Load(); calls != 0 {
		t.Fatalf("removed route's procedure called the rotate API %d times", calls)
	}
	if got := s.e.Rotations(); got != 0 {
		t.Fatalf("Rotations = %d, want 0 for an abandoned procedure", got)
	}
	st := snapshotHost(t, s.pl, "m1.test")
	if st.Rotation.State != "idle" || st.Rotation.LastIP != "" {
		t.Fatalf("abandoned procedure recorded an outcome: %+v", st.Rotation)
	}
}

func waitRotationState(t *testing.T, pl *pool.Pool, host, state string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for snapshotHost(t, pl, host).Rotation.State != state {
		if time.Now().After(deadline) {
			t.Fatalf("route %q never reached rotation state %q", host, state)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// finishProcedure must not unregister a replacement procedure: after a
// remove→re-add reload the same route id can have a stale procedure still
// running while a fresh one is admitted, and a stale finish that deleted by
// id alone would free the concurrency slot of the live replacement.
func TestStaleProcedureFinishKeepsReplacementRegistered(t *testing.T) {
	e := New(nil, discardLogger())
	spec := manualRoute(t, "m1.test", time.Minute, config.RotateAPI{})
	id := routeID(spec.RouteSpec)
	stale := testPool(t, &config.RuntimeConfig{ManualRoutes: []config.ManualRouteSpec{spec}}).Lookup(id)
	replacement := testPool(t, &config.RuntimeConfig{ManualRoutes: []config.ManualRouteSpec{spec}}).Lookup(id)
	if stale == nil || replacement == nil || stale == replacement {
		t.Fatal("need two distinct proxy instances sharing one route id")
	}

	e.mu.Lock()
	e.active[id] = stale
	e.mu.Unlock()
	// The reload swap: the replacement is admitted under the same id before
	// the stale procedure reaches its finish.
	e.mu.Lock()
	e.active[id] = replacement
	e.mu.Unlock()

	e.finishProcedure(id, stale)
	e.mu.Lock()
	got := e.active[id]
	e.mu.Unlock()
	if got != replacement {
		t.Fatalf("active slot = %v, want the replacement to stay registered", got)
	}

	// The replacement's own finish does release the slot.
	e.finishProcedure(id, replacement)
	e.mu.Lock()
	_, ok := e.active[id]
	e.mu.Unlock()
	if ok {
		t.Fatal("replacement finish left the slot occupied")
	}
}

// A stale procedure finishing during a remove→re-add overlap must leave the
// replacement's active slot alone, so the scheduler cannot admit a duplicate
// procedure for the same route while the replacement still runs.
func TestReloadRemoveReaddOverlapKeepsCapHonest(t *testing.T) {
	ips := newIPServer(t, "203.0.113.7")
	api := newAPIServer(t)
	spec := manualRoute(t, "m1.test", time.Minute, apiSpec(api))
	cfg := &config.RuntimeConfig{Rotation: fastSettings(), ManualRoutes: []config.ManualRouteSpec{spec}}
	s := newSetup(t, cfg, nil, ips)

	// Park every rotate call on a channel; each token releases exactly one
	// parked call in the order it arrived. Cleanup drains tokens so no parked
	// procedure outlives the test.
	release := make(chan struct{}, 8)
	t.Cleanup(func() {
		for range 8 {
			select {
			case release <- struct{}{}:
			default:
			}
		}
	})
	var entries, inFlight, peak atomic.Int64
	api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entries.Add(1)
		cur := inFlight.Add(1)
		for {
			old := peak.Load()
			if cur <= old || peak.CompareAndSwap(old, cur) {
				break
			}
		}
		<-release
		inFlight.Add(-1)
		w.WriteHeader(http.StatusOK)
	})

	// Procedure #1 parks inside its rotate call.
	id := routeID(spec.RouteSpec)
	done1 := make(chan struct{})
	go func() {
		defer close(done1)
		s.e.runProcedure(context.Background(), s.gen, spec,
			s.pl.Lookup(id), id)
	}()
	waitUntil(t, "procedure #1 parked in the rotate call", func() bool { return inFlight.Load() == 1 })

	// Reload: remove the route. The scheduler sweep stops counting the
	// still-running procedure (by design, so its slot is reused), then the
	// same route identity is re-added as fresh state and admitted again.
	s.e.store.Publish(&config.RuntimeConfig{Rotation: fastSettings()})
	s.e.evaluate(context.Background())
	s.e.store.Publish(cfg)
	s.e.evaluate(context.Background())
	s.e.mu.Lock()
	replacement := s.e.active[id]
	s.e.mu.Unlock()
	if replacement == nil {
		t.Fatal("evaluate did not admit a replacement after the re-add")
	}
	waitUntil(t, "procedure #2 parked in the rotate call", func() bool { return inFlight.Load() == 2 })

	// The provider moves the IP, so the released stale procedure's verify
	// succeeds immediately and it reaches the gone() checkpoint without
	// waiting out the IP-check window.
	ips.set("198.51.100.9")
	release <- struct{}{}
	<-done1

	// The stale procedure is gone; the replacement is still parked in its
	// own rotate call. A scheduler pass must still see the slot occupied —
	// exactly two admissions, never a third.
	s.e.evaluate(context.Background())
	s.e.mu.Lock()
	still := s.e.active[id]
	s.e.mu.Unlock()
	if still != replacement {
		t.Fatalf("active slot = %v, want the replacement held across the stale finish", still)
	}
	if got := entries.Load(); got != 2 {
		t.Fatalf("rotate API admissions = %d, want exactly 2", got)
	}

	// Let the replacement finish its rotation for real.
	release <- struct{}{}
	waitUntil(t, "replacement procedure to finish", func() bool {
		s.e.mu.Lock()
		defer s.e.mu.Unlock()
		return s.e.active[id] == nil
	})
	if got := entries.Load(); got != 2 {
		t.Fatalf("rotate API admissions after completion = %d, want exactly 2", got)
	}
	if got := peak.Load(); got != 2 {
		t.Fatalf("peak in-flight rotate calls = %d, want 2 (stale sweep + replacement)", got)
	}
	if got := s.e.Rotations(); got != 1 {
		t.Fatalf("Rotations = %d, want 1 from the replacement", got)
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestBootPrecheckRecordsBaselines drives the boot-time double probe: it must
// learn each manual route's starting egress IP, keep the second observation
// when the provider moves the IP between probes, and leave routes it could
// not probe unverified.
func TestBootPrecheckRecordsBaselines(t *testing.T) {
	newOne := func(t *testing.T, ips *ipServer, routeFail *atomic.Bool) (*setup, config.ManualRouteSpec) {
		spec := manualRoute(t, "m1.test", time.Minute, apiSpec(newAPIServer(t)))
		cfg := &config.RuntimeConfig{Rotation: fastSettings(), ManualRoutes: []config.ManualRouteSpec{spec}}
		return newSetup(t, cfg, routeFail, ips), spec
	}

	t.Run("sticky IP becomes the baseline", func(t *testing.T) {
		s, _ := newOne(t, newIPServer(t, "203.0.113.7"), nil)
		s.e.bootPrecheck(context.Background(), s.gen)
		if st := snapshotHost(t, s.pl, "m1.test"); st.Rotation.LastIP != "203.0.113.7" {
			t.Fatalf("baseline = %+v, want 203.0.113.7", st.Rotation)
		}
	})
	t.Run("moved IP records the second probe", func(t *testing.T) {
		ips := newIPServer(t, "203.0.113.7")
		s, _ := newOne(t, ips, nil)
		base := s.e.dial
		var dials atomic.Int64
		s.e.dial = func(ctx context.Context, pu *url.URL, target socksdial.Target, timeout time.Duration) (net.Conn, error) {
			if dials.Add(1) == 2 {
				ips.set("198.51.100.9") // the provider moved it between probes
			}
			return base(ctx, pu, target, timeout)
		}
		s.e.bootPrecheck(context.Background(), s.gen)
		if st := snapshotHost(t, s.pl, "m1.test"); st.Rotation.LastIP != "198.51.100.9" {
			t.Fatalf("baseline = %+v, want the second observation 198.51.100.9", st.Rotation)
		}
	})
	t.Run("failed probes leave the route unverified", func(t *testing.T) {
		routeFail := new(atomic.Bool)
		routeFail.Store(true)
		s, _ := newOne(t, newIPServer(t, "203.0.113.7"), routeFail)
		s.e.bootPrecheck(context.Background(), s.gen)
		if st := snapshotHost(t, s.pl, "m1.test"); st.Rotation.LastIP != "" {
			t.Fatalf("baseline = %+v, want none after failed probes", st.Rotation)
		}
	})
	t.Run("route removed by a reload is skipped", func(t *testing.T) {
		s, _ := newOne(t, newIPServer(t, "203.0.113.7"), nil)
		s.e.store.Publish(&config.RuntimeConfig{Rotation: fastSettings()})
		s.e.bootPrecheck(context.Background(), s.gen)
		if st := snapshotHost(t, s.pl, "m1.test"); st.Rotation.LastIP != "" {
			t.Fatalf("removed route learned a baseline: %+v", st.Rotation)
		}
	})
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

// TestRunCancelAbandonsActiveProcedure parks a procedure inside the rotate
// API call and cancels the engine context: Run must return promptly and the
// route must be returned to serving without a recorded outcome.
func TestRunCancelAbandonsActiveProcedure(t *testing.T) {
	ips := newIPServer(t, "203.0.113.7")
	api := newAPIServer(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	handlerDone := make(chan struct{})
	api.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		close(handlerDone)
		w.WriteHeader(http.StatusOK)
	})
	settings := fastSettings()
	settings.RotateOnStart = true
	spec := manualRoute(t, "m1.test", time.Hour, apiSpec(api))
	cfg := &config.RuntimeConfig{Rotation: settings, ManualRoutes: []config.ManualRouteSpec{spec}}
	s := newSetup(t, cfg, nil, ips)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.e.Run(ctx)
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("procedure never reached the rotate API call")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}

	if got := s.e.Rotations(); got != 0 {
		t.Fatalf("Rotations = %d, want 0 for an abandoned procedure", got)
	}
	waitRotationState(t, s.pl, "m1.test", "idle")
	st := snapshotHost(t, s.pl, "m1.test")
	if st.Rotation.LastIP != "" {
		t.Fatalf("canceled procedure recorded an outcome: %+v", st.Rotation)
	}

	close(release) // let the parked handler goroutine exit
	select {
	case <-handlerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("rotate API handler never finished")
	}
}

// logBuf is a mutex-guarded capture buffer for engine log records.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *logBuf) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *logBuf) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

// logRecords decodes the captured JSON lines; undecodable lines are skipped.
func logRecords(output string) []map[string]any {
	var recs []map[string]any
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		recs = append(recs, rec)
	}
	return recs
}

func findLogRecord(recs []map[string]any, want map[string]string) map[string]any {
	for _, rec := range recs {
		ok := true
		for k, v := range want {
			if fmt.Sprint(rec[k]) != v {
				ok = false
				break
			}
		}
		if ok {
			return rec
		}
	}
	return nil
}

// A completed procedure must leave a phase trail: entering rotating and
// verifying records how long the previous phase took and how far the
// procedure is from its start, so a slow rotation is attributable to a phase
// without cross-referencing timestamps.
func TestProcedureLogsPhaseTransitions(t *testing.T) {
	ips := newIPServer(t, "203.0.113.7")
	ips.unique.Store(true) // every probe observes a fresh IP, so verify succeeds
	api := newAPIServer(t)
	spec := manualRoute(t, "m1.test", 90*time.Second, apiSpec(api))
	cfg := &config.RuntimeConfig{Rotation: fastSettings(), ManualRoutes: []config.ManualRouteSpec{spec}}
	s := newSetup(t, cfg, nil, ips)
	var buf logBuf
	s.e.log = logging.New(&buf)

	s.runOne(cfg.ManualRoutes[0])

	recs := logRecords(buf.String())
	for _, phase := range []string{"rotating", "verifying"} {
		rec := findLogRecord(recs, map[string]string{"msg": "rotation phase entered", "phase": phase})
		if rec == nil {
			t.Fatalf("no phase-entered record for %q:\n%s", phase, buf.String())
		}
		for _, key := range []string{"previous", "in_previous", "since_start"} {
			if _, has := rec[key]; !has {
				t.Errorf("phase %q record missing %q: %v", phase, key, rec)
			}
		}
	}
	if rec := findLogRecord(recs, map[string]string{"msg": "rotation complete"}); rec == nil {
		t.Errorf("no completion record:\n%s", buf.String())
	}
}
