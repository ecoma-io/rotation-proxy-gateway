package proxyserver

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
)

// A target TLS handshake happens inside the SOCKS tunnel after the endpoint
// dial succeeded, so its failure is `setup`: one sanitized 502, no retry, and
// no route-health mutation. The first case exercises the secure default
// (target-tls-insecure: false) actually verifying certificates; the second
// proves the classification holds even with verification disabled.
func TestTargetTLSHandshakeFailureIsSetupNotHealthChange(t *testing.T) {
	cases := []struct {
		name     string
		target   func(*testing.T) string
		insecure bool
	}{
		{"secure default rejects unverifiable certificate", newSelfSignedTLSTarget, false},
		{"insecure verify still fails against a non-TLS target", newPlainTarget, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			targetURL := tc.target(t)
			fs := startSocks5Proxy(t, socksOptions{})
			pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute, config.KindBalance{})
			cfg := defaultRuntime()
			cfg.TargetTLSInsecure = tc.insecure
			s := newRuntimeServer(pl, cfg, testLogger())

			req := httptest.NewRequest(http.MethodGet, targetURL+"/", nil)
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, req)

			resp := rec.Result()
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusBadGateway || string(body) != "upstream SOCKS setup failed\n" {
				t.Fatalf("status=%d body=%q, want sanitized 502", resp.StatusCode, body)
			}
			if got := len(fs.hits); got != 1 {
				t.Fatalf("SOCKS attempts = %d, want 1 (no retry)", got)
			}
			snap := pl.Snapshot()[0]
			if snap.Successes != 0 || snap.Failures != 0 || snap.AuthFailures != 0 || !snap.Available {
				t.Fatalf("TLS handshake failure changed route health: %+v", snap)
			}
		})
	}
}

// Repeated absolute-form https requests through one Server reuse TLS sessions:
// without a shared ClientSessionCache every request paid a full handshake
// inside its freshly dialed tunnel. The target reports DidResume per request,
// so the first request must complete a full handshake and the second must
// resume from the cache. Insecure verification is used only to trust the
// httptest certificate; session resumption is independent of verification.
func TestTargetTLSSessionsResume(t *testing.T) {
	var resumed []bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		resumed = append(resumed, r.TLS != nil && r.TLS.DidResume)
	}))
	t.Cleanup(srv.Close)

	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute, config.KindBalance{})
	cfg := defaultRuntime()
	cfg.TargetTLSInsecure = true
	s := newRuntimeServer(pl, cfg, testLogger())

	for range 2 {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, srv.URL+"/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("request status = %d, want 200", rec.Code)
		}
	}
	if len(resumed) != 2 {
		t.Fatalf("target saw %d requests, want 2", len(resumed))
	}
	if resumed[0] {
		t.Fatal("first handshake resumed; expected a full handshake")
	}
	if !resumed[1] {
		t.Fatal("second handshake did not resume; session cache not effective")
	}
}

func newSelfSignedTLSTarget(t *testing.T) string {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("unverifiable target must never be reached")
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func newPlainTarget(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("plain target must never complete a TLS handshake")
	}))
	t.Cleanup(srv.Close)
	// The request scheme, not the listener, decides whether the gateway
	// attempts TLS inside the tunnel; point https:// at the plain listener.
	return "https://" + mustHost(t, srv.URL)
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}
