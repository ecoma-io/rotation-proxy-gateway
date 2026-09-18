package proxyserver

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

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
			pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute)
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
