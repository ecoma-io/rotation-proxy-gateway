package proxyserver

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"rotation-proxy-gateway/internal/pool"
)

func mustTargetURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

// targetAddress resolves the SOCKS CONNECT target: explicit ports win, the
// http/https defaults apply only when absent, and anything scheme-less or
// host-less is a local setup error that must never touch pool health.
func TestTargetAddressResolution(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"explicit port wins", "http://example.com:8080/", "example.com:8080"},
		{"non-http scheme with explicit port", "ftp://example.com:21/", "example.com:21"},
		{"http default", "http://example.com/", "example.com:80"},
		{"https default", "https://example.com/", "example.com:443"},
		{"ipv6 with port", "http://[2001:db8::1]:3128/", "[2001:db8::1]:3128"},
		{"userinfo ignored", "https://user:pass@example.com/", "example.com:443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := targetAddress(mustTargetURL(t, tc.raw))
			if err != nil {
				t.Fatalf("targetAddress(%q): %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("targetAddress(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
	for _, tc := range []struct{ name, raw, want string }{
		{"scheme without port default", "gopher://example.com/", "unsupported target scheme"},
		{"missing host", "http:///path", "no host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := targetAddress(mustTargetURL(t, tc.raw)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("targetAddress(%q) error = %v, want %q", tc.raw, err, tc.want)
			}
		})
	}
}

func TestTunnelTargetLogValueFallbacks(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{"host port passthrough", "example.com:8080", "example.com:8080"},
		{"userinfo stripped on parse failure", "TESTUSER:TESTPASS@target.example", "target.example"},
		{"plain string without port", "target.example", "target.example"},
		{"empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tunnelTargetLogValue(tc.input)
			if got != tc.want {
				t.Fatalf("tunnelTargetLogValue(%q) = %q, want %q", tc.input, got, tc.want)
			}
			for _, secret := range []string{"TESTUSER", "TESTPASS"} {
				if strings.Contains(got, secret) {
					t.Fatalf("tunnelTargetLogValue(%q) leaked credentials: %q", tc.input, got)
				}
			}
		})
	}
}

func TestUpstreamLogValueNil(t *testing.T) {
	if got := upstreamLogValue(nil); got != "none" {
		t.Fatalf("upstreamLogValue(nil) = %q, want none", got)
	}
	if got := upstreamLogValue(&pool.Proxy{}); got != "none" {
		t.Fatalf("upstreamLogValue(no URL) = %q, want none", got)
	}
}

// Unknown auth reasons (future wrapped errors, dependency text) must fall back
// to the fixed label: raw reason text never reaches logs or /status.
func TestAuthErrorSafeTextFallback(t *testing.T) {
	for _, tc := range []struct {
		reason string
		want   string
	}{
		{"endpoint requires credentials but none are configured", "endpoint requires credentials but none are configured"},
		{"endpoint rejected credentials", "endpoint rejected credentials"},
		{"endpoint accepted no offered authentication method", "endpoint accepted no offered authentication method"},
		{"endpoint says socks5://TESTUSER:TESTPASS@proxy.example:1080", "SOCKS authentication failed"},
		{"", "SOCKS authentication failed"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			got := logErrorValue(&ProxyAuthError{Reason: tc.reason})
			if got != tc.want {
				t.Fatalf("logErrorValue(auth %q) = %q, want %q", tc.reason, got, tc.want)
			}
			for _, secret := range []string{"TESTUSER", "TESTPASS"} {
				if strings.Contains(got, secret) {
					t.Fatalf("logErrorValue(auth %q) leaked credentials: %q", tc.reason, got)
				}
			}
		})
	}
	if got := logErrorValue(nil); got != "" {
		t.Fatalf("logErrorValue(nil) = %q, want empty", got)
	}
	if got := logErrorValue(errors.New("plain")); got != "plain" {
		t.Fatalf("logErrorValue(plain) = %q, want plain", got)
	}
}
