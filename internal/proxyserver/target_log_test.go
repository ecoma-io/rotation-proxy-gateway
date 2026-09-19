package proxyserver

import (
	"errors"
	"strings"
	"testing"

	"rotation-proxy-gateway/internal/pool"
)

// socksTargetLogValue keeps only the normalized host:port of a SOCKS target.
// Credentials inside a target string must never survive, whether or not the
// target parses as host:port.
func TestSocksTargetLogValueFallbacks(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{"host port passthrough", "example.com:8080", "example.com:8080"},
		{"userinfo stripped with valid port", "TESTUSER:TESTPASS@target.example:8443", "target.example:8443"},
		{"userinfo stripped on parse failure", "TESTUSER:TESTPASS@target.example", "target.example"},
		{"plain string without port", "target.example", "target.example"},
		{"ipv6 passthrough", "[2001:db8::1]:443", "[2001:db8::1]:443"},
		{"empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := socksTargetLogValue(tc.input)
			if got != tc.want {
				t.Fatalf("socksTargetLogValue(%q) = %q, want %q", tc.input, got, tc.want)
			}
			for _, secret := range []string{"TESTUSER", "TESTPASS"} {
				if strings.Contains(got, secret) {
					t.Fatalf("socksTargetLogValue(%q) leaked credentials: %q", tc.input, got)
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
