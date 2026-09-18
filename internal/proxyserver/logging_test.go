package proxyserver

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"proxy-auto-rotate-forwarder/internal/pool"
)

func TestLogValuesRedactCredentialsAndRequestDetails(t *testing.T) {
	upstream, err := url.Parse("socks5://route-user:route-password@proxy.example:1080")
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse("https://target-user:target-password@target.example:8443/path?token=secret#fragment")
	if err != nil {
		t.Fatal(err)
	}

	values := []string{
		upstreamLogValue(&pool.Proxy{URL: upstream}),
		httpTargetLogValue(target),
		tunnelTargetLogValue("[2001:db8::1]:443"),
		logErrorValue(errors.New("failed through socks5://route-user:route-password@proxy.example:1080")),
	}
	for _, value := range values {
		for _, secret := range []string{"route-user", "route-password", "target-user", "target-password", "token=secret", "/path"} {
			if strings.Contains(value, secret) {
				t.Fatalf("log value %q contains secret or request detail %q", value, secret)
			}
		}
	}
	if got := values[0]; got != "proxy.example:1080" {
		t.Fatalf("upstreamLogValue() = %q, want proxy.example:1080", got)
	}
	if got := values[1]; got != "target.example:8443" {
		t.Fatalf("httpTargetLogValue() = %q, want target.example:8443", got)
	}
	if got := values[2]; got != "[2001:db8::1]:443" {
		t.Fatalf("tunnelTargetLogValue() = %q, want [2001:db8::1]:443", got)
	}
	if got := values[3]; !strings.Contains(got, "socks5://[redacted]@proxy.example:1080") {
		t.Fatalf("logErrorValue() = %q, want redacted URL", got)
	}
}

func TestLogErrorKind(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"dial", &ProxyDialError{Err: errors.New("refused")}, errorKindProxyConnect},
		{"auth", &ProxyAuthError{Reason: "rejected"}, errorKindAuthRoute},
		{"setup", &SocksProtocolError{Op: "connect target", Err: errors.New("refused")}, errorKindSetup},
		{"generic", errors.New("target TLS failed"), errorKindSetup},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := logErrorKind(tc.err); got != tc.want {
				t.Fatalf("logErrorKind(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

func TestLogErrorValueIsBoundedAndSingleLine(t *testing.T) {
	err := errors.New("first\nsecond\t" + strings.Repeat("x", maxLogErrorLength+1))
	got := logErrorValue(err)
	if strings.ContainsAny(got, "\n\r\t") {
		t.Fatalf("logErrorValue() contains a control character: %q", got)
	}
	if n := len([]rune(got)); n != maxLogErrorLength+1 {
		t.Fatalf("logErrorValue() rune length = %d, want %d", n, maxLogErrorLength+1)
	}
}
