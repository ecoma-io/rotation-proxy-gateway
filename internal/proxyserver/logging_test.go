package proxyserver

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"rotation-proxy-gateway/internal/pool"
)

func TestLogValuesRedactCredentialsAndRequestDetails(t *testing.T) {
	upstream, err := url.Parse("socks5://route-user:route-password@proxy.example:1080")
	if err != nil {
		t.Fatal(err)
	}

	values := []string{
		upstreamLogValue(&pool.Proxy{URL: upstream}),
		socksTargetLogValue("target-user:target-password@target.example:8443"),
		socksTargetLogValue("[2001:db8::1]:443"),
		logErrorValue(errors.New("failed through socks5://route-user:route-password@proxy.example:1080")),
		socksRejectLogValue(errors.New("unsupported address type for socks5://route-user:route-password@proxy.example:1080")),
	}
	for _, value := range values {
		for _, secret := range []string{"route-user", "route-password", "target-user", "target-password"} {
			if strings.Contains(value, secret) {
				t.Fatalf("log value %q contains secret %q", value, secret)
			}
		}
	}
	if got := values[0]; got != "proxy.example:1080" {
		t.Fatalf("upstreamLogValue() = %q, want proxy.example:1080", got)
	}
	if got := values[1]; got != "target.example:8443" {
		t.Fatalf("socksTargetLogValue() = %q, want target.example:8443", got)
	}
	if got := values[2]; got != "[2001:db8::1]:443" {
		t.Fatalf("socksTargetLogValue() = %q, want [2001:db8::1]:443", got)
	}
	if got := values[3]; !strings.Contains(got, "socks5://[redacted]@proxy.example:1080") {
		t.Fatalf("logErrorValue() = %q, want redacted URL", got)
	}
	if got := values[4]; !strings.Contains(got, "socks5://[redacted]@proxy.example:1080") {
		t.Fatalf("socksRejectLogValue() = %q, want redacted URL", got)
	}
}

// socksRejectLogValue carries locally generated framing diagnostics, so it
// must pass ordinary reasons through while bounding and sanitizing anything
// that could break the log stream.
func TestSocksRejectLogValueIsBoundedAndSanitized(t *testing.T) {
	if got := socksRejectLogValue(nil); got != "" {
		t.Fatalf("socksRejectLogValue(nil) = %q, want empty", got)
	}
	if got := socksRejectLogValue(errors.New("unexpected SOCKS version 0x04")); got != "unexpected SOCKS version 0x04" {
		t.Fatalf("socksRejectLogValue(plain) = %q, want the reason unchanged", got)
	}
	raw := errors.New("unsupported address type 0x\x1b[31m80\nsecond\tline" + strings.Repeat("z", maxLogErrorLength+40))
	got := socksRejectLogValue(raw)
	if strings.ContainsAny(got, "\n\r\t\x1b") {
		t.Fatalf("socksRejectLogValue() contains a control character: %q", truncateDiag(got))
	}
	if n := len([]rune(got)); n > maxLogErrorLength+1 {
		t.Fatalf("socksRejectLogValue() rune length = %d, want <= %d", n, maxLogErrorLength+1)
	}
	if !strings.HasPrefix(got, "unsupported address type 0x80") {
		t.Fatalf("socksRejectLogValue() lost the diagnostic prefix: %q", truncateDiag(got))
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
		{"handshake reply", &SocksHandshakeError{Op: "connect target", Err: errors.New("SOCKS reply 0x05")}, errorKindSocksConnect},
		{"handshake framing", &SocksHandshakeError{Op: "read greeting", Err: errors.New("truncated")}, errorKindSocksConnect},
		{"setup local", &SocksProtocolError{Op: "encode target", Err: errors.New("invalid hostname")}, errorKindSetup},
		{"generic", errors.New("upstream write failed"), errorKindSetup},
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
