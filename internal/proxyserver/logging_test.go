package proxyserver

import (
	"bufio"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/pool"
)

func TestLogValuesRedactCredentialsAndRequestDetails(t *testing.T) {
	upstream, err := url.Parse("socks5://route-user:route-password@proxy.example:1080")
	if err != nil {
		t.Fatal(err)
	}

	values := []string{
		upstreamLogValue(&pool.Proxy{URL: upstream}),
		targetLogValue("target-user:target-password@target.example:8443"),
		targetLogValue("[2001:db8::1]:443"),
		logErrorValue(errors.New("failed through socks5://route-user:route-password@proxy.example:1080")),
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
		t.Fatalf("targetLogValue() = %q, want target.example:8443", got)
	}
	if got := values[2]; got != "[2001:db8::1]:443" {
		t.Fatalf("targetLogValue() = %q, want [2001:db8::1]:443", got)
	}
	if got := values[3]; !strings.Contains(got, "socks5://[redacted]@proxy.example:1080") {
		t.Fatalf("logErrorValue() = %q, want redacted URL", got)
	}
}

// The HTTP ingress has no local protocol-reject log value of its own: every
// request rejection is a bodyless status plus a bad_request record that carries
// no error field at all. The bounded, sanitized diagnostic path that used to
// back the SOCKS reject reason is now reachable only through logErrorValue, so
// the same bounding and control-character guarantees are pinned there —
// TestLogErrorValueIsBoundedAndSingleLine and the ANSI case in
// TestLogErrorValueLeakProof cover it. This keeps an explicit assertion that a
// bad_request record never grows an unbounded, attacker-influenced error field.
func TestBadRequestRecordsCarryNoUnboundedErrorField(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute)
	var logs safeLogBuffer
	_, addr := newProxyServer(t, pl, defaultRuntime(), captureLogger(&logs))

	// A malformed request line carrying a hostile request detail in its shape.
	conn := dialGateway(t, addr)
	if _, err := conn.Write([]byte("GET \x1b[31m" + strings.Repeat("z", maxLogErrorLength+40) + " HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if status, err := tryReadIngressStatus(bufio.NewReader(conn), http.MethodGet); err != nil || status != http.StatusBadRequest {
		t.Fatalf("malformed request status = %d (err=%v), want 400", status, err)
	}

	output := waitForRecord(t, &logs, map[string]string{"msg": "HTTP proxy request rejected", "error_kind": "bad_request"})
	for _, rec := range decodeRecords(output) {
		if !recordMatches(rec, map[string]string{"error_kind": "bad_request"}) {
			continue
		}
		if _, has := rec["error"]; has {
			t.Errorf("bad_request record grew an error field: %v", rec)
		}
	}
	if strings.Contains(output, "\x1b") {
		t.Errorf("logs contain a raw ESC: %q", truncateDiag(output))
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
