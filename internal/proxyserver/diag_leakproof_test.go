package proxyserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
)

// Test-first: AdminMux /status currently can expose raw arbitrary errors.
func TestStatusLeakProof(t *testing.T) {
	u, _ := url.Parse("socks5://proxy.test:1080")
	pl := pool.NewRoutes([]config.RouteSpec{{URL: u, Kind: config.EgressV4}}, 30*time.Second, time.Minute, config.KindBalance{})
	p := pl.PickFor(nil, nil)
	raw := errors.New("dial socks5://TESTUSER:TESTP/ss?w@rd@proxy.test:1080: refused\x1b[31m" + strings.Repeat("z", 600))
	pl.ReportFailure(p, raw)
	pl.ReportAuthBlocked(p, errors.New("auth sees socks5://TESTUSER2:TESTP2@proxy.test:1080 \x1b[1m"+strings.Repeat("y", 600)))

	s := newRuntimeServer(pl, defaultRuntime(), testLogger())
	admin := httptest.NewServer(s.AdminMux())
	defer admin.Close()
	resp, err := http.Get(admin.URL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got struct {
		Pool []pool.Status `json:"pool"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Pool) != 1 {
		t.Fatalf("pool len = %d", len(got.Pool))
	}
	combined := got.Pool[0].LastDialError + "|" + got.Pool[0].LastAuthError
	for _, secret := range []string{"TESTUSER", "TESTUSER2", "TESTP", "TESTP2"} {
		if strings.Contains(combined, secret) {
			t.Fatalf("/status leaked %q in %q", secret, truncateDiag(combined))
		}
	}
	if strings.Contains(combined, "\x1b") {
		t.Fatalf("/status contains ESC: %q", truncateDiag(combined))
	}
	for _, field := range []string{got.Pool[0].LastDialError, got.Pool[0].LastAuthError} {
		if n := utf8.RuneCountInString(field); n > 513 {
			t.Fatalf("status error field rune length = %d, want <= 513", n)
		}
	}
	if got.Pool[0].Proxy != "proxy.test:1080" {
		t.Fatalf("Proxy = %q, want host-only", got.Pool[0].Proxy)
	}
}

func TestLogErrorValueLeakProof(t *testing.T) {
	// URL userinfo edge case: synthetic password with '/' '?' '@'.
	err := errors.New("failed through socks5://TESTUSER:TESTP/ss?w@rd@proxy.test:1080")
	got := logErrorValue(err)
	for _, secret := range []string{"TESTUSER", "TESTP"} {
		if strings.Contains(got, secret) {
			t.Fatalf("logErrorValue leaked %q in %q", secret, truncateDiag(got))
		}
	}
	if !strings.Contains(got, "proxy.test:1080") {
		t.Fatalf("logErrorValue lost host identity: %q", truncateDiag(got))
	}

	// Auth reason must not leak raw secrets / controls: only the fixed
	// production labels (or the generic fallback) may surface.
	authErr := &ProxyAuthError{Reason: "rejected for TESTAUTHSECRET\x1b[31m\nsecond line" + strings.Repeat("q", 600)}
	gotAuth := logErrorValue(authErr)
	if strings.Contains(gotAuth, "TESTAUTHSECRET") {
		t.Fatalf("logErrorValue auth leaked secret in %q", truncateDiag(gotAuth))
	}
	if strings.Contains(gotAuth, "\x1b") || strings.ContainsAny(gotAuth, "\n\r\t") {
		t.Fatalf("logErrorValue auth contains controls: %q", truncateDiag(gotAuth))
	}
	if n := utf8.RuneCountInString(gotAuth); n > 513 {
		t.Fatalf("logErrorValue auth rune length = %d, want <= 513", n)
	}
	if gotAuth != "SOCKS authentication failed" {
		t.Fatalf("logErrorValue unknown auth reason = %q, want fixed fallback", truncateDiag(gotAuth))
	}
	for _, reason := range []string{
		"endpoint requires credentials but none are configured",
		"endpoint rejected credentials",
		"endpoint accepted no offered authentication method",
	} {
		if got := logErrorValue(&ProxyAuthError{Reason: reason}); got != reason {
			t.Fatalf("logErrorValue known auth reason = %q, want %q", truncateDiag(got), reason)
		}
	}

	// ANSI neutralization.
	gotANSI := logErrorValue(errors.New("x\x1b[31mred\x1b[0m"))
	if strings.Contains(gotANSI, "\x1b") {
		t.Fatalf("logErrorValue contains ESC: %q", truncateDiag(gotANSI))
	}
}

func truncateDiag(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
