package pool

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// Test-first proof that Snapshot can expose raw arbitrary errors.
// Uses only fake TEST credentials (RFC-mocked .test hosts).
func TestSnapshotSanitizesDialError(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://proxy.test:1080")
	raw := errors.New("dial socks5://TESTUSER:TESTP/ss?w@rd@proxy.test:1080: refused\x1b[31m" + strings.Repeat("x", 600))
	pl.ReportFailure(pl.entries[0], raw)
	snap := pl.Snapshot()
	got := snap[0].LastDialError
	for _, secret := range []string{"TESTUSER", "TESTP", "ss?w@rd"} {
		if strings.Contains(got, secret) {
			t.Fatalf("Snapshot LastDialError leaked %q in %q", secret, truncateForMsg(got))
		}
	}
	if strings.Contains(got, "\x1b") {
		t.Fatalf("Snapshot LastDialError contains ESC: %q", truncateForMsg(got))
	}
	if strings.ContainsAny(got, "\n\r\t") {
		t.Fatalf("Snapshot LastDialError contains control character: %q", truncateForMsg(got))
	}
	if n := utf8.RuneCountInString(got); n > 513 {
		t.Fatalf("Snapshot LastDialError rune length = %d, want <= 513", n)
	}
	if !strings.Contains(got, "proxy.test:1080") {
		t.Fatalf("Snapshot LastDialError lost host-only route identity: %q", truncateForMsg(got))
	}
	if snap[0].Proxy != "proxy.test:1080" {
		t.Fatalf("Snapshot Proxy = %q, want host-only proxy.test:1080", snap[0].Proxy)
	}
}

func TestSnapshotSanitizesAuthError(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://proxy.test:1080")
	raw := errors.New("endpoint rejected credentials via socks5://TESTUSER:TESTP/ss@proxy.test:1080\x1b[1m" + strings.Repeat("y", 600))
	pl.ReportAuthBlocked(pl.entries[0], raw)
	snap := pl.Snapshot()
	got := snap[0].LastAuthError
	for _, secret := range []string{"TESTUSER", "TESTP"} {
		if strings.Contains(got, secret) {
			t.Fatalf("Snapshot LastAuthError leaked %q in %q", secret, truncateForMsg(got))
		}
	}
	if strings.Contains(got, "\x1b") {
		t.Fatalf("Snapshot LastAuthError contains ESC: %q", truncateForMsg(got))
	}
	if n := utf8.RuneCountInString(got); n > 513 {
		t.Fatalf("Snapshot LastAuthError rune length = %d, want <= 513", n)
	}
	// Auth errors surface only fixed safe labels; host identity lives in
	// the Proxy field, not in the error text.
	if got != "endpoint rejected credentials" {
		t.Fatalf("Snapshot LastAuthError = %q, want fixed safe label", truncateForMsg(got))
	}
	if snap[0].Proxy != "proxy.test:1080" {
		t.Fatalf("Snapshot Proxy = %q, want host-only proxy.test:1080", snap[0].Proxy)
	}
	if !snap[0].AuthBlocked || snap[0].AuthFailures != 1 {
		t.Fatalf("auth state lost by sanitization: %+v", snap[0])
	}
}

func truncateForMsg(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
