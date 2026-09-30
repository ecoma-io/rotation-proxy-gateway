package coord

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// These tests run against a real Redis. They are skipped, loudly, when
// RPGW_TEST_REDIS_ADDR is unset — the whole point of this package is that
// fencing is enforced atomically inside a Redis script, and a fake client
// would assert that the fake is correct, which is the one thing it cannot be.
//
// Each test gets its own key namespace, derived from its name, and drops it
// when it finishes. Isolation is not tidiness here: several of these tests
// deliberately expire leases and advance the cluster epoch, and a shared
// namespace would let one test's counter bump be observed as another test's.
//
// The address is read from the environment and never printed: a hosted Redis
// URL commonly carries a password.
func testAddr(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("RPGW_TEST_REDIS_ADDR")
	if strings.TrimSpace(addr) == "" {
		t.Skip("RPGW_TEST_REDIS_ADDR is unset; skipping the live-Redis coordination test — a stub client cannot prove fencing, so this suite never fakes it")
	}
	return addr
}

// testStore opens a Store in a namespace of its own, dropped at test end.
//
// The namespace is the test name plus a per-run suffix, so two packages (or a
// re-run of the same test) never collide on the lease counters — which are
// deliberately never reset, so a collision would be a genuine false failure
// rather than noise.
func testStore(t *testing.T) *Store {
	t.Helper()
	addr := testAddr(t)
	store, err := New(context.Background(), addr, Options{
		Namespace: "rpgwtest:" + sanitizedName(t.Name()) + ":" + runSuffix(),
		OpTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("open a live-Redis coordination store: %v", err)
	}
	t.Cleanup(func() {
		dropNamespace(t, store)
		_ = store.Close()
	})
	return store
}

// runSuffix distinguishes concurrent runs within one process. crypto/rand
// only, per the repository's semgrep gate.
func runSuffix() string { return GenerateOwnerID() }

// sanitizedName maps a test name to a key fragment with no spaces or colons,
// since the namespace is joined with colons.
func sanitizedName(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return '-'
		}
	}, name)
}

// dropNamespace removes every key under the store's namespace, so a test leaves
// no state behind for the next one.
func dropNamespace(t *testing.T, store *Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var cursor uint64
	for {
		keys, next, err := store.rdb.Scan(ctx, cursor, store.prefix+"*", 256).Result()
		if err != nil {
			t.Logf("scanning the test namespace for cleanup: %v", err)
			return
		}
		if len(keys) > 0 {
			if err := store.rdb.Del(ctx, keys...).Err(); err != nil {
				t.Logf("dropping the test namespace: %v", err)
				return
			}
		}
		if next == 0 {
			return
		}
		cursor = next
	}
}

// quietLogger discards output, so a test's own assertions are the only thing
// that reaches the test log.
func quietLogger() zerolog.Logger { return zerolog.Nop() }

// waitFor polls cond until it holds or the deadline passes. It exists for the
// tests that must observe a *concurrent* event — a second instance taking over
// — rather than a local one, which is where a bare sleep would be a race the
// test could lose.
func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", d, what)
}
