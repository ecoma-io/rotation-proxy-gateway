package pool

import (
	"errors"
	"net/url"
	"reflect"
	"testing"
	"time"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

// clock replaces Pool.Now so cooldown tests are deterministic.
type clock struct{ now time.Time }

func (c *clock) NowFunc() time.Time      { return c.now }
func (c *clock) advance(d time.Duration) { c.now = c.now.Add(d) }

func newTestPool(t *testing.T, c *clock, urls ...string) *Pool {
	t.Helper()
	parsed := make([]*url.URL, 0, len(urls))
	for _, u := range urls {
		parsed = append(parsed, mustURL(t, u))
	}
	pl := New(parsed, 30*time.Second, time.Minute)
	pl.Now = c.NowFunc
	return pl
}

func TestRoundRobinCyclesAll(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1", "socks5://b:2", "socks5://c:3")
	var got []string
	for range 6 {
		got = append(got, pl.Pick(nil).URL.Host)
	}
	want := []string{"a:1", "b:2", "c:3", "a:1", "b:2", "c:3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pick order = %v, want %v", got, want)
	}
}

func TestFailureCooldownSkipAndRevive(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1", "socks5://b:2")

	first := pl.Pick(nil)
	if first.URL.Host != "a:1" {
		t.Fatalf("first pick = %s, want a:1", first.URL.Host)
	}
	pl.ReportFailure(first, errors.New("dial refused"))

	if got := pl.Pick(nil).URL.Host; got != "b:2" {
		t.Fatalf("pick after failure = %s, want b:2 (a cooling)", got)
	}
	c.advance(31 * time.Second)
	if got := pl.Pick(nil).URL.Host; got != "a:1" {
		t.Fatalf("pick after cooldown = %s, want a:1 revived", got)
	}
}

func TestCooldownExponentialCap(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1")
	p := pl.Pick(nil)

	if cd := pl.ReportFailure(p, nil); cd != 30*time.Second {
		t.Fatalf("first cooldown = %s, want 30s", cd)
	}
	c.advance(30 * time.Second)
	if cd := pl.ReportFailure(p, nil); cd != time.Minute {
		t.Fatalf("second cooldown = %s, want 1m", cd)
	}
	c.advance(time.Minute)
	if cd := pl.ReportFailure(p, nil); cd != time.Minute {
		t.Fatalf("third cooldown = %s, want capped 1m", cd)
	}
}

func TestExhaustedReturnsNil(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1")
	p := pl.Pick(nil)
	if got := pl.Pick(map[*Proxy]bool{p: true}); got != nil {
		t.Fatalf("Pick(all excluded) = %v, want nil", got)
	}
}

func TestAllCoolingPicksSoonestRecovery(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1", "socks5://b:2")

	pl.ReportFailure(pl.entries[0], nil) // a: cooldown until +30s
	pl.ReportFailure(pl.entries[1], nil)
	pl.ReportFailure(pl.entries[1], nil) // b: two failures -> until +60s

	got := pl.Pick(nil)
	if got.URL.Host != "a:1" {
		t.Fatalf("pick with all cooling = %s, want a:1 (soonest recovery)", got.URL.Host)
	}
}

func TestAuthBlockedDoesNotCreateCooldown(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1", "socks5://b:2")
	pl.ReportAuthBlocked(pl.entries[0], errors.New("socks5: auth rejected"))

	snap := pl.Snapshot()
	if snap[0].Available || !snap[0].AuthBlocked || snap[0].AuthFailures != 1 ||
		snap[0].Failures != 0 || snap[0].ConsecutiveFailures != 0 || snap[0].CooldownFor != "0s" {
		t.Fatalf("blocked route snapshot = %+v", snap[0])
	}
	if got := pl.Pick(nil); got.URL.Host != "b:2" {
		t.Fatalf("Pick() = %s, want unblocked b:2", got.URL.Host)
	}
}

func TestAllAuthBlockedReturnsNil(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1")
	pl.ReportAuthBlocked(pl.entries[0], errors.New("auth rejected"))
	if got := pl.Pick(nil); got != nil {
		t.Fatalf("Pick() = %v, want nil when all routes auth-blocked", got)
	}
}

func TestReloadPreservesUnchangedStateAndResetsChangedCredentials(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://u:old@a:1", "socks5://b:2")
	pl.ReportAuthBlocked(pl.entries[0], errors.New("auth rejected"))
	pl.ReportFailure(pl.entries[1], errors.New("dial refused"))

	pl.Reload([]*url.URL{
		mustURL(t, "socks5://u:old@a:1"),
		mustURL(t, "socks5://u:new@b:2"),
	})

	snap := pl.Snapshot()
	if !snap[0].AuthBlocked || snap[0].AuthFailures != 1 {
		t.Fatalf("unchanged route state = %+v, want auth state preserved", snap[0])
	}
	if snap[1].AuthBlocked || snap[1].Failures != 0 || snap[1].CooldownFor != "0s" {
		t.Fatalf("changed route state = %+v, want fresh state", snap[1])
	}
}

func TestSnapshotFields(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, "socks5://a:1", "socks5://b:2")
	pl.ReportFailure(pl.entries[0], errors.New("dial refused"))

	snap := pl.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot len = %d, want 2", len(snap))
	}
	a := snap[0]
	if a.Proxy != "a:1" || a.Available || a.ConsecutiveFailures != 1 || a.Failures != 1 || a.LastDialError != "dial refused" {
		t.Fatalf("status a = %+v", a)
	}
	if a.CooldownFor == "" || a.CooldownFor == "0s" {
		t.Fatalf("status a cooldown = %q, want positive", a.CooldownFor)
	}
	b := snap[1]
	if b.Proxy != "b:2" || !b.Available || b.CooldownFor != "0s" || b.LastDialError != "" {
		t.Fatalf("status b = %+v", b)
	}
}
