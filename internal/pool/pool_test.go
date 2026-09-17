package pool

import (
	"errors"
	"net/url"
	"reflect"
	"testing"
	"time"

	"proxy-auto-rotate-forwarder/internal/config"
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

func newTestPool(t *testing.T, c *clock, mode config.RotateMode, urls ...string) *Pool {
	t.Helper()
	parsed := make([]*url.URL, 0, len(urls))
	for _, u := range urls {
		parsed = append(parsed, mustURL(t, u))
	}
	pl := New(parsed, mode, 30*time.Second, time.Minute)
	pl.Now = c.NowFunc
	return pl
}

func TestRoundRobinCyclesAll(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, config.RoundRobin, "http://a:1", "http://b:2", "http://c:3")
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
	pl := newTestPool(t, c, config.RoundRobin, "http://a:1", "http://b:2")

	first := pl.Pick(nil)
	if first.URL.Host != "a:1" {
		t.Fatalf("first pick = %s, want a:1", first.URL.Host)
	}
	pl.ReportFailure(first, errors.New("boom"))

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
	pl := newTestPool(t, c, config.RoundRobin, "http://a:1")
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

func TestRandomModeCoversPool(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, config.Random, "http://a:1", "http://b:2", "http://c:3")
	seen := map[string]bool{}
	for range 60 {
		seen[pl.Pick(nil).URL.Host] = true
	}
	if len(seen) != 3 {
		t.Fatalf("random picks covered %d of 3 proxies: %v", len(seen), seen)
	}
}

func TestExhaustedReturnsNil(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, config.RoundRobin, "http://a:1")
	p := pl.Pick(nil)
	if got := pl.Pick(map[*Proxy]bool{p: true}); got != nil {
		t.Fatalf("Pick(all excluded) = %v, want nil", got)
	}
}

func TestAllCoolingPicksSoonestRecovery(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, config.RoundRobin, "http://a:1", "http://b:2")

	pl.ReportFailure(pl.entries[0], nil) // a: cooldown until +30s
	pl.ReportFailure(pl.entries[1], nil)
	pl.ReportFailure(pl.entries[1], nil) // b: two failures -> until +60s

	got := pl.Pick(nil)
	if got.URL.Host != "a:1" {
		t.Fatalf("pick with all cooling = %s, want a:1 (soonest recovery)", got.URL.Host)
	}
}

func TestReloadCarriesCooldown(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, config.RoundRobin, "http://a:1", "http://b:2")
	pl.ReportFailure(pl.entries[0], nil) // a cooling

	pl.Reload([]*url.URL{mustURL(t, "http://a:1"), mustURL(t, "http://b:2")})

	if got := pl.Pick(nil).URL.Host; got != "b:2" {
		t.Fatalf("pick after reload = %s, want b:2 (a still cooling)", got)
	}
	c.advance(31 * time.Second)
	if got := pl.Pick(nil).URL.Host; got != "a:1" {
		t.Fatalf("pick after reload+cooldown = %s, want a:1 revived", got)
	}
}

func TestSnapshotFields(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newTestPool(t, c, config.RoundRobin, "http://a:1", "http://b:2")
	pl.ReportFailure(pl.entries[0], errors.New("boom"))

	snap := pl.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot len = %d, want 2", len(snap))
	}
	a := snap[0]
	if a.Proxy != "a:1" || a.Available || a.ConsecutiveFailures != 1 || a.Failures != 1 || a.LastError != "boom" {
		t.Fatalf("status a = %+v", a)
	}
	if a.CooldownFor == "" || a.CooldownFor == "0s" {
		t.Fatalf("status a cooldown = %q, want positive", a.CooldownFor)
	}
	b := snap[1]
	if b.Proxy != "b:2" || !b.Available || b.CooldownFor != "0s" {
		t.Fatalf("status b = %+v", b)
	}
}
