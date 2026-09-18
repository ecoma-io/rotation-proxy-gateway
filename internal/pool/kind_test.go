package pool

import (
	"errors"
	"net/url"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
)

func kindedPool(t *testing.T) *Pool {
	t.Helper()
	parse := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	return NewRoutes([]config.RouteSpec{
		{URL: parse("socks5://v4a.test:1080"), Kind: config.EgressV4},
		{URL: parse("socks5://v6.test:1080"), Kind: config.EgressV6},
		{URL: parse("socks5://v4b.test:1080"), Kind: config.EgressV4},
	}, time.Second, time.Minute)
}

func only(kind config.EgressKind) func(*Proxy) bool {
	return func(p *Proxy) bool { return p.Kind == kind }
}

func TestPickForRestrictsKindAndPreservesMixedVisibility(t *testing.T) {
	pl := kindedPool(t)
	v4a := pl.PickFor(nil, only(config.EgressV4))
	if v4a == nil || v4a.Kind != config.EgressV4 {
		t.Fatalf("v4 pick = %+v", v4a)
	}
	pl.ReportAuthBlocked(v4a, errors.New("endpoint rejected credentials"))
	mixed := pl.PickFor(nil, nil)
	if mixed == nil || mixed.Kind != config.EgressV6 {
		t.Fatalf("mixed pick after v4 auth block = %+v, want v6 route", mixed)
	}
	v4b := pl.PickFor(nil, only(config.EgressV4))
	if v4b == nil || v4b.URL.Host != "v4b.test:1080" {
		t.Fatalf("v4 pick after v4a block = %+v, want v4b", v4b)
	}
}

func TestPickForCoolingFallbackDoesNotCrossKind(t *testing.T) {
	pl := kindedPool(t)
	v4a := pl.PickFor(nil, only(config.EgressV4))
	v4b := pl.PickFor(map[*Proxy]bool{v4a: true}, only(config.EgressV4))
	pl.ReportFailure(v4a, errors.New("refused"))
	pl.ReportFailure(v4b, errors.New("refused"))
	got := pl.PickFor(nil, only(config.EgressV4))
	if got == nil || got.Kind != config.EgressV4 {
		t.Fatalf("all-cooling v4 fallback crossed kind: %+v", got)
	}
}

func TestReconfigureResetsChangedKindAndSnapshotIsSafe(t *testing.T) {
	pl := kindedPool(t)
	old := pl.PickFor(nil, only(config.EgressV4))
	pl.ReportFailure(old, errors.New("refused"))
	next := pl.Reconfigure([]config.RouteSpec{
		{URL: old.URL, Kind: config.EgressV6},
	}, time.Second, time.Minute)
	got := next.PickFor(nil, nil)
	if got == old {
		t.Fatal("route with changed kind retained health identity")
	}
	snap := next.Snapshot()
	if len(snap) != 1 || snap[0].Kind != config.EgressV6 || snap[0].Failures != 0 || snap[0].Proxy != "v4a.test:1080" {
		t.Fatalf("snapshot = %+v", snap)
	}
}

func TestReconfigureAppliesCooldownsToFutureFailures(t *testing.T) {
	pl := kindedPool(t).Reconfigure([]config.RouteSpec{
		{URL: mustURL(t, "socks5://v4a.test:1080"), Kind: config.EgressV4},
	}, 3*time.Second, 3*time.Second)
	p := pl.PickFor(nil, nil)
	if got := pl.ReportFailure(p, nil); got != 3*time.Second {
		t.Fatalf("cooldown = %s, want 3s", got)
	}
}
