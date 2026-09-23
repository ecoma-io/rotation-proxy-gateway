package pool

import (
	"errors"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
)

// TestCanonicalIPIdentity pins the one definition of "the same egress IP" the
// whole rotation path is written in terms of. Two literals are the same address
// exactly when their canonical forms match, so no comparison elsewhere in the
// subsystem has to know about address spellings; a value that is not an address
// literal can only ever match itself, which keeps an unparseable value from
// silently equating with something else.
func TestCanonicalIPIdentity(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b string
		same bool
		note string
	}{
		{name: "identical IPv4", a: "203.0.113.1", b: "203.0.113.1", same: true},
		{
			name: "IPv4 and its mapped form", a: "203.0.113.1", b: "::ffff:203.0.113.1", same: true,
			note: "a provider switching between the two spellings has not rotated anything",
		},
		{
			name: "mapped form and IPv4, reversed", a: "::ffff:203.0.113.1", b: "203.0.113.1", same: true,
			note: "identity is symmetric, so no caller has to order the comparison",
		},
		{
			name: "equivalent IPv6 spellings", a: "2001:db8::1", b: "2001:0db8:0:0:0:0:0:1", same: true,
			note: "expanded and compressed forms are one address",
		},
		{name: "IPv6 hex case", a: "2001:DB8::1", b: "2001:db8::1", same: true},
		{name: "different IPv4 addresses", a: "203.0.113.1", b: "203.0.113.2", same: false},
		{name: "different IPv6 addresses", a: "2001:db8::1", b: "2001:db8::2", same: false},
		{
			name: "IPv4 address and a different address's mapped form", a: "::ffff:203.0.113.1", b: "203.0.113.2", same: false,
			note: "the mapped form must not collapse unrelated addresses together",
		},
		{
			name: "unparseable values", a: "not-an-address", b: "not-an-address", same: true,
			note: "impossible for a probe-verified IP; such a value matches only itself",
		},
		{name: "unparseable against a real address", a: "not-an-address", b: "203.0.113.1", same: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SameIP(tc.a, tc.b); got != tc.same {
				t.Fatalf("SameIP(%q, %q) = %v, want %v (%s)", tc.a, tc.b, got, tc.same, tc.note)
			}
			// The identity behind the comparison is the canonical 16-byte form,
			// and wherever both sides are address literals it agrees with the
			// textual comparison. When one side is not a literal there is no key
			// to compare, which is exactly why SameIP cannot equate it with a
			// real address.
			ka, oka := IPIdentity(tc.a)
			kb, okb := IPIdentity(tc.b)
			if oka && okb {
				if keySame := ka == kb; keySame != tc.same {
					t.Fatalf("IPIdentity(%q) = %x, IPIdentity(%q) = %x, want same=%v", tc.a, ka, tc.b, kb, tc.same)
				}
			} else if wantSame := tc.a == tc.b; tc.same != wantSame {
				t.Fatalf("SameIP(%q, %q) = %v, want %v with a non-literal operand", tc.a, tc.b, tc.same, wantSame)
			}
			if got := CanonicalIP(tc.a) == CanonicalIP(tc.b); got != tc.same {
				t.Fatalf("CanonicalIP comparison for %q / %q = %v, want %v", tc.a, tc.b, got, tc.same)
			}
		})
	}
}

// The canonical text is what a route records, so /status shows the address
// rather than whichever spelling arrived, and the recorded value is a fresh
// string rather than the probe response substring it was parsed out of.
func TestCanonicalIPNormalizesStoredForm(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1")
	p := pl.entries[0]

	// A mapped spelling of the baseline is stored as the address itself.
	p.SetBaselineIP("::ffff:203.0.113.1")
	if got := p.LastIP(); got != "203.0.113.1" {
		t.Fatalf("baseline stored as %q, want the canonical address", got)
	}
	// The same holds for a committed rotation, and for an expanded IPv6 form.
	commitVerified(t, pl, p, "2001:0db8:0:0:0:0:0:1", c.now)
	if got := p.LastIP(); got != "2001:db8::1" {
		t.Fatalf("committed IP stored as %q, want the canonical address", got)
	}
	// The route's recorded address is the canonical one, so the collision set
	// carries that form and not the spelling the probe reported.
	if ips := pl.LastIPs(nil); len(ips) != 1 || !ips["2001:db8::1"] {
		t.Fatalf("LastIPs(nil) = %v, want the canonical committed address", ips)
	}
}

// LastIPs is the set a candidate is screened against, so its keys must be the
// same canonical form the comparison uses — otherwise the screen and the commit
// would disagree about what a collision is.
func TestLastIPsKeysAreCanonical(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1", "socks5://m2:2")
	pl.entries[0].SetBaselineIP("::ffff:203.0.113.10")
	pl.entries[1].EndRotation("2001:0db8:0:0:0:0:0:1", c.now)

	ips := pl.LastIPs(nil)
	if len(ips) != 2 || !ips["203.0.113.10"] || !ips["2001:db8::1"] {
		t.Fatalf("LastIPs(nil) = %v, want canonical keys for both addresses", ips)
	}
	// A candidate in either spelling screens as held.
	if !ips[CanonicalIP("::ffff:203.0.113.10")] || !ips[CanonicalIP("2001:db8::1")] {
		t.Fatalf("a canonicalized candidate does not match the set: %v", ips)
	}
}

// A collision is a collision regardless of the spelling either side used:
// committing the plain form of an address another manual route holds in its
// mapped form must be rejected, and the rejection must leave the rejected route
// exactly as it was.
func TestCommitRotationCollisionIsCanonical(t *testing.T) {
	for _, tc := range []struct{ name, held, candidate string }{
		{name: "mapped holder, plain candidate", held: "::ffff:203.0.113.10", candidate: "203.0.113.10"},
		{name: "plain holder, mapped candidate", held: "203.0.113.10", candidate: "::ffff:203.0.113.10"},
		{name: "expanded holder, compressed candidate", held: "2001:0db8:0:0:0:0:0:1", candidate: "2001:db8::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &clock{now: time.Unix(0, 0)}
			pl := newManualPool(t, c, "socks5://m1:1", "socks5://m2:2")
			holder, candidate := pl.entries[0], pl.entries[1]
			holder.SetBaselineIP(tc.held)

			revisit, err := pl.CommitRotation(storeOver(t, pl), candidate, tc.candidate, c.now)
			if !errors.Is(err, ErrRotationCollision) {
				t.Fatalf("CommitRotation(%q) = %v, want ErrRotationCollision", tc.candidate, err)
			}
			if revisit {
				t.Fatal("a rejected candidate reported a revisit")
			}
			// Nothing about the rejected route moved: no counters, no recorded
			// address, no history entry for the candidate.
			if got, want := rotationCounts(t, pl, "m2:2"), [2]int{0, 0}; got != want {
				t.Fatalf("rejected route counters = %v, want %v", got, want)
			}
			if got := candidate.LastIP(); got != "" {
				t.Fatalf("rejected route lastIP = %q, want nothing recorded", got)
			}
			if key, ok := IPIdentity(tc.candidate); !ok {
				t.Fatalf("test candidate %q is not an address literal", tc.candidate)
			} else if _, indexed := candidate.verifiedIPs[key]; indexed {
				t.Fatal("the rejected candidate entered the route's history")
			}
			// The holder kept the address it held, in canonical form.
			if got, want := holder.LastIP(), CanonicalIP(tc.held); got != want {
				t.Fatalf("holder lastIP = %q, want %q", got, want)
			}
		})
	}
}

// A rotation that returns to an address the route has already verified is a
// revisit even when the provider returns it in another spelling — this is the
// historical-address question, and it is deliberately separate from "did the
// address change", which commit never decides.
func TestCommitRotationRevisitIsCanonical(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1")
	p := pl.entries[0]

	p.SetBaselineIP("203.0.113.1")                 // A
	commitVerified(t, pl, p, "203.0.113.2", c.now) // B: a fresh address
	if revisit := commitVerified(t, pl, p, "::ffff:203.0.113.1", c.now); !revisit {
		t.Fatal("returning to the baseline in its mapped spelling was not a revisit")
	}
	if got, want := rotationCounts(t, pl, "m1:1"), [2]int{2, 1}; got != want {
		t.Fatalf("counters = %v, want %v", got, want)
	}
	if got := p.LastIP(); got != "203.0.113.1" {
		t.Fatalf("lastIP after the revisit = %q, want the canonical address", got)
	}
}

// liveRouteStore publishes a pool built from specs into a Store, which is what a
// reload publishes into and what a procedure's commit is addressed to.
func liveRouteStore(t *testing.T, c *clock, specs []config.RouteSpec) (*Store, *Pool) {
	t.Helper()
	cfg := &config.RuntimeConfig{}
	for _, spec := range specs {
		cfg.ManualRoutes = append(cfg.ManualRoutes, config.ManualRouteSpec{RouteSpec: spec})
	}
	pl := NewRoutes(specs, 30*time.Second, time.Minute)
	pl.Now = c.NowFunc
	return NewStore(cfg, pl), pl
}

// assertNothingRecorded checks every observable a successful rotation would have
// moved: the counters, the recorded address, and the route's history. It is the
// shared body of the refusal cases, which all assert the same thing — a commit
// the pool refused must be invisible.
func assertNothingRecorded(t *testing.T, pl *Pool, p *Proxy, host, candidate string, wantCounters [2]int, wantLastIP string) {
	t.Helper()
	if got := rotationCounts(t, pl, host); got != wantCounters {
		t.Fatalf("counters after the refused commit = %v, want %v", got, wantCounters)
	}
	if got := p.LastIP(); got != wantLastIP {
		t.Fatalf("lastIP after the refused commit = %q, want %q", got, wantLastIP)
	}
	if key, ok := IPIdentity(candidate); !ok {
		t.Fatalf("test candidate %q is not an address literal", candidate)
	} else if _, indexed := p.verifiedIPs[key]; indexed {
		t.Fatalf("the refused candidate %q entered the route's history", candidate)
	}
}

// TestCommitRotationRejectsRouteRemovedFromTheLivePool covers the membership
// branch: the commit is addressed to the generation that is currently live, but
// the route itself is not in it, so nothing can be recorded for it.
func TestCommitRotationRejectsRouteRemovedFromTheLivePool(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	specs := []config.RouteSpec{manualSpec(t, "socks5://m1:1")}
	store, pl := liveRouteStore(t, c, specs)
	p := pl.entries[0]

	// A baseline and one committed rotation, so "unchanged" below is asserted
	// against values that would visibly move.
	p.SetBaselineIP("203.0.113.1")
	commitVerified(t, pl, p, "203.0.113.2", c.now)
	when := p.lastRotationAt

	// The reload publishes a pool without the route.
	store.Publish(&config.RuntimeConfig{})

	revisit, err := store.Load().Pool.CommitRotation(store, p, "203.0.113.3", c.now)
	if !errors.Is(err, ErrRotationRouteGone) {
		t.Fatalf("commit after removal = %v, want ErrRotationRouteGone", err)
	}
	if revisit {
		t.Fatal("a refused commit reported a revisit")
	}
	assertNothingRecorded(t, pl, p, "m1:1", "203.0.113.3", [2]int{1, 0}, "203.0.113.2")
	if !p.lastRotationAt.Equal(when) {
		t.Fatalf("lastRotationAt moved to %v, want %v", p.lastRotationAt, when)
	}
	if got := p.rotationStatus().State; got != "idle" {
		t.Fatalf("state after the refused commit = %q, want idle", got)
	}
}

// A reload that changes a route's identity replaces its state rather than
// keeping it. The replacement must start clean — a procedure still holding the
// old identity must not be able to write into the new one.
func TestCommitRotationRejectsRouteReplacedUnderANewIdentity(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	specs := []config.RouteSpec{manualSpec(t, "socks5://m1:1")}
	store, pl := liveRouteStore(t, c, specs)
	stale := pl.entries[0]

	stale.SetBaselineIP("203.0.113.1")
	commitVerified(t, pl, stale, "203.0.113.2", c.now)

	// The same URL under a different kind is a different route identity: a new
	// Proxy with fresh state, not the one the procedure holds.
	next := store.Publish(&config.RuntimeConfig{
		ManualRoutes: []config.ManualRouteSpec{{
			RouteSpec: config.RouteSpec{URL: specs[0].URL, Kind: config.EgressV4, Origin: config.RouteOriginManual},
		}},
	})
	live := next.Pool
	fresh := live.entries[0]
	if fresh == stale {
		t.Fatal("an identity change reused the old route state")
	}

	revisit, err := live.CommitRotation(store, stale, "203.0.113.3", c.now)
	if !errors.Is(err, ErrRotationRouteGone) {
		t.Fatalf("commit from the replaced identity = %v, want ErrRotationRouteGone", err)
	}
	if revisit {
		t.Fatal("a refused commit reported a revisit")
	}
	assertNothingRecorded(t, pl, stale, "m1:1", "203.0.113.3", [2]int{1, 0}, "203.0.113.2")

	// The replacement is untouched: fresh counters, no address, no history.
	if got, want := rotationCounts(t, live, "m1:1"), [2]int{0, 0}; got != want {
		t.Fatalf("replacement counters = %v, want %v", got, want)
	}
	if got := fresh.LastIP(); got != "" {
		t.Fatalf("replacement lastIP = %q, want nothing recorded", got)
	}
	if len(fresh.verifiedIPs) != 0 {
		t.Fatalf("replacement history = %v, want empty", fresh.verifiedIPs)
	}
}

// TestCommitRotationRejectsWhenGenerationChanged is the generation-publication
// race itself, at the level the engine hits it: the procedure resolved its pool
// from the store, a reload published a new generation before the commit ran,
// and the commit therefore lands on a pool that is no longer the live one.
//
// The reload preserves the route's identity, so Pool.Reconfigure reuses the
// very same *Proxy: the route IS a member of the pool being committed to, and
// the membership check alone would accept it. Only the generation check can
// refuse this — which is what makes this the case the membership check cannot
// cover, and why "same *Proxy" is not sufficient for a valid commit.
func TestCommitRotationRejectsWhenGenerationChanged(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	specs := []config.RouteSpec{manualSpec(t, "socks5://m1:1")}
	store, pl := liveRouteStore(t, c, specs)
	p := pl.entries[0]

	p.SetBaselineIP("203.0.113.1")
	commitVerified(t, pl, p, "203.0.113.2", c.now)
	when := p.lastRotationAt

	// Republish the identical spec: a new generation, a new *Pool, and the same
	// route state behind it.
	next := store.Publish(&config.RuntimeConfig{
		ManualRoutes: []config.ManualRouteSpec{{RouteSpec: specs[0]}},
	})
	if next.Pool == pl {
		t.Fatal("a reload must publish a new pool instance")
	}
	if next.Pool.Lookup(config.CanonicalRouteID(specs[0].URL)+"|"+string(specs[0].Kind)) != p {
		t.Fatal("an identity-preserving reload must reuse the route state, or this test proves nothing about membership")
	}

	// The procedure holds the pool it resolved before the reload and commits
	// through it. The route is a member, and holds no collision — the commit
	// must still be refused, because this is no longer the live generation.
	live := store.Load().Pool
	if live == pl {
		t.Fatal("the store did not publish the new generation")
	}
	revisit, err := pl.CommitRotation(store, p, "203.0.113.3", c.now)
	if !errors.Is(err, ErrRotationRouteGone) {
		t.Fatalf("commit against a superseded generation = %v, want ErrRotationRouteGone", err)
	}
	if revisit {
		t.Fatal("a refused commit reported a revisit")
	}

	// Nothing moved in either place: the counters, the address, the timestamp,
	// and the history are exactly as they were, and the newly live pool serves
	// the same unchanged state.
	assertNothingRecorded(t, pl, p, "m1:1", "203.0.113.3", [2]int{1, 0}, "203.0.113.2")
	if !p.lastRotationAt.Equal(when) {
		t.Fatalf("lastRotationAt moved to %v, want %v", p.lastRotationAt, when)
	}
	if got, want := rotationCounts(t, live, "m1:1"), [2]int{1, 0}; got != want {
		t.Fatalf("live pool counters = %v, want %v", got, want)
	}
	if got := p.rotationStatus().State; got != "idle" {
		t.Fatalf("state after the refused commit = %q, want idle", got)
	}
}

// A commit is addressed to a generation; without one there is nothing to
// validate against, so the candidate is refused rather than accepted. This is
// the guard that keeps the generation check from being optional.
func TestCommitRotationRejectsWithoutAGeneration(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1")
	p := pl.entries[0]
	p.SetBaselineIP("203.0.113.1")

	if revisit, err := pl.CommitRotation(nil, p, "203.0.113.2", c.now); !errors.Is(err, ErrRotationRouteGone) {
		t.Fatalf("commit without a generation = %v, want ErrRotationRouteGone", err)
	} else if revisit {
		t.Fatal("a refused commit reported a revisit")
	}
	assertNothingRecorded(t, pl, p, "m1:1", "203.0.113.2", [2]int{0, 0}, "203.0.113.1")
}
