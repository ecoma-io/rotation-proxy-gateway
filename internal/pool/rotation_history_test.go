package pool

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
)

// commitVerified commits ip as a verified rotation of p and fails the test when
// the pool rejects the candidate; it returns the revisit signal.
func commitVerified(t *testing.T, pl *Pool, p *Proxy, ip string, at time.Time) bool {
	t.Helper()
	revisit, err := pl.CommitRotation(p, ip, at)
	if err != nil {
		t.Fatalf("CommitRotation(%q) = %v, want a successful commit", ip, err)
	}
	return revisit
}

// rotationCounts returns the route's successful-rotation counters from
// /status as {rotationCount, ipRevisitCount}.
func rotationCounts(t *testing.T, pl *Pool, host string) [2]int {
	t.Helper()
	s := findStatus(t, pl.Snapshot(), host)
	if s.Rotation == nil {
		t.Fatalf("route %s has no rotation view", host)
	}
	return [2]int{s.Rotation.RotationCount, s.Rotation.IPRevisitCount}
}

// TestRotationCountersFollowVerifiedIPHistory pins the counter semantics
// against the history they are defined over: rotationCount counts every
// successfully committed verified IP, and ipRevisitCount counts the subset of
// those commits that landed on an address the same route had already verified
// — the baseline included. Cross-route collisions, rejected candidates, and
// unchanged attempts never reach a commit and so are covered elsewhere.
func TestRotationCountersFollowVerifiedIPHistory(t *testing.T) {
	const (
		a = "203.0.113.1"
		b = "203.0.113.2"
		c = "203.0.113.3"
	)
	for _, tc := range []struct {
		name             string
		baseline         string
		commits          []string
		wantCount        int
		wantRevisitCount int
	}{
		{
			name:      "baseline then two fresh commits",
			baseline:  a,
			commits:   []string{b, c},
			wantCount: 2,
		},
		{
			name:             "returning to the baseline is a revisit",
			baseline:         a,
			commits:          []string{b, a},
			wantCount:        2,
			wantRevisitCount: 1,
		},
		{
			name:             "returning to an older, non-immediate address",
			baseline:         a,
			commits:          []string{b, c, a},
			wantCount:        3,
			wantRevisitCount: 1,
		},
		{
			// The issue's worked example: every commit is a rotation, and the
			// second arrival at an already-verified address is a revisit.
			name:             "multiple revisits",
			baseline:         a,
			commits:          []string{b, c, a, c},
			wantCount:        4,
			wantRevisitCount: 2,
		},
		{
			name:             "revisits interleaved with fresh addresses",
			baseline:         a,
			commits:          []string{b, c, a, c, b},
			wantCount:        5,
			wantRevisitCount: 3,
		},
		{
			name:      "no baseline still counts commits without revisits",
			commits:   []string{a, b, c},
			wantCount: 3,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &clock{now: time.Unix(0, 0)}
			pl := newManualPool(t, c, "socks5://m1:1")
			p := pl.entries[0]
			if tc.baseline != "" {
				p.SetBaselineIP(tc.baseline)
			}
			for _, ip := range tc.commits {
				commitVerified(t, pl, p, ip, c.now)
			}
			if got, want := rotationCounts(t, pl, "m1:1"), [2]int{tc.wantCount, tc.wantRevisitCount}; got != want {
				t.Fatalf("counters = %v, want %v", got, want)
			}
		})
	}
}

// The history is keyed by the canonical 16-byte address, so the two textual
// forms of the same IPv4 address are one identity: a provider reporting
// ::ffff:203.0.113.1 has handed back the address the route already held.
func TestRevisitIdentityIsCanonicalAcrossAddressForms(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1")
	p := pl.entries[0]

	p.SetBaselineIP("203.0.113.1")
	if revisit := commitVerified(t, pl, p, "::ffff:203.0.113.1", c.now); !revisit {
		t.Fatal("the v4-mapped form of the baseline was not recognized as a revisit")
	}
	if got, want := rotationCounts(t, pl, "m1:1"), [2]int{1, 1}; got != want {
		t.Fatalf("counters = %v, want %v", got, want)
	}
}

// An IP that is not an address literal (impossible for a probe-verified IP,
// possible only for a directly-constructed call) is committed but not indexed:
// it counts as a rotation, can never be a revisit, and never enters the
// history a later commit is compared against.
func TestUnparseableCommittedIPIsCountedButNotIndexed(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1")
	p := pl.entries[0]

	p.SetBaselineIP("203.0.113.1")
	if revisit := commitVerified(t, pl, p, "not-an-address", c.now); revisit {
		t.Fatal("an unparseable candidate reported a revisit")
	}
	if revisit := commitVerified(t, pl, p, "not-an-address", c.now); revisit {
		t.Fatal("an unindexed candidate became a revisit on its second commit")
	}
	// The baseline is still the only history entry, so returning to it is a
	// revisit: the unindexed commits disturbed nothing.
	if revisit := commitVerified(t, pl, p, "203.0.113.1", c.now); !revisit {
		t.Fatal("returning to the baseline after unindexed commits is not a revisit")
	}
	if got, want := rotationCounts(t, pl, "m1:1"), [2]int{3, 1}; got != want {
		t.Fatalf("counters = %v, want %v", got, want)
	}
}

// TestRejectedCollisionLeavesCountersAndHistoryUntouched covers the rejected
// side of a collision: a procedure whose candidate lost the atomic
// check-and-record race moves neither counter and leaves no trace in the
// loser's history. "Leaves no trace" is asserted behaviourally, since the
// history is internal by design: once the winner moves off the contested
// address, the loser committing that same address is a fresh commit, not a
// revisit.
func TestRejectedCollisionLeavesCountersAndHistoryUntouched(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1", "socks5://m2:2")
	winner, loser := pl.entries[0], pl.entries[1]
	const shared = "198.51.100.9"

	if revisit := commitVerified(t, pl, winner, shared, c.now); revisit {
		t.Fatal("the winner's first commit reported a revisit")
	}
	// The loser screened the address before the winner committed it.
	revisit, err := pl.CommitRotation(loser, shared, c.now)
	if !errors.Is(err, ErrRotationCollision) {
		t.Fatalf("lost race commit = %v, want ErrRotationCollision", err)
	}
	if revisit {
		t.Fatal("a rejected candidate reported a revisit")
	}
	if got, want := rotationCounts(t, pl, "m2:2"), [2]int{0, 0}; got != want {
		t.Fatalf("loser counters after the rejection = %v, want %v", got, want)
	}
	if got := loser.LastIP(); got != "" {
		t.Fatalf("loser lastIP = %q, want nothing recorded", got)
	}

	// The winner rotates away from the contested address, so nothing in the
	// pool holds it any longer.
	commitVerified(t, pl, winner, "198.51.100.10", c.now)

	// The rejected candidate never entered the loser's history: committing it
	// now is a fresh commit, and the loser's counters move exactly once.
	if revisit := commitVerified(t, pl, loser, shared, c.now); revisit {
		t.Fatal("the formerly rejected candidate counted as a revisit")
	}
	if got, want := rotationCounts(t, pl, "m2:2"), [2]int{1, 0}; got != want {
		t.Fatalf("loser counters after the fresh commit = %v, want %v", got, want)
	}
	if got, want := rotationCounts(t, pl, "m1:1"), [2]int{2, 0}; got != want {
		t.Fatalf("winner counters = %v, want %v", got, want)
	}
}

// Pool.Reconfigure retains the same *Proxy for an unchanged URL+kind+origin,
// so the counters and the history ride along with the rest of the route's
// rotation state — a revisit still counts after a reload. A route whose
// identity changed is a new state and legitimately starts fresh.
func TestRotationCountersAndHistorySurviveIdentityPreservingReload(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	specs := []config.RouteSpec{manualSpec(t, "socks5://m1:1")}
	pl := NewRoutes(specs, 30*time.Second, time.Minute)
	pl.Now = c.NowFunc
	p := pl.entries[0]

	p.SetBaselineIP("203.0.113.1")
	commitVerified(t, pl, p, "203.0.113.2", c.now)
	if got, want := rotationCounts(t, pl, "m1:1"), [2]int{1, 0}; got != want {
		t.Fatalf("counters before the reload = %v, want %v", got, want)
	}

	next := pl.Reconfigure(specs, 30*time.Second, time.Minute)
	next.Now = c.NowFunc
	if next.entries[0] != p {
		t.Fatal("an unchanged manual route rebuilt a new state")
	}
	if got, want := rotationCounts(t, next, "m1:1"), [2]int{1, 0}; got != want {
		t.Fatalf("counters lost across an identity-preserving reload: %v, want %v", got, want)
	}
	// The history survived too: the pre-reload baseline is still a revisit.
	if revisit := commitVerified(t, next, next.entries[0], "203.0.113.1", c.now); !revisit {
		t.Fatal("the baseline was forgotten across an identity-preserving reload")
	}
	if got, want := rotationCounts(t, next, "m1:1"), [2]int{2, 1}; got != want {
		t.Fatalf("counters after the post-reload revisit = %v, want %v", got, want)
	}

	// A kind change is a new route identity: fresh state, fresh counters, and
	// no history to revisit.
	changed := []config.RouteSpec{{URL: specs[0].URL, Kind: config.EgressV4, Origin: config.RouteOriginManual}}
	rebuilt := next.Reconfigure(changed, 30*time.Second, time.Minute)
	rebuilt.Now = c.NowFunc
	if rebuilt.entries[0] == p {
		t.Fatal("an identity change reused the old route state")
	}
	if got, want := rotationCounts(t, rebuilt, "m1:1"), [2]int{0, 0}; got != want {
		t.Fatalf("counters after an identity change = %v, want %v", got, want)
	}
	if revisit := commitVerified(t, rebuilt, rebuilt.entries[0], "203.0.113.2", c.now); revisit {
		t.Fatal("a rebuilt route reported a revisit against the old history")
	}
}

// The two counters are always emitted — no omitempty — so an operator reading
// /status sees an explicit zero rather than a missing key, under the exact
// field names the observability contract documents.
func TestRotationStatusAlwaysSerializesCounters(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	pl := newManualPool(t, c, "socks5://m1:1")
	p := pl.entries[0]

	// A fresh route: both keys present, both zero.
	raw := marshalRotation(t, pl.Snapshot()[0].Rotation)
	for _, key := range []string{"rotationCount", "ipRevisitCount"} {
		if _, ok := raw[key]; !ok {
			t.Fatalf("fresh rotation view omits %q: %s", key, raw)
		}
	}
	p.SetBaselineIP("203.0.113.1")
	commitVerified(t, pl, p, "203.0.113.2", c.now)
	commitVerified(t, pl, p, "203.0.113.1", c.now)

	var decoded RotationStatus
	encoded, err := json.Marshal(pl.Snapshot()[0].Rotation)
	if err != nil {
		t.Fatalf("marshal rotation view: %v", err)
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal rotation view: %v", err)
	}
	if decoded.RotationCount != 2 || decoded.IPRevisitCount != 1 {
		t.Fatalf("decoded counters = %d/%d, want 2/1", decoded.RotationCount, decoded.IPRevisitCount)
	}
	// The pre-existing fields keep their names and values alongside them.
	if decoded.State != "idle" || decoded.LastIP != "203.0.113.1" || decoded.ConsecutiveSameIP != 0 {
		t.Fatalf("rotation view = %+v, want the existing fields unchanged", decoded)
	}
}

func marshalRotation(t *testing.T, rs *RotationStatus) map[string]json.RawMessage {
	t.Helper()
	if rs == nil {
		t.Fatal("manual route has no rotation view")
	}
	encoded, err := json.Marshal(rs)
	if err != nil {
		t.Fatalf("marshal rotation view: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatalf("unmarshal rotation view: %v", err)
	}
	return raw
}
