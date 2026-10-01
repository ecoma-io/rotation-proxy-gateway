package coord

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestLeaseTokenIsMonotonicPerAcquisition pins the property that makes a lease
// safe to lose: every acquisition gets a token strictly greater than every
// token the authority ever issued before it.
//
// The counter is INCR-only and has no TTL, so the sequence cannot restart when a
// lease lapses. That is the difference between a fencing token and a lock with
// an expiry: a restarted counter would hand a new holder a token an old holder
// still believes in, and the old holder would not be fenced.
func TestLeaseTokenIsMonotonicPerAcquisition(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	const name = "monotonic"

	var previous uint64
	for range 5 {
		lease, err := store.Acquire(ctx, name, "instance-a", 30*time.Second)
		if err != nil {
			t.Fatalf("acquire %d: %v", previous, err)
		}
		if lease.Token <= previous {
			t.Fatalf("token %d did not increase past %d: the fencing sequence restarted", lease.Token, previous)
		}
		previous = lease.Token
		// Release between acquisitions so this exercises a fresh takeover
		// rather than a renewal of a live lease.
		if err := store.Release(ctx, lease); err != nil {
			t.Fatalf("release: %v", err)
		}
	}

	issued, err := store.TokensIssued(ctx, name)
	if err != nil {
		t.Fatalf("read the issued-token count: %v", err)
	}
	if issued != previous {
		t.Fatalf("the authority issued %d tokens but the highest observed was %d", issued, previous)
	}
}

// TestLeaseRefusesALiveHolder pins that a held lease is not stealable: a second
// instance cannot acquire while the first's lease is unexpired, so fencing
// handles the paused-holder case and the lease handles the live-holder case.
// Each covers a failure the other cannot.
func TestLeaseRefusesALiveHolder(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	const name = "refused"

	held, err := store.Acquire(ctx, name, "instance-a", 30*time.Second)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if _, err := store.Acquire(ctx, name, "instance-b", 30*time.Second); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("second acquire returned %v, want ErrLeaseHeld", err)
	}
	// The refused acquisition must not have consumed a token: nothing was
	// taken, so nothing may be fenced by it.
	issued, err := store.TokensIssued(ctx, name)
	if err != nil {
		t.Fatalf("read the issued-token count: %v", err)
	}
	if issued != 1 {
		t.Fatalf("a refused acquisition consumed a token: issued %d, want 1", issued)
	}
	// The original holder is unaffected and its token still works.
	if err := store.Release(ctx, held); err != nil {
		t.Fatalf("release: %v", err)
	}
}

// TestLeaseExpiresWithoutAResource pins TTL expiry as a liveness property: a
// lease nobody renews lapses on its own, which is what lets a paused instance
// eventually be replaced.
//
// ForceExpire stands in for the pause here so the test is deterministic; the
// real version is a TTL running out, and the property under test — that the
// lease key is gone while the token counter survives — is identical.
func TestLeaseExpiresWithoutAResource(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	const name = "expiry"

	paused, err := store.Acquire(ctx, name, "instance-a", 200*time.Millisecond)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := store.Release(ctx, Lease{}); err != nil {
		t.Fatalf("releasing the zero lease must be a no-op: %v", err)
	}

	// After the TTL the key is gone and a peer can take the lease.
	waitFor(t, 5*time.Second, "the paused lease to lapse", func() bool {
		holder, err := store.Holder(ctx, name)
		return err == nil && holder == ""
	})

	taken, err := store.Acquire(ctx, name, "instance-b", 30*time.Second)
	if err != nil {
		t.Fatalf("a peer could not take the lapsed lease: %v", err)
	}
	if taken.Token <= paused.Token {
		t.Fatalf("the peer got token %d, not greater than the paused holder's %d: a lapsed holder would not be fenced",
			taken.Token, paused.Token)
	}
}

// TestClusterEpochIsMonotonic pins the cluster rotation epoch as strictly
// increasing and shared: the value read back after a bump is the bumped value,
// so a second instance reading the same counter sees the same generation.
func TestClusterEpochIsMonotonic(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	current, err := store.CurrentEpoch(ctx)
	if err != nil {
		t.Fatalf("read the initial epoch: %v", err)
	}
	if current != NoEpoch {
		t.Fatalf("a fresh namespace read epoch %s, want the zero epoch", current)
	}
	for want := current + 1; want <= current+4; want++ {
		got, err := store.BumpEpoch(ctx)
		if err != nil {
			t.Fatalf("bump: %v", err)
		}
		if got != want {
			t.Fatalf("bump returned %s, want %s", got, want)
		}
	}
}

// TestCommitIsExactlyOnce pins the requirement that a successful rotation
// commits the new egress IP exactly once, even when the request is retried.
//
// The idempotency key is the fencing token — the authority issues one per lease
// acquisition, so a token names exactly one rotation attempt. A retry carries
// the same token, the script sees the record already committed under it, and
// nothing is written a second time: no second epoch bump, no second record.
func TestCommitIsExactlyOnce(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	const name, route = "exactly-once", "route-a|v4"

	lease, err := store.Acquire(ctx, name, "instance-a", 30*time.Second)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	commit := Commit{
		Lease:      lease,
		Route:      route,
		BaselineIP: "198.51.100.7",
		ObservedIP: "203.0.113.9",
		StartedAt:  time.Now(),
	}

	first, committed, err := store.CommitRotation(ctx, commit)
	if err != nil || !committed {
		t.Fatalf("first commit: epoch %s committed %v err %v", first, committed, err)
	}

	// The same attempt, retried: the caller's request was duplicated. It must
	// change nothing, and must not advance the epoch.
	second, committed, err := store.CommitRotation(ctx, commit)
	if err != nil {
		t.Fatalf("retried commit: %v", err)
	}
	if committed {
		t.Fatal("a retried commit reported a second commit: the egress IP was written twice")
	}
	if second != first {
		t.Fatalf("a retried commit advanced the epoch from %s to %s", first, second)
	}

	after, err := store.CurrentEpoch(ctx)
	if err != nil {
		t.Fatalf("read the epoch after the retry: %v", err)
	}
	if after != first {
		t.Fatalf("the cluster epoch is %s after one rotation; a retry moved it to %s", first, after)
	}

	// The record names exactly one rotation, and it is the one that committed.
	rec, found, err := store.Rotation(ctx, route)
	if err != nil || !found {
		t.Fatalf("read the rotation record: found %v err %v", found, err)
	}
	if rec.Epoch != first {
		t.Fatalf("the record names epoch %s, want %s", rec.Epoch, first)
	}
	if rec.ObservedIP != "203.0.113.9" {
		t.Fatalf("the record observed IP is %q, want the canonical committed address", rec.ObservedIP)
	}
	if rec.Owner != "instance-a" {
		t.Fatalf("the record owner is %q, want instance-a", rec.Owner)
	}
	if rec.State != StateCommitted {
		t.Fatalf("the record state is %q, want committed", rec.State)
	}
}

// TestFencingRejectsAStaleHolder is the central invariant, tested directly: a
// token below the highest the authority has seen for the resource is refused at
// the mutation, and the record still names the winner.
//
// A unit test with a fake clock would only prove the arithmetic. This one runs
// against Redis, where the check happens inside the same script as the write,
// so it proves the check and the mutation really are one atomic step.
func TestFencingRejectsAStaleHolder(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	const name, route = "stale", "route-b|v4"

	stale, err := store.Acquire(ctx, name, "instance-a", 30*time.Second)
	if err != nil {
		t.Fatalf("acquire for the stale holder: %v", err)
	}
	// The holder is replaced: its lease lapses and a peer takes over with a
	// higher token. The stale holder is told nothing — that is the whole
	// failure this reproduces.
	if err := store.ForceExpire(ctx, name); err != nil {
		t.Fatalf("expire the stale holder's lease: %v", err)
	}
	winner, err := store.Acquire(ctx, name, "instance-b", 30*time.Second)
	if err != nil {
		t.Fatalf("the peer could not take over: %v", err)
	}
	if winner.Token <= stale.Token {
		t.Fatalf("the peer's token %d is not above the stale holder's %d", winner.Token, stale.Token)
	}

	// The winner commits a rotation.
	winEpoch, committed, err := store.CommitRotation(ctx, Commit{
		Lease:      winner,
		Route:      route,
		BaselineIP: "198.51.100.20",
		ObservedIP: "203.0.113.21",
		StartedAt:  time.Now(),
	})
	if err != nil || !committed {
		t.Fatalf("the winner's commit: epoch %s committed %v err %v", winEpoch, committed, err)
	}

	// The stale holder now resumes and tries to commit its own result. It must
	// be refused, and refused by the token — not by the lease, which is the
	// weaker check.
	_, _, err = store.CommitRotation(ctx, Commit{
		Lease:      stale,
		Route:      route,
		BaselineIP: "198.51.100.20",
		ObservedIP: "198.51.100.99",
		StartedAt:  time.Now(),
	})
	if !errors.Is(err, ErrFenced) {
		t.Fatalf("the stale holder's commit returned %v, want ErrFenced", err)
	}

	// The cluster state still shows the winner's rotation, untouched.
	rec, found, err := store.Rotation(ctx, route)
	if err != nil || !found {
		t.Fatalf("read the rotation record: found %v err %v", found, err)
	}
	if rec.Owner != "instance-b" {
		t.Fatalf("the record owner is %q after a fenced commit, want the winner instance-b", rec.Owner)
	}
	if rec.ObservedIP != "203.0.113.21" {
		t.Fatalf("the record observed IP is %q after a fenced commit, want the winner's 203.0.113.21", rec.ObservedIP)
	}
	if rec.Epoch != winEpoch {
		t.Fatalf("the record epoch is %s after a fenced commit, want the winner's %s", rec.Epoch, winEpoch)
	}
	// A fenced commit must not advance the epoch either.
	now, err := store.CurrentEpoch(ctx)
	if err != nil {
		t.Fatalf("read the epoch after the fenced commit: %v", err)
	}
	if now != winEpoch {
		t.Fatalf("a fenced commit advanced the cluster epoch to %s, want it unchanged at %s", now, winEpoch)
	}
}

// TestFencingRejectsALowerTokenForTheSameLease pins that fencing does not
// depend on a takeover having happened: even while one owner still holds the
// lease, a lower token is refused.
//
// This is the check a TTL-only lock cannot make. Here the lease is held by the
// *same* owner the whole time, so a lease check would pass it — only the token
// comparison catches it.
func TestFencingRejectsALowerTokenForTheSameLease(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	const name, route = "lower-token", "route-c|v4"

	first, err := store.Acquire(ctx, name, "instance-a", 30*time.Second)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// A second acquisition by the same owner re-issues a higher token, which
	// fences the first.
	if _, err := store.Acquire(ctx, name, "instance-a", 30*time.Second); err != nil {
		t.Fatalf("re-acquire: %v", err)
	}

	// The first token is now stale, and the lease is still held by the same
	// owner — so only the token check can refuse this.
	if _, _, err := store.CommitRotation(ctx, Commit{
		Lease:      first,
		Route:      route,
		ObservedIP: "203.0.113.44",
		StartedAt:  time.Now(),
	}); !errors.Is(err, ErrFenced) {
		t.Fatalf("a superseded token returned %v, want ErrFenced", err)
	}
	if _, found, err := store.Rotation(ctx, route); err != nil {
		t.Fatalf("read the record: %v", err)
	} else if found {
		t.Fatal("a fenced commit created a rotation record")
	}
}

// TestCommitRequiresTheLeaseHeld pins the second half of the fence: a holder
// whose lease is gone is refused even when its token is current.
//
// It is the case the token comparison alone cannot catch. A lease key naming a
// different owner is written directly here — bypassing Acquire, so the token
// counter does not advance — which is the only way to reach this branch: an
// ordinary takeover issues a higher token and is caught by fencing first. That
// ordering is itself worth pinning, so the test also asserts it: a takeover
// fences the stale holder on the token, and only a lease key that moved without
// a new token reaches ErrNotHolder.
func TestCommitRequiresTheLeaseHeld(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	const name, route = "not-holder", "route-d|v4"

	lease, err := store.Acquire(ctx, name, "instance-a", 30*time.Second)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// The lease key names somebody else while this holder's token is still the
	// highest issued — a lease that moved without a new token being issued.
	if err := store.rdb.Set(ctx, store.leaseKey(name), "instance-b", 0).Err(); err != nil {
		t.Fatalf("move the lease key to another owner: %v", err)
	}

	if _, _, err := store.CommitRotation(ctx, Commit{
		Lease:      lease,
		Route:      route,
		ObservedIP: "203.0.113.55",
		StartedAt:  time.Now(),
	}); !errors.Is(err, ErrNotHolder) {
		t.Fatalf("a commit from a non-holder returned %v, want ErrNotHolder", err)
	}
	if _, found, err := store.Rotation(ctx, route); err != nil {
		t.Fatalf("read the record: %v", err)
	} else if found {
		t.Fatal("a refused commit created a rotation record")
	}
}

// TestTakeoverFencesOnTheTokenNotTheLease pins which check fires first after an
// ordinary takeover, because it decides what an operator sees in the logs.
//
// A takeover issues a higher token, so a stale holder is fenced on the token.
// That is the correct and stronger outcome: the refusal does not depend on the
// lease key having been deleted, only on the authority having issued a newer
// token since. A stale holder whose lease key somehow survived still cannot
// write.
func TestTakeoverFencesOnTheTokenNotTheLease(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	const name, route = "takeover-order", "route-g|v4"

	stale, err := store.Acquire(ctx, name, "instance-a", 30*time.Second)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// A live lease cannot be taken — that is the lease's own job, and the two
	// checks are complementary. The peer takes over only once the lease has
	// lapsed, which is what a paused holder's lease does.
	if err := store.ForceExpire(ctx, name); err != nil {
		t.Fatalf("lapse the stale holder's lease: %v", err)
	}
	winner, err := store.Acquire(ctx, name, "instance-b", 30*time.Second)
	if err != nil {
		t.Fatalf("takeover: %v", err)
	}

	// Even with the lease key restored to the stale owner — the most generous
	// possible reading in its favour — the stale token is refused.
	if err := store.rdb.Set(ctx, store.leaseKey(name), stale.Owner, 30*time.Second).Err(); err != nil {
		t.Fatalf("restore the lease key to the stale owner: %v", err)
	}
	if _, _, err := store.CommitRotation(ctx, Commit{
		Lease:      stale,
		Route:      route,
		ObservedIP: "203.0.113.66",
		StartedAt:  time.Now(),
	}); !errors.Is(err, ErrFenced) {
		t.Fatalf("a superseded holder returned %v, want ErrFenced even though it holds the lease key", err)
	}

	// The winner commits normally: fencing must not have wedged the record.
	// Restoring the lease key to its real owner first, since the previous step
	// moved it deliberately.
	if err := store.rdb.Set(ctx, store.leaseKey(name), winner.Owner, 30*time.Second).Err(); err != nil {
		t.Fatalf("restore the lease key to the winner: %v", err)
	}
	if _, committed, err := store.CommitRotation(ctx, Commit{
		Lease:      winner,
		Route:      route,
		ObservedIP: "203.0.113.77",
		StartedAt:  time.Now(),
	}); err != nil || !committed {
		t.Fatalf("the winner's commit: committed %v err %v", committed, err)
	}
}

// TestIPsAreCanonicalized pins the hard IP invariant: ::ffff:1.2.3.4 and
// 1.2.3.4 are one identity, stored once and compared as equal.
//
// Without this, the same address arriving in two spellings — a probe and a
// rotate API rarely agree on the form — would read as a changed egress IP and
// count a rotation that never happened.
func TestIPsAreCanonicalized(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"1.2.3.4", "1.2.3.4"},
		{"::ffff:1.2.3.4", "1.2.3.4"},
		{"::FFFF:1.2.3.4", "1.2.3.4"},
		{"2001:db8::1", "2001:db8::1"},
		{"2001:0db8:0000::1", "2001:db8::1"},
		{"not-an-ip", ""},
	} {
		if got := canonicalIP(tc.in); got != tc.want {
			t.Errorf("canonicalIP(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if !sameIP("::ffff:1.2.3.4", "1.2.3.4") {
		t.Error("an IPv4-in-IPv6 address did not compare equal to its plain form")
	}
	if sameIP("1.2.3.4", "1.2.3.5") {
		t.Error("two distinct addresses compared equal")
	}
}

// TestRecordCanonicalizesStoredIPs pins that canonicalization reaches storage,
// not just the comparison helper: a commit carrying an IPv4-mapped address must
// store the plain form, so a reader can never see two spellings.
func TestRecordCanonicalizesStoredIPs(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	const name, route = "canon", "route-e|v4"

	lease, err := store.Acquire(ctx, name, "instance-a", 30*time.Second)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, _, err := store.CommitRotation(ctx, Commit{
		Lease:      lease,
		Route:      route,
		BaselineIP: "::ffff:198.51.100.1",
		ObservedIP: "::ffff:203.0.113.2",
		StartedAt:  time.Now(),
	}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	rec, found, err := store.Rotation(ctx, route)
	if err != nil || !found {
		t.Fatalf("read the record: found %v err %v", found, err)
	}
	if rec.ObservedIP != "203.0.113.2" {
		t.Fatalf("the stored observed IP is %q, want the canonical 203.0.113.2", rec.ObservedIP)
	}
	if rec.BaselineIP != "198.51.100.1" {
		t.Fatalf("the stored baseline IP is %q, want the canonical 198.51.100.1", rec.BaselineIP)
	}
}

// TestCommitRefusesAnUnparseableIP pins that an address we cannot canonicalize
// is refused rather than stored. A stored unparseable value could never be
// compared correctly later, so it would guarantee a future misread.
func TestCommitRefusesAnUnparseableIP(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	const route = "route-f|v4"

	lease, err := store.Acquire(ctx, "unparseable", "instance-a", 30*time.Second)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, _, err := store.CommitRotation(ctx, Commit{
		Lease:      lease,
		Route:      route,
		ObservedIP: "definitely not an ip",
		StartedAt:  time.Now(),
	}); err == nil {
		t.Fatal("a commit with an unparseable observed IP was accepted")
	}
}
