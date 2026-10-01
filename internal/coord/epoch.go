package coord

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/redis/go-redis/v9"
)

// Epoch is the cluster's rotation generation.
//
// It is monotonic and authoritative for the whole cluster: every instance
// reads it, and bumping it is what invalidates every instance's local warm
// connections at once. The local invariant internal/warmpool already enforces —
// a warm connection's epoch must equal the route's current epoch or it is
// discarded — is the same invariant; this counter is where the route's epoch
// comes from once more than one instance is running.
//
// It is an uint64 because it is only ever compared for "greater than" and
// never rendered as a human-sized number, so it cannot overflow in any
// realistic lifetime (at one rotation per route per minute across a million
// routes it takes about 1.9 million years).
type Epoch uint64

// NoEpoch is the zero Epoch: the state before anything has been committed, and
// never a valid epoch to present as a fencing token.
const NoEpoch Epoch = 0

// IsValid reports whether the epoch is one the authority actually issued.
func (e Epoch) IsValid() bool { return e > NoEpoch }

// String renders the epoch for logs and /status.
func (e Epoch) String() string { return fmt.Sprintf("epoch-%d", uint64(e)) }

// CurrentEpoch reads the cluster's current rotation epoch.
//
// It never returns an error for an unset counter: a cluster that has never
// rotated reads as NoEpoch, which is a state to serve from, not a failure. The
// zero value is the correct answer for a fresh deployment.
func (s *Store) CurrentEpoch(ctx context.Context) (Epoch, error) {
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	v, err := s.rdb.Get(ctx, s.epochKey()).Uint64()
	switch {
	case errors.Is(err, redis.Nil):
		return NoEpoch, nil
	case err != nil:
		return NoEpoch, fmt.Errorf("read cluster rotation epoch: %w", err)
	}
	return Epoch(v), nil
}

// bumpEpochScript advances the cluster epoch and returns the new value.
//
// INCR is atomic and is the whole operation: it allocates a value strictly
// greater than every value the counter has ever held, and returns the new one.
// No read-then-write, no possibility of two instances allocating the same
// epoch.
//
// The epoch counter has no TTL. An epoch that could expire would let the
// cluster's generation go backwards, and warm connections stamped with a high
// epoch would outlive the record that invalidated them.
var bumpEpochScript = redis.NewScript(`
return redis.call('INCR', KEYS[1])
`)

// BumpEpoch advances the cluster rotation epoch and returns the new value.
//
// It is called exactly once per successful manual-route rotation, and by the
// fencing guard in CommitRotation, so a retried or duplicated commit cannot
// advance it twice: the second attempt is fenced before it reaches this.
//
// The new epoch is what every instance must adopt. A warm connection stamped
// with an older epoch is discarded by internal/warmpool's own epoch check,
// which is why the counter has to live in the shared authority rather than in
// one process.
func (s *Store) BumpEpoch(ctx context.Context) (Epoch, error) {
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	v, err := bumpEpochScript.Run(ctx, s.rdb, []string{s.epochKey()}).Int64()
	if err != nil {
		return NoEpoch, fmt.Errorf("bump cluster rotation epoch: %w", err)
	}
	if v <= 0 {
		return NoEpoch, fmt.Errorf("bump cluster rotation epoch: the authority returned %d", v)
	}
	return Epoch(v), nil
}

// EpochFunc is the seam through which a running gateway learns that the
// cluster epoch moved. It is called on the reconcile tick and on a pub/sub
// nudge — never on the request path.
//
// The function returns the epoch it adopted, or an error if it could not
// re-read. An implementation that re-reads the authority and publishes locally
// is convergent: a dropped notification costs at most one interval.
type EpochFunc func(ctx context.Context, epoch Epoch) error

// Record fields. These are the hash fields of the shared rotation state
// record. They are named here as constants so the writer, the reader, and the
// tests cannot drift apart, and so it is obvious at a glance that no field is
// a credential.
const (
	FieldRoute       = "route"
	FieldEpoch       = "rotation_epoch"
	FieldState       = "state"
	FieldOwner       = "owner"
	FieldToken       = "fencing_token"
	FieldStartedAt   = "started_at"
	FieldBaselineIP  = "baseline_ip"
	FieldObservedIP  = "observed_ip"
	FieldNextRetryAt = "next_retry_at"
	FieldUpdatedAt   = "updated_at"
)

// RotationState is the phase of a manual route's rotation, as the cluster sees
// it. The values mirror internal/pool's RotationState so a record read here and
// a /status snapshot of the same route read there agree, without this package
// importing the pool or the pool importing this one.
type RotationState string

// The cluster-visible rotation phases. These are the same four the local pool
// publishes plus the two terminal outcomes a distributed rotation adds.
const (
	// StateIdle is a route serving normally, between rotations.
	StateIdle RotationState = "idle"
	// StateDraining is a route quiescing its in-flight work.
	StateDraining RotationState = "draining"
	// StateRotating is a route with the provider rotate call in flight.
	StateRotating RotationState = "rotating"
	// StateVerifying is a route polling until its egress IP actually changed.
	StateVerifying RotationState = "verifying"
	// StateStale is a route whose rotation did not change its egress IP; it
	// keeps serving and retries with backoff.
	StateStale RotationState = "stale"
	// StateCommitted is a rotation whose new egress IP was committed to the
	// cluster. It is the terminal success state.
	StateCommitted RotationState = "committed"
)

// canonicalIP renders an IP for storage and comparison, unmapping an
// IPv4-in-IPv6 form so `::ffff:1.2.3.4` and `1.2.3.4` are one identity.
//
// This is a hard invariant of the whole migration, not a nicety: the same
// address arriving in two spellings from a probe and a rotate API would
// otherwise read as a changed egress IP and count as a rotation that never
// happened. An unparseable address is stored as the empty string rather than
// kept verbatim, so a malformed value can never become a distinct "IP".
func canonicalIP(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	return addr.Unmap().String()
}

// sameIP reports whether two addresses are the same identity after
// canonicalization. Both are canonicalized first, so the comparison cannot be
// defeated by differing spellings.
func sameIP(a, b string) bool {
	ca, cb := canonicalIP(a), canonicalIP(b)
	return ca != "" && ca == cb
}

// RecordTTL bounds how long an unfinished rotation record survives with no
// writer touching it.
//
// A record outlives its rotation so an operator can see what happened, and so
// an instance that missed every notification can still read the outcome. It is
// a TTL on the whole hash rather than per-field because a record whose phases
// were written at different times is not a coherent record: partial
// liveness would let a reader observe a state field newer than its token.
const RecordTTL = time.Hour
