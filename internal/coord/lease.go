// Package coord is the distributed coordination substrate: how several gateway
// instances agree on who owns a rotation, and what the cluster's rotation
// generation currently is.
//
// The authority is Redis. It is authoritative for exactly three things —
// lease ownership, the fencing token sequence, and the cluster rotation
// epoch — and it is never on the serving path. A proxied request never touches
// Redis: coordination happens on rotation, on configuration change, and on the
// reconcile tick.
//
// # Why a fencing token and not a lock with a TTL
//
// The obvious design is "lock = instance-id, with a TTL". It is wrong, and the
// failure is not hypothetical. An instance that takes the lease, then pauses
// past its TTL — a long GC, a stop-the-world, a SIGSTOP, a suspended VM —
// comes back believing it still holds the lease, because nothing told it
// otherwise. Meanwhile a second instance took the lease over, saw the TTL had
// lapsed, and acted on it. The first instance then writes on top of the
// second one's work.
//
// A TTL cannot fix this, because the failure is indistinguishable from the
// holder being alive. What fixes it is a token that only ever moves forward,
// handed out by the authority, and checked at the moment of mutation rather
// than at acquisition. A holder that pauses still holds a token, but the token
// is stale — somebody else's acquisition pushed the counter past it — and the
// authority refuses it. The holder's belief about its own ownership is never
// consulted, because it cannot be trusted.
//
// This is the same construction as a Chubby lock with a sequence number, and
// the same reason Kubernetes' resourceVersion and etcd's mod_revision exist: the
// fence is what makes a lease safe to lose.
//
// # The token is monotonically increasing per acquisition
//
// Acquire issues the token from a Redis INCR on a per-lease counter, inside
// the same script that takes the lease. Two things follow, and both matter:
//
//   - The counter is never reset, not even when the lease key expires. A
//     counter that restarted at 1 would hand a fresh holder a token an old
//     holder still believes in.
//   - The INCR happens on every acquisition, not only on takeover, so a holder
//     that re-acquires its own lapsed lease gets a *new, higher* token rather
//     than silently keeping the old one. That is what makes a self-healing
//     renewal safe: the old token is fenced out the moment the new one is
//     issued.
//
// # Fencing is checked at mutation, not at acquisition
//
// Acquire succeeding says nothing about a later write being allowed. Between
// acquiring and writing, the holder can pause, lose the lease, and be replaced.
// Every mutation therefore carries its fencing token, and the authority rejects
// a token below the highest it has recorded for that resource. This is the
// central invariant of the package; see ErrFenced.
//
// # Pub/sub is an optimization, never the authority
//
// A Redis pub/sub message tells an instance that something changed and that it
// should go re-read. The message carries no authority and the receiver trusts
// nothing in it: the store is re-read, and a periodic reconcile covers a
// message that never arrived. Redis pub/sub drops messages with no subscribers
// and no delivery guarantee, so treating it as the authority would let a
// single dropped message leave an instance serving stale cluster state
// indefinitely. See Watch.
package coord

import (
	"errors"
	"fmt"
	"time"
)

// ErrFenced reports that a mutation presented a fencing token the authority
// has already superseded — a lower token than the highest it has recorded for
// that resource.
//
// This is the central error of the package and it is never transient in the
// way a connection error is: retrying the identical write will fail
// identically. The caller has been paused long enough for someone else to take
// over, and its view of the world is stale. The only correct response is to
// abandon the work in flight and re-acquire, which yields a new, higher token.
//
// It is deliberately not ErrLeaseLost. A caller can lose a lease and know it
// (the lease key is gone); ErrFenced is the case where it did not know, which
// is the one that would otherwise corrupt cluster state.
var ErrFenced = errors.New("fencing token superseded; this holder was replaced")

// ErrNotHolder reports that a mutation named an owner that is not the
// resource's current owner. It is distinct from ErrFenced: the lease may be
// held by the caller still, but under a newer token than the one presented.
var ErrNotHolder = errors.New("mutation does not name the current lease holder")

// LeaseTTL bounds how long a lease survives without a renewal. It is a
// liveness bound, not a correctness bound: correctness comes from the fencing
// token, so a TTL that is too generous costs takeover latency rather than
// safety. It is deliberately short — a paused instance is replaced quickly —
// and a holder renews well inside it.
const LeaseTTL = 10 * time.Second

// Lease is a held lease: an owner, a fencing token, and the key namespace it
// lives under. The token is what every mutation must present.
//
// A Lease value is a capability, not a mutex: holding one does not by itself
// authorize a write, because authority is re-checked at the mutation against
// the token, not against this struct's existence.
type Lease struct {
	// Name is the lease's logical name, which callers key their mutations by.
	Name string
	// Owner is the instance identifier that acquired the lease.
	Owner string
	// Token is the fencing token issued by the authority for this
	// acquisition. It is strictly greater than every token the authority ever
	// issued for this lease name.
	Token uint64
	// Namespace isolates this lease's keys from other tests, deployments, or
	// clusters sharing one Redis.
	Namespace string
}

// String renders the lease for logs. It names the lease and the owner but never
// anything from the resource the lease guards — callers log through
// sanitize.Sanitize where a route or an address may appear.
func (l Lease) String() string { return fmt.Sprintf("%s/%s@%d", l.Namespace, l.Name, l.Token) }

// IsZero reports whether l is the zero Lease, which no authority ever issued.
func (l Lease) IsZero() bool { return l.Name == "" && l.Token == 0 }

// ErrNoLease reports that the caller asked to renew or release a lease it does
// not hold. Renewal of a lapsed lease is refused rather than silently
// re-acquired: a holder that was replaced must re-acquire explicitly and get a
// new token, so that the fencing of its old token is a deliberate act.
var ErrNoLease = errors.New("lease is not held")

// ErrLeaseHeld reports that Acquire found the lease held by another owner and
// unexpired. The caller does not hold the lease and must not mutate anything
// guarded by it.
var ErrLeaseHeld = errors.New("lease is held by another owner")
