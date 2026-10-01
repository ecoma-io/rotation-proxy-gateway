package rotation

import (
	"context"
	"errors"
	"time"

	"rotation-proxy-gateway/internal/coord"
	"rotation-proxy-gateway/internal/pool"
)

// Coordinator is the cluster-coordination seam the rotation engine depends on.
//
// It is an interface rather than a concrete coordinator for two reasons that
// both matter: a single-instance deployment has no Redis and therefore has no
// coordinator, and the engine's own tests must drive the distributed path
// without one. The interface is small enough that neither has to care.
//
// The nil case is meaningful and must be handled by every implementation here:
// with no coordinator the engine behaves exactly as it did before
// multi-instance coordination existed — every instance rotates on its own,
// there is no lease to contend for, and no cluster epoch to adopt.
type Coordinator interface {
	// Held returns the lease this instance currently owns, or the zero Lease.
	Held() coord.Lease

	// TryAcquire takes the rotation lease if it is free. A zero Lease with a
	// nil error means another instance holds it, which is the steady state for
	// every instance but one.
	TryAcquire(ctx context.Context) (coord.Lease, error)

	// CommitRotation records a verified rotation outcome, fenced, and adopts
	// the new cluster epoch locally. It reports whether this call performed the
	// commit.
	//
	// The fence is enforced at the mutation by the authority, not here and not
	// at acquisition, so an instance that was replaced while its procedure ran
	// is refused even though it believes it still holds the lease.
	CommitRotation(ctx context.Context, commit coord.Commit, adopt func(coord.Epoch) int) (coord.Epoch, bool, error)

	// AdoptAll raises every route's local epoch to the cluster epoch, which is
	// what makes internal/warmpool discard connections parked before it.
	AdoptAll(cluster coord.Epoch, adopt func(coord.Epoch) int) int
}

// UseCoordinator installs the cluster coordinator and the function that adopts
// a cluster epoch into the live generation.
//
// adopt is normally pool.Store.Load().Pool.AdoptClusterEpoch. It is passed in
// rather than constructed here so the engine does not need the generation
// store's Load path to stay current, and so the count it returns is the pool's
// own — an invented count would be a figure an operator would trust and nothing
// would enforce.
//
// A nil coordinator keeps the single-instance behavior exactly. That is the
// default and must remain correct: one instance, no Redis, no lease.
func (e *Engine) UseCoordinator(c Coordinator, adopt func(coord.Epoch) int) {
	e.coordMu.Lock()
	defer e.coordMu.Unlock()
	e.coordinator = c
	e.adoptEpochFn = adopt
}

// coordinatorOrNil returns the installed coordinator, or nil in
// single-instance mode.
func (e *Engine) coordinatorOrNil() Coordinator {
	e.coordMu.Lock()
	defer e.coordMu.Unlock()
	return e.coordinator
}

// ClusterEpochAdopter returns the closure that raises every route's local epoch
// to the cluster epoch. It is what a caller wires into UseCoordinator, and is
// exported so the gateway does not have to reconstruct it.
func ClusterEpochAdopter(gen *pool.Store) func(coord.Epoch) int {
	return func(epoch coord.Epoch) int {
		if gen == nil || !epoch.IsValid() {
			return 0
		}
		g := gen.Load()
		if g == nil {
			return 0
		}
		return g.Pool.AdoptClusterEpoch(uint64(epoch))
	}
}

// mayRotate reports whether this instance may start a rotation procedure at
// all.
//
// With coordination enabled, only the lease holder rotates. That is the point:
// rotation is a provider-side action with a per-route outcome, and two
// instances draining and rotating the same route concurrently is the hazard the
// lease exists to remove. Without coordination every instance answers true,
// which is exactly the pre-coordination behavior.
//
// This is a gate, not a guarantee. It is deliberately cheap and advisory in
// effect — a holder that pauses past this check is not thereby safe. The
// guarantee lives in the fenced commit, which re-checks the token at the
// mutation. Treating this gate as sufficient is precisely the bug fencing was
// added to prevent.
func (e *Engine) mayRotate(ctx context.Context) bool {
	c := e.coordinatorOrNil()
	if c == nil {
		return true
	}
	lease, err := c.TryAcquire(ctx)
	if err != nil {
		// A coordination failure is not permission to rotate: the safe answer
		// is to stand down for this tick and let the next one retry. Rotating
		// un-coordinated is the failure mode coordination exists to remove.
		e.log.Warn().Str("error", err.Error()).Msg("cluster lease unavailable; skipping rotation this cycle")
		return false
	}
	return !lease.IsZero()
}

// commitOutcome coordination-aware commit result, layered over the engine's
// existing commitOutcome.
//
// A distributed commit adds two terminal states the local engine has no word
// for: this instance was fenced (a peer won), and the commit was a duplicate of
// one that already landed. Neither is a rotation failure and neither may touch
// route health — a procedure that lost its lease has not proved anything about
// the endpoint's health, and treating it as a failure would cool a working
// route.
type distributedOutcome uint8

const (
	// distributedCommitted: the authority accepted the commit.
	distributedCommitted distributedOutcome = iota
	// distributedFenced: a peer holds the lease and this instance's token was
	// superseded. The procedure unwinds without recording anything.
	distributedFenced
	// distributedDuplicate: this attempt already committed; the record holds
	// exactly one rotation.
	distributedDuplicate
)

// commitDistributed records a verified rotation in the cluster, fenced.
//
// It returns distributedCommitted when this call is the one that committed,
// distributedDuplicate when the attempt had already committed, and
// distributedFenced when the instance was replaced mid-procedure.
//
// Every one of those outcomes leaves route health alone. In particular the
// fenced one: an instance that lost its lease learned nothing about the
// endpoint's reachability, and cooling the route would be a permanent failure
// classification for what is a coordination event — exactly the failure mode
// the contract forbids inventing.
func (e *Engine) commitDistributed(ctx context.Context, p *pool.Proxy, id, baseline, observed string, started time.Time) (distributedOutcome, coord.Epoch) {
	c := e.coordinatorOrNil()
	if c == nil {
		return distributedCommitted, coord.NoEpoch
	}
	lease := c.Held()
	if lease.IsZero() {
		// No lease: this instance is not the rotator. Nothing to commit, and
		// nothing to record about it.
		return distributedFenced, coord.NoEpoch
	}
	_, committed, err := c.CommitRotation(ctx, coord.Commit{
		Lease:      lease,
		Route:      id,
		BaselineIP: baseline,
		ObservedIP: observed,
		StartedAt:  started,
	}, e.adoptEpochFnForCommit())
	switch {
	case errors.Is(err, coord.ErrFenced), errors.Is(err, coord.ErrNotHolder):
		e.log.Warn().
			Uint64("fencing_token", lease.Token).
			Str("route", p.URL.Host).
			Msg("rotation not recorded in the cluster: this instance was replaced mid-procedure")
		return distributedFenced, coord.NoEpoch
	case err != nil:
		e.log.Warn().Str("error", err.Error()).Msg("cluster rotation commit failed")
		return distributedFenced, coord.NoEpoch
	case !committed:
		return distributedDuplicate, coord.NoEpoch
	default:
		return distributedCommitted, coord.NoEpoch
	}
}

// adoptEpochFnForCommit returns the adoption closure for a commit, read under
// the lock rather than through the wrapper.
func (e *Engine) adoptEpochFnForCommit() func(coord.Epoch) int {
	e.coordMu.Lock()
	defer e.coordMu.Unlock()
	return e.adoptEpochFn
}
