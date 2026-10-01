package coord

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// Controller is one instance's coordination identity: which instance it is,
// which lease it holds, and how it keeps its local warm connections in step
// with the cluster epoch.
//
// It is the seam the rotation engine and the gateway use, so neither has to know
// how fencing is implemented. Everything it does is off the serving path.
//
// One Controller is created per process when coordination is configured, and
// closed exactly once at shutdown. With no Redis configured there is none, and
// the gateway behaves exactly as it did before multi-instance coordination
// existed — the single-instance deployment keeps every previous path.
type Controller struct {
	store *Store
	log   zerolog.Logger
	owner string
	// leaseName is the cluster-wide rotation lease. One lease covers manual
	// rotation for the whole fleet: rotation is a provider-side action with a
	// per-route outcome, so two instances draining and rotating the same route
	// concurrently is the hazard the lease exists to remove. One lease is
	// simpler and stricter than a per-route lease, and the capacity cost is one
	// rotation at a time for the cluster.
	leaseName  string
	renewEvery time.Duration

	watcher *Watcher

	mu sync.Mutex
	// held is the lease this instance currently owns, or the zero Lease.
	held Lease
	// epochs records the highest cluster epoch adopted per canonical route id,
	// so adopting the same cluster epoch twice does not republish a generation.
	epochs map[string]Epoch
}

// ControllerOptions configures a Controller.
type ControllerOptions struct {
	// Owner identifies this instance in the cluster. It must be stable for the
	// process's lifetime: an owner that changed mid-run would let the old
	// identity's lease look like a different holder's.
	Owner string
	// LeaseName overrides the rotation lease name. Zero takes DefaultLeaseName.
	LeaseName string
	// RenewEvery overrides the lease renewal period. Zero takes a third of
	// LeaseTTL.
	RenewEvery time.Duration
	// WatchInterval overrides the authoritative reconcile period.
	WatchInterval time.Duration
}

// DefaultLeaseName is the cluster rotation lease's name. It is fixed rather
// than configurable per deployment because every instance must contend on the
// same lease; a name that varied would give each instance its own.
const DefaultLeaseName = "rotation"

// NewController builds a Controller over a store.
//
// A nil store panics: a controller that cannot reach the authority would
// silently never fence anything, which is the failure the type exists to
// prevent.
func NewController(store *Store, log zerolog.Logger, opts ControllerOptions) *Controller {
	if store == nil {
		panic("coord: NewController requires a non-nil store")
	}
	owner := opts.Owner
	if owner == "" {
		owner = GenerateOwnerID()
	}
	leaseName := opts.LeaseName
	if leaseName == "" {
		leaseName = DefaultLeaseName
	}
	renewEvery := opts.RenewEvery
	if renewEvery <= 0 {
		// Renew at a third of the TTL: two consecutive failed renewals still
		// leave a full period before the lease lapses, so one transient Redis
		// error never causes a takeover.
		renewEvery = store.ttl / 3
	}
	return &Controller{
		store:      store,
		log:        log,
		owner:      owner,
		leaseName:  leaseName,
		renewEvery: renewEvery,
		epochs:     map[string]Epoch{},
	}
}

// Owner reports this instance's cluster identity.
func (c *Controller) Owner() string { return c.owner }

// Store exposes the authority for callers that read the cluster state directly
// (the epoch watcher and /status).
func (c *Controller) Store() *Store { return c.store }

// GenerateOwnerID builds an instance identifier from crypto/rand.
//
// crypto/rand only: an owner id a predictable generator could anticipate would
// let an instance claim a peer's identity. The value is a name, not a
// credential, and carries nothing from the configuration.
func GenerateOwnerID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand cannot fail on any platform this binary targets, and a
		// coordinator with no identity would fence nothing. Falling back to a
		// timestamp keeps the process running and is still distinct per
		// instance in practice; the fencing token, not this value, is what
		// guarantees safety.
		return fmt.Sprintf("instance-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("instance-%x", b[:])
}

// Held reports the lease this instance currently owns, or the zero Lease.
func (c *Controller) Held() Lease {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.held
}

// Holds reports whether this instance currently owns the rotation lease.
//
// It is a local read and must never be used to authorize a mutation: the whole
// point of fencing is that a holder's belief about its own ownership is not
// evidence. Use CommitRotation, which the authority checks.
func (c *Controller) Holds() bool { return !c.Held().IsZero() }

// TryAcquire takes the rotation lease if it is free, and reports whether this
// instance now holds it.
//
// A failure to acquire is the common and quiet case for every instance but one:
// only the lease holder rotates, and the others keep serving. That is why
// ErrLeaseHeld is not logged here — it is the steady state, not an incident.
func (c *Controller) TryAcquire(ctx context.Context) (Lease, error) {
	l, err := c.store.Acquire(ctx, c.leaseName, c.owner, c.store.ttl)
	switch {
	case errors.Is(err, ErrLeaseHeld):
		c.clearHeld()
		return Lease{}, nil
	case err != nil:
		return Lease{}, err
	}
	c.mu.Lock()
	c.held = l
	c.mu.Unlock()
	c.log.Debug().Str("lease", l.String()).Msg("acquired the cluster rotation lease")
	return l, nil
}

// Renew keeps a held lease alive, re-issuing a higher fencing token.
//
// Re-acquisition is how renewal works, and the higher token is the point: an
// instance that paused long enough for its lease to lapse must not resume with
// its old token. Re-acquiring fences that token immediately.
//
// A holder that finds the lease gone simply stops holding it. It does not
// panic, does not retry in a loop, and keeps serving — the next TryAcquire
// takes over cleanly.
func (c *Controller) Renew(ctx context.Context) error {
	current := c.Held()
	if current.IsZero() {
		return ErrNoLease
	}
	next, err := c.store.Renew(ctx, current, c.store.ttl)
	switch {
	case errors.Is(err, ErrLeaseHeld):
		// Somebody took it over while this instance was away. Its token is
		// already fenced; dropping the lease locally makes the new state
		// visible immediately rather than at the next failed commit.
		c.clearHeld()
		c.log.Warn().Msg("lost the cluster rotation lease to another instance")
		return ErrNoLease
	case err != nil:
		return err
	}
	c.mu.Lock()
	c.held = next
	c.mu.Unlock()
	return nil
}

// Release drops the lease if held and announces it, so a peer can take over
// without waiting out the TTL. Release is best effort: a failure here leaves
// the lease to lapse on its own, which is correct, just slower.
func (c *Controller) Release(ctx context.Context) error {
	current := c.Held()
	if current.IsZero() {
		return nil
	}
	if err := c.store.Release(ctx, current); err != nil {
		return err
	}
	c.clearHeld()
	return nil
}

// clearHeld drops the local lease record.
func (c *Controller) clearHeld() {
	c.mu.Lock()
	c.held = Lease{}
	c.mu.Unlock()
}

// RunLease keeps the lease alive until ctx is canceled, renewing at
// renewEvery and re-acquiring if it was lost.
//
// Re-acquisition on loss is what makes a paused instance recover rather than
// stay fenced out forever: it rejoins with a new, higher token on the next
// attempt, and only once no one else holds the lease.
func (c *Controller) RunLease(ctx context.Context) {
	ticker := time.NewTicker(c.renewEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if c.Holds() {
			if err := c.Renew(ctx); err != nil && ctx.Err() == nil {
				c.log.Warn().Str("error", err.Error()).Msg("lease renewal failed")
			}
			continue
		}
		if _, err := c.TryAcquire(ctx); err != nil && ctx.Err() == nil {
			// Back off on a Redis failure rather than spinning: the tick is the
			// floor, so a persistent outage costs one attempt per period.
			c.log.Warn().Str("error", err.Error()).Msg("lease acquisition failed")
		}
	}
}

// CommitRotation records a verified rotation outcome in the cluster and adopts
// the new epoch locally.
//
// This is the whole distributed write path for a rotation, in one call, so no
// caller can commit without fencing and adopt the epoch separately. The order
// is fixed and deliberate:
//
//  1. Commit to the authority, fenced. A stale holder stops here and never
//     touches local state — which is what keeps a resumed instance from
//     rotating its own warm connections on top of the winner's.
//  2. Adopt the new cluster epoch across this instance's routes, which is what
//     discards warm connections stamped before the winner's rotation.
//
// The returned bool reports whether this call committed a new rotation. A retry
// of an attempt that already committed returns false with the record's epoch:
// the mutation happened exactly once either way.
//
// ErrFenced is returned unchanged so the caller can distinguish "I was replaced"
// from "Redis is unhappy"; the latter must never be treated as the former, or a
// real outage would silently stop rotations.
//
// The returned bool reports whether this call is the one that committed. A retry
// of an attempt that already committed returns false alongside the epoch the
// record holds: the mutation happened exactly once either way, and the caller
// still adopts the epoch because the record names that generation.
//
// adopt is invoked with the epoch regardless of committed, and is normally the
// gateway's pool-adoption closure. It runs after the authority has accepted the
// write and never before, so a fenced holder cannot invalidate its own warm
// connections on the strength of a rotation the cluster refused.
func (c *Controller) CommitRotation(ctx context.Context, commit Commit, adopt func(Epoch) int) (Epoch, bool, error) {
	epoch, committed, err := c.store.CommitRotation(ctx, commit)
	if err != nil {
		if errors.Is(err, ErrFenced) {
			// The central case: this instance was replaced while its rotation
			// procedure ran. Nothing local is touched — no epoch adoption, no
			// warm-connection invalidation, no announce — because the cluster
			// refused the write. The peer that won is unaffected by this call.
			c.log.Warn().
				Str("route", commit.Route).
				Uint64("fencing_token", commit.Lease.Token).
				Msg("rotation commit refused: this instance was replaced while the procedure ran")
			return NoEpoch, false, ErrFenced
		}
		return NoEpoch, false, err
	}
	c.Adopt(commit.Route, epoch, adopt)
	if err := c.store.Announce(ctx, "epoch"); err != nil {
		// The mutation already landed. A failed publish costs peers one
		// reconcile interval, which is the designed failure mode.
		c.log.Debug().Str("error", err.Error()).Msg("rotation committed; the epoch hint did not publish")
	}
	return epoch, committed, nil
}

// Adopt raises the local route epochs to the cluster epoch, returning the
// adoption function's report of how many routes moved.
//
// It is idempotent by epoch: adopting the same epoch twice invokes the
// adoption function once. That matters because the reconcile tick runs every
// second and an unchanged epoch is the overwhelmingly common case.
//
// The adoption function is supplied by the gateway and is normally
// func(coord.Epoch) int { return pool.Load().Pool.AdoptClusterEpoch(uint64(e)) }
// — which raises each route's local epoch, and thereby discards warm
// connections stamped before it, through the check internal/warmpool already
// enforces. The count is the pool's, never a number this package invents: an
// invented count is a figure /status would publish and nothing would enforce.
//
// A nil adopt records the epoch without applying it, which is what an instance
// with coordination enabled but no live generation yet needs.
func (c *Controller) Adopt(route string, epoch Epoch, adopt func(Epoch) int) int {
	if epoch == NoEpoch {
		return 0
	}
	c.mu.Lock()
	key := "route:" + route
	last := c.epochs[key]
	moved := epoch > last
	if moved {
		c.epochs[key] = epoch
	}
	c.mu.Unlock()
	if !moved || adopt == nil {
		return 0
	}
	return adopt(epoch)
}

// AdoptAll raises every route's local epoch to the cluster epoch. It is what
// the reconcile tick calls when the counter moved while pub/sub was silent.
//
// It is keyed separately from a per-route adoption ("cluster") because a
// cluster-wide generation is not attributable to one route: keying it by route
// would let the first per-route adoption mask a later cluster-wide bump.
func (c *Controller) AdoptAll(cluster Epoch, adopt func(Epoch) int) int {
	if cluster == NoEpoch {
		return 0
	}
	c.mu.Lock()
	last := c.epochs["cluster"]
	moved := cluster > last
	if moved {
		c.epochs["cluster"] = cluster
	}
	c.mu.Unlock()
	if !moved || adopt == nil {
		return 0
	}
	return adopt(cluster)
}

// ClusterEpoch reports the highest cluster epoch this controller has adopted.
func (c *Controller) ClusterEpoch() Epoch {
	c.mu.Lock()
	defer c.mu.Unlock()
	highest := c.epochs["cluster"]
	for key, e := range c.epochs {
		if key != "cluster" && e > highest {
			highest = e
		}
	}
	return highest
}

// Watch starts the nudge-plus-reconcile loop that adopts cluster epochs.
//
// onAdopt receives every epoch the watcher observes as genuinely new — from a
// pub/sub message or from the authoritative tick, never from the message
// itself. The loop is the only thing that drives epoch adoption from outside
// this instance's own commits.
func (c *Controller) Watch(ctx context.Context, log zerolog.Logger, onAdopt func(Epoch)) {
	w := NewWatcher(c.store, log, WatchOptions{}, func(context.Context) error {
		epoch, err := c.store.CurrentEpoch(ctx)
		if err != nil {
			return err
		}
		if onAdopt != nil {
			onAdopt(epoch)
		}
		return nil
	})
	c.watcher = w
	w.Run(ctx)
}

// Watcher exposes the watcher, for /status. It is nil until Watch is called.
func (c *Controller) Watcher() *Watcher { return c.watcher }
