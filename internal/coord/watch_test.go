package coord

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestPubSubLossStillConverges is the test that makes pub/sub safe to use.
//
// The claim under test is the one the whole design rests on: a message that is
// never delivered costs the receiver latency, never correctness. So this test
// makes the loss real rather than simulating it — no Announce is ever called, so
// nothing is ever published — and then asserts the watcher still converges, and
// that it converged on the reconcile tick rather than by message.
//
// Converging alone would be a weak assertion: a watcher that adopted nothing
// while reporting the right number would satisfy it. So the callback records the
// epoch the process would actually be serving with, and that is asserted too.
func TestPubSubLossStillConverges(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	const name = "pubsub-loss"

	lease, err := store.Acquire(ctx, name, "instance-a", 30*time.Second)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	first := commitSeed(t, store, lease, "route-a", "198.51.100.7", "203.0.113.9")

	var adopted atomic.Uint64
	watcher := NewWatcher(store, quietLogger(), WatchOptions{Interval: 50 * time.Millisecond},
		func(context.Context) error {
			current, err := store.CurrentEpoch(context.Background())
			if err != nil {
				return err
			}
			adopted.Store(uint64(current))
			return nil
		})

	// The loss: nothing publishes, ever. Notifications must therefore stay at
	// zero for the whole test, which is what makes the convergence below
	// attributable to the ticker.
	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		watcher.Run(watchCtx)
	}()

	// Wait out the watcher's own startup re-read first. Without this the later
	// convergence could be that read rather than a tick, and the test would pass
	// for the wrong reason.
	waitFor(t, 5*time.Second, "the watcher's startup re-read", func() bool {
		return watcher.Epoch() == first
	})

	// Now the peer rotates again — and still says nothing. Only the interval can
	// surface this.
	if _, _, err := store.CommitRotation(ctx, Commit{
		Lease:      lease,
		Route:      "route-b",
		BaselineIP: "203.0.113.9",
		ObservedIP: "203.0.113.44",
		StartedAt:  time.Now(),
	}); err != nil {
		t.Fatalf("second rotation: %v", err)
	}
	second, err := store.CurrentEpoch(ctx)
	if err != nil {
		t.Fatalf("read the epoch after the second rotation: %v", err)
	}
	if second == first {
		t.Fatalf("the second rotation did not advance the cluster epoch past %s; the test cannot prove convergence to a value that never moved", first)
	}

	waitFor(t, 5*time.Second, "the reconcile tick to adopt the unannounced epoch", func() bool {
		return watcher.Epoch() == second && adopted.Load() == uint64(second)
	})

	if n := watcher.Notifications(); n != 0 {
		t.Fatalf("the watcher received %d pub/sub messages; this test's premise is that none was ever published, so a non-zero count means the loss was not real", n)
	}
	cancel()
	<-done
}

// TestAnnouncePromptsAReReadBeforeTheTick is the other half of the contract: the
// message is a fast path and has to actually be fast.
//
// The interval is an hour, so the only thing that can produce a prompt re-read
// is the message. If the fast path were removed this test would hang instead of
// passing slowly — which is exactly the failure a convergence-only test cannot
// see, and the one the subscription exists to prevent.
func TestAnnouncePromptsAReReadBeforeTheTick(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	const name = "pubsub-fast-path"

	lease, err := store.Acquire(ctx, name, "instance-a", 30*time.Second)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	seed := commitSeed(t, store, lease, "route-a", "198.51.100.7", "203.0.113.9")

	var adopted atomic.Uint64
	watcher := NewWatcher(store, quietLogger(), WatchOptions{Interval: time.Hour},
		func(context.Context) error {
			current, err := store.CurrentEpoch(context.Background())
			if err != nil {
				return err
			}
			adopted.Store(uint64(current))
			return nil
		})

	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		watcher.Run(watchCtx)
	}()
	waitFor(t, 5*time.Second, "the watcher's startup re-read", func() bool {
		return watcher.Epoch() == seed && adopted.Load() == uint64(seed)
	})

	// An empty event name publishes to the same all-events channel the watcher
	// subscribes to when it does not filter by event.
	if err := store.Announce(ctx, ""); err != nil {
		t.Fatalf("announce: %v", err)
	}
	waitFor(t, 10*time.Second, "the announcement to prompt a re-read", func() bool {
		return watcher.Notifications() > 0
	})
	cancel()
	<-done
}

// TestAForgedNotificationIsNotBelieved pins that a message is a hint with no
// authority. A pub/sub body is whatever the publisher sent, on a channel with
// no authentication, so believing it would let any publisher — including a
// misconfigured or hostile one — move an instance onto an epoch the store never
// issued. The watcher re-reads and adopts what the store says.
//
// The forged message announces epoch 999999, which no real rotation could have
// produced, and the assertion is that the watcher does not move there.
func TestAForgedNotificationIsNotBelieved(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	const name = "pubsub-forged"

	lease, err := store.Acquire(ctx, name, "instance-a", 30*time.Second)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	truth := commitSeed(t, store, lease, "route-a", "198.51.100.7", "203.0.113.9")

	// No callback: a forged message must not be able to move the process's
	// generation, so there is nothing here for it to call.
	watcher := NewWatcher(store, quietLogger(), WatchOptions{Interval: time.Hour}, nil)
	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		watcher.Run(watchCtx)
	}()
	waitFor(t, 5*time.Second, "the watcher's startup re-read", func() bool {
		return watcher.Epoch() == truth
	})

	if err := store.rdb.Publish(ctx, store.key("events"), "999999").Err(); err != nil {
		t.Fatalf("publish a forged message: %v", err)
	}
	waitFor(t, 5*time.Second, "the watcher to process the forged message", func() bool {
		return watcher.Notifications() > 0
	})

	if got := watcher.Epoch(); got != truth {
		t.Fatalf("a forged message moved the watcher to epoch %s; the store says %s. A message is a hint and must never be an authority", got, truth)
	}
	cancel()
	<-done
}

// TestWatchReadFailureKeepsTheLastKnownEpoch pins the degradation rule: losing
// the authority for a moment must not blank the generation an instance is
// serving with. The last known-good epoch keeps serving and the next tick
// advances it. Resetting to zero instead would make every instance treat itself
// as pre-rotation and re-adopt stale warm connections.
func TestWatchReadFailureKeepsTheLastKnownEpoch(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	const name = "pubsub-read-failure"

	lease, err := store.Acquire(ctx, name, "instance-a", 30*time.Second)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	truth := commitSeed(t, store, lease, "route-a", "198.51.100.7", "203.0.113.9")

	watcher := NewWatcher(store, quietLogger(), WatchOptions{Interval: 20 * time.Millisecond}, nil)
	watcher.Observe(truth)

	// Make every read fail, then drive a re-read against it. Driving fire
	// directly keeps this deterministic; racing a connection close against the
	// ticker would test the network stack rather than the degradation rule.
	closed := store.rdb
	store.rdb = closedClient(t)
	t.Cleanup(func() { store.rdb = closed })
	watcher.store = store

	watcher.fire(canceledCtx(), "test")

	if got := watcher.Epoch(); got != truth {
		t.Fatalf("a failed re-read moved the epoch from %s to %s; a coordination read failure must keep the last known epoch serving", truth, got)
	}
	if got, err := store.CurrentEpoch(canceledCtx()); err == nil && got != truth {
		t.Fatalf("the store's own epoch changed to %s during a read failure; expected it to stay at %s", got, truth)
	}
}

// commitSeed performs one committed rotation and returns the epoch it produced,
// failing the test if the commit was refused. It exists so the watch tests read
// as the scenario they are testing rather than as script invocations.
func commitSeed(t *testing.T, store *Store, lease Lease, route, baseline, observed string) Epoch {
	t.Helper()
	epoch, committed, err := store.CommitRotation(context.Background(), Commit{
		Lease:      lease,
		Route:      route,
		BaselineIP: baseline,
		ObservedIP: observed,
		StartedAt:  time.Now(),
	})
	if err != nil {
		t.Fatalf("seed a rotation: %v", err)
	}
	if !committed {
		t.Fatal("seed a rotation was refused; the test premise is a committed rotation")
	}
	return epoch
}

// canceledCtx is already done, so any operation attempted with it fails at once
// instead of depending on a timeout.
func canceledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
