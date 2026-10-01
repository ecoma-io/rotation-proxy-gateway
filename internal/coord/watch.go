package coord

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// DefaultWatchInterval is how often Watch re-reads the authority even when no
// notification arrived.
//
// This is the property that makes pub/sub safe to use at all. Redis pub/sub is
// fire-and-forget: it drops messages with no subscriber, has no delivery
// guarantee, and gives the receiver no way to know a message was lost. If the
// notification were the authority, one dropped message would leave an instance
// serving stale cluster state until someone noticed — potentially forever. So
// the notification is only a hint to go look sooner, and this interval is what
// actually guarantees convergence: an instance is never more than one interval
// behind, whatever pub/sub did.
const DefaultWatchInterval = time.Second

// ChannelName is the pub/sub channel cluster coordination events ride. It is a
// fixed name within the store's namespace; the message body carries nothing
// trusted, because a receiver re-reads the authority regardless.
const ChannelName = "cluster-events"

// WatchOptions configures a Watcher.
type WatchOptions struct {
	// Interval overrides the authoritative reconcile period. Zero takes
	// DefaultWatchInterval.
	Interval time.Duration
	// Event names the logical event to subscribe to; two are used by the
	// gateway, "epoch" and "rotation". Empty subscribes to all of them.
	Event string
}

// Watcher delivers nudges that cluster state moved, and periodically re-reads
// it regardless.
//
// The contract, and it is the whole point of the type:
//
//   - A received message carries no authority. The receiver re-reads the store.
//     Nothing in the message is believed — not the epoch, not the route, not
//     the writer.
//   - A dropped message costs at most one Interval. The ticker is the actual
//     guarantee; pub/sub only makes the common case faster.
//   - Reconnection is the subscriber's problem, handled by go-redis's
//     background reconnect. A disconnect produces no error the caller must
//     handle, because the ticker covers the gap.
//
// Every method is safe for concurrent use.
type Watcher struct {
	store    *Store
	log      zerolog.Logger
	interval time.Duration
	channel  string

	// onEvent is invoked when the cluster state should be re-read. It runs on
	// the watcher's own goroutine, so a slow re-read delays the next nudge but
	// never a serving request: nothing here is on the request path.
	onEvent func(context.Context) error

	mu sync.Mutex
	// last is the highest cluster epoch this watcher has observed, so a nudge
	// that finds nothing new costs no publication.
	last Epoch
	// notifications counts messages received, for /status and for proving a
	// dropped message was recovered by the ticker rather than by a message.
	notifications int
}

// NewWatcher builds a Watcher over a store. onEvent is called whenever the
// cluster state should be re-read — on a pub/sub nudge, and on every tick of the
// authoritative interval.
//
// A nil onEvent makes a watcher that still tracks notifications, which is what
// the status view needs.
func NewWatcher(store *Store, log zerolog.Logger, opts WatchOptions, onEvent func(context.Context) error) *Watcher {
	if store == nil {
		panic("coord: NewWatcher requires a non-nil store")
	}
	interval := opts.Interval
	if interval <= 0 {
		interval = DefaultWatchInterval
	}
	channel := store.key("events")
	if opts.Event != "" {
		channel = store.key("events", opts.Event)
	}
	return &Watcher{store: store, log: log, interval: interval, channel: channel, onEvent: onEvent}
}

// Run watches until ctx is canceled. It subscribes first, then performs one
// immediate re-read, so a fresh start does not spend a full interval behind a
// write that happened before it subscribed.
func (w *Watcher) Run(ctx context.Context) {
	// Subscribe owns the connection for its lifetime and reconnects in the
	// background. Its channel is buffered: a slow consumer drops rather than
	// stalling the publisher, which is safe precisely because the ticker is
	// the authority.
	pub := w.store.rdb.Subscribe(ctx, w.channel)
	defer func() { _ = pub.Close() }()

	events := pub.Channel()
	// One immediate re-read, then the ticker and the messages. Re-reading here
	// closes the window between subscribing and the first tick.
	w.fire(ctx, "startup")

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// The authority. A message lost, dropped, or never sent still
			// converges here.
			w.fire(ctx, "reconcile")
		case _, ok := <-events:
			if !ok {
				// The subscription closed. The ticker still runs, so this is a
				// latency regression and not a correctness one.
				w.log.Debug().Msg("coordination subscription closed; relying on the reconcile tick")
				events = nil
				continue
			}
			w.mu.Lock()
			w.notifications++
			w.mu.Unlock()
			// The hint. The store is re-read authoritatively inside fire, so
			// the message body is never consulted.
			w.fire(ctx, "notification")
		}
	}
}

// fire re-reads the cluster epoch and invokes the callback when it moved.
//
// Re-reading here rather than trusting the message is what makes the message a
// hint: even a forged or stale message results in a correct re-read, and a
// message that arrives with nothing new costs one GET and no callback.
func (w *Watcher) fire(ctx context.Context, cause string) {
	epoch, err := w.store.CurrentEpoch(ctx)
	if err != nil {
		// A coordination read failure is not fatal: the previous epoch keeps
		// serving and the next tick retries. Logging at warn is right here —
		// this is a real degradation, but a recoverable one.
		w.log.Warn().Str("cause", cause).Err(err).Msg("cluster epoch re-read failed; keeping the current epoch")
		return
	}
	w.mu.Lock()
	moved := epoch != w.last
	if moved {
		w.last = epoch
	}
	w.mu.Unlock()
	if !moved {
		return
	}
	w.log.Debug().Str("cause", cause).Str("epoch", epoch.String()).Msg("cluster rotation epoch adopted")
	if w.onEvent != nil {
		if err := w.onEvent(ctx); err != nil {
			w.log.Warn().Str("cause", cause).Err(err).Msg("adopting cluster state failed")
		}
	}
}

// Epoch reports the highest cluster epoch this watcher has observed.
func (w *Watcher) Epoch() Epoch {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.last
}

// Notifications reports how many pub/sub messages this watcher received. It
// exists so an operator — and the pub/sub-loss test — can tell the difference
// between convergence by message and convergence by the reconcile tick.
func (w *Watcher) Notifications() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.notifications
}

// Observe records an epoch the caller already knows about, so the watcher's
// first tick does not fire a callback for state the process has already
// adopted. It never moves the watcher backwards.
func (w *Watcher) Observe(epoch Epoch) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if epoch > w.last {
		w.last = epoch
	}
}

// Announce publishes a cluster event hint.
//
// It is fire-and-forget by design and reports failure without treating it as
// significant: the publisher has already committed its mutation, and a failed
// publish costs the peer at most one reconcile interval. That asymmetry is why
// the return value is logged and not acted on.
func (s *Store) Announce(ctx context.Context, event string) error {
	channel := s.key("events")
	if event != "" {
		channel = s.key("events", event)
	}
	pubCtx, cancel := s.withTimeout(ctx)
	defer cancel()
	if err := s.rdb.Publish(pubCtx, channel, time.Now().UnixMilli()).Err(); err != nil {
		return fmt.Errorf("publish coordination event: %w", err)
	}
	return nil
}

// ErrEpochUnavailable reports that the authority could not be read at all, so
// an instance has no cluster epoch to adopt. It is distinct from NoEpoch, which
// is a successfully-read "nothing has ever rotated".
var ErrEpochUnavailable = errors.New("cluster rotation epoch unavailable")
