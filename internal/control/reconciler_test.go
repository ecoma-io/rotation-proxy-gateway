package control

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/configstore"
	"rotation-proxy-gateway/internal/pool"

	"github.com/rs/zerolog"
)

// The reconciler is the defensive half of the durable store, and these tests
// are about the defences: an invalid candidate never replaces a serving
// generation, a stale generation's route state survives a revision change, and
// the notify hook can only ever see configurations that were validated.

// fakeStore is an in-memory Repository. It exists so the reconciler's contract
// can be tested exhaustively without a database, and — more importantly — so
// the reconciler can be handed a candidate no real store would accept, which is
// exactly the untrusted-input case it exists to survive.
type fakeStore struct {
	mu     sync.Mutex
	active *configstore.Active
	// committed accumulates every appended revision, so a test can assert a
	// rejected write left no trace.
	committed []configstore.Revision
	next      int64

	// readErr, when set, is returned by Active instead of the active revision.
	readErr error
	// activeCalls counts reads, so a test can assert the steady-state poll does
	// no work beyond one query.
	activeCalls int
}

func newFakeStore() *fakeStore { return &fakeStore{next: 1} }

func (s *fakeStore) Active(context.Context) (configstore.Active, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeCalls++
	if s.readErr != nil {
		return configstore.Active{}, s.readErr
	}
	if s.active == nil {
		return configstore.Active{}, configstore.ErrNoActiveRevision
	}
	return *s.active, nil
}

// readAttempts reports how many times Active has been called, under the lock —
// the reconciler reads it from the goroutine its Run loop owns.
func (s *fakeStore) readAttempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeCalls
}

func (s *fakeStore) setActive(doc configstore.Document, revision configstore.Revision) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = &configstore.Active{Record: configstore.Record{
		Revision:   revision,
		DocVersion: doc.Version,
		Document:   doc.JSON,
	}}
}

func (s *fakeStore) Get(_ context.Context, revision configstore.Revision) (configstore.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil || s.active.Revision != revision {
		return configstore.Record{}, fmt.Errorf("%w: %d", configstore.ErrNoRevision, int64(revision))
	}
	return s.active.Record, nil
}

func (s *fakeStore) Commit(_ context.Context, expected configstore.Revision, doc configstore.Document, _ configstore.Meta) (configstore.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected.IsValid() && (s.active == nil || s.active.Revision != expected) {
		return configstore.Record{}, configstore.ErrRevisionMismatch
	}
	revision := configstore.Revision(s.next)
	s.next++
	s.committed = append(s.committed, revision)
	s.active = &configstore.Active{Record: configstore.Record{
		Revision:   revision,
		DocVersion: doc.Version,
		Document:   doc.JSON,
	}}
	return s.active.Record, nil
}

func (s *fakeStore) Activate(_ context.Context, expected, target configstore.Revision) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil || s.active.Revision != expected {
		return configstore.ErrRevisionMismatch
	}
	s.active.Revision = target
	return nil
}

func (s *fakeStore) Migrate(context.Context) error { return nil }
func (s *fakeStore) SchemaVersion(context.Context) (int, error) {
	return 1, nil
}
func (s *fakeStore) Close() {}

// mustConfig decodes a configuration document fixture.
func mustConfig(t *testing.T, document string) *config.RuntimeConfig {
	t.Helper()
	cfg, err := config.DecodeDocument([]byte(document))
	if err != nil {
		t.Fatalf("decoding the fixture: %v", err)
	}
	return cfg
}

// mustDocument encodes a configuration fixture into a durable document.
func mustDocument(t *testing.T, cfg *config.RuntimeConfig) configstore.Document {
	t.Helper()
	doc, err := configstore.NewDocument(cfg)
	if err != nil {
		t.Fatalf("encoding the fixture: %v", err)
	}
	return doc
}

// documentFor builds a durable document straight from JSON, for the cases whose
// point is that the document does not decode.
func documentFor(t *testing.T, body string) configstore.Document {
	t.Helper()
	return configstore.Document{Version: config.DocumentVersion, JSON: []byte(body)}
}

// servingPool builds a generation store already serving cfg, the way the boot
// path does after seeding.
func servingPool(cfg *config.RuntimeConfig) *pool.Store {
	return pool.NewStore(cfg, pool.NewRoutes(cfg.AllRoutes(), cfg.CooldownBase, cfg.CooldownMax))
}

// routeState extracts one route's serving state by operator-facing id, or by
// host when the route is unnamed.
func routeState(t *testing.T, gen *pool.Generation, id string) pool.Status {
	t.Helper()
	for _, status := range gen.Pool.Snapshot() {
		if status.ID == id {
			return status
		}
	}
	t.Fatalf("no route carries id %q; snapshot is %+v", id, gen.Pool.Snapshot())
	return pool.Status{}
}

// The core invariant: a bad durable revision leaves the previous generation
// serving, byte for byte. Not a degraded pool, not the seed — the same one.
func TestReconcileLeavesThePreviousGenerationServingOnAnInvalidDocument(t *testing.T) {
	ctx := context.Background()
	good := mustConfig(t, `{
      "version": 1, "log-level": "info", "max-retries": 2,
      "cooldown": {"base": "15s", "max": "10m"}, "dial-timeout": "10s",
      "proxies": {"auto": [{"id": "egress-a", "proxy": "good.example:1080", "kind": "v4"}]}
    }`)
	generations := servingPool(good)
	before := generations.Load()

	store := newFakeStore()
	store.setActive(mustDocument(t, good), 7)
	reconciler := NewReconciler(store, generations, zerolog.Nop(), Options{})

	// A document that decodes structurally but violates every runtime rule the
	// file config enforces.
	for name, body := range map[string]string{
		"route with a scheme": `{"version":1,"log-level":"info","max-retries":2,
			"cooldown":{"base":"15s","max":"10m"},"dial-timeout":"10s",
			"proxies":{"auto":[{"id":"egress-a","proxy":"socks5://good.example:1080","kind":"v4"}]}}`,
		"zero port": `{"version":1,"log-level":"info","max-retries":2,
			"cooldown":{"base":"15s","max":"10m"},"dial-timeout":"10s",
			"proxies":{"auto":[{"id":"egress-a","proxy":"good.example:0","kind":"v4"}]}}`,
		"retired weight key": `{"version":1,"log-level":"info","max-retries":2,
			"cooldown":{"base":"15s","max":"10m"},"dial-timeout":"10s",
			"proxies":{"auto":[{"id":"egress-a","proxy":"good.example:1080","kind":"v4","weight":5}]}}`,
		"retired global block": `{"version":1,"global":{"target-tls-insecure":true},"log-level":"info","max-retries":2,
			"cooldown":{"base":"15s","max":"10m"},"dial-timeout":"10s",
			"proxies":{"auto":[{"id":"egress-a","proxy":"good.example:1080","kind":"v4"}]}}`,
		"bad kind": `{"version":1,"log-level":"info","max-retries":2,
			"cooldown":{"base":"15s","max":"10m"},"dial-timeout":"10s",
			"proxies":{"auto":[{"id":"egress-a","proxy":"good.example:1080","kind":"v5"}]}}`,
		"not json at all": `this is not a document`,
		"empty object":    `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			store.setActive(documentFor(t, body), 8)
			if err := reconciler.ReconcileOnce(ctx); err == nil {
				t.Fatal("ReconcileOnce accepted an invalid durable revision")
			}
			after := generations.Load()
			if after != before {
				t.Errorf("the serving generation was replaced by rejected revision %d", after.ConfigRevision)
			}
			if after.Config.LogLevel != "info" || len(after.Config.AllRoutes()) != 1 {
				t.Errorf("the serving configuration changed: %+v", after.Config)
			}
			if after.ConfigRevision != 0 {
				t.Errorf("ConfigRevision = %d, want 0 (still the boot-time seed)", after.ConfigRevision)
			}
		})
	}
}

// A document version this build does not implement is refused before its fields
// are read at all: a reader that skipped what it did not recognize would
// validate less than the writer did.
func TestReconcileRefusesAnUnknownDocumentVersion(t *testing.T) {
	ctx := context.Background()
	good := mustConfig(t, `{
      "version": 1, "log-level": "info", "max-retries": 2,
      "cooldown": {"base": "15s", "max": "10m"}, "dial-timeout": "10s",
      "proxies": {"auto": [{"id": "egress-a", "proxy": "good.example:1080", "kind": "v4"}]}
    }`)
	generations := servingPool(good)
	before := generations.Load()
	store := newFakeStore()
	reconciler := NewReconciler(store, generations, zerolog.Nop(), Options{})

	store.setActive(configstore.Document{
		Version: config.DocumentVersion + 1,
		JSON:    mustDocument(t, good).JSON,
	}, 9)
	err := reconciler.ReconcileOnce(ctx)
	if err == nil {
		t.Fatal("ReconcileOnce accepted a document newer than this build")
	}
	// The refusal is reported with the revision and the reason, not by wrapping
	// the sentinel: an operator reading the log needs to know which revision is
	// being refused and why, and the reason must not quote the document.
	if !strings.Contains(err.Error(), "durable revision 9") {
		t.Errorf("error %q does not name the refused revision", err)
	}
	if !strings.Contains(err.Error(), "unsupported config document version") {
		t.Errorf("error %q does not carry the underlying reason", err)
	}
	if generations.Load() != before {
		t.Error("a too-new document replaced the serving generation")
	}
}

// A store failure is reported, not published: the serving generation is
// untouched and the caller decides whether to retry.
func TestReconcileReportsAStoreFailureWithoutPublishing(t *testing.T) {
	ctx := context.Background()
	good := mustConfig(t, `{
      "version": 1, "log-level": "info", "max-retries": 2,
      "cooldown": {"base": "15s", "max": "10m"}, "dial-timeout": "10s",
      "proxies": {"auto": [{"id": "egress-a", "proxy": "good.example:1080", "kind": "v4"}]}
    }`)
	generations := servingPool(good)
	before := generations.Load()
	store := newFakeStore()
	reconciler := NewReconciler(store, generations, zerolog.Nop(), Options{})

	store.readErr = errors.New("connection refused")
	if err := reconciler.ReconcileOnce(ctx); err == nil {
		t.Fatal("ReconcileOnce reported success while the store was failing")
	}
	if generations.Load() != before {
		t.Error("a store failure replaced the serving generation")
	}
}

// An empty store is not an error: the seed generation is the correct thing to
// keep serving, and stopping proxying over it would be the wrong response.
func TestReconcileTreatsAnEmptyStoreAsNothingToDo(t *testing.T) {
	ctx := context.Background()
	good := mustConfig(t, `{
      "version": 1, "log-level": "info", "max-retries": 2,
      "cooldown": {"base": "15s", "max": "10m"}, "dial-timeout": "10s",
      "proxies": {"auto": [{"id": "egress-a", "proxy": "good.example:1080", "kind": "v4"}]}
    }`)
	generations := servingPool(good)
	before := generations.Load()
	reconciler := NewReconciler(newFakeStore(), generations, zerolog.Nop(), Options{})

	if err := reconciler.ReconcileOnce(ctx); err != nil {
		t.Fatalf("ReconcileOnce on an empty store: %v", err)
	}
	if generations.Load() != before {
		t.Error("an empty store disturbed the serving generation")
	}
}

// A valid revision publishes, and the generation records the revision it came
// from so /status can report it without querying the database.
func TestReconcilePublishesAValidRevisionAndRecordsIt(t *testing.T) {
	ctx := context.Background()
	seed := mustConfig(t, `{
      "version": 1, "log-level": "info", "max-retries": 2,
      "cooldown": {"base": "15s", "max": "10m"}, "dial-timeout": "10s",
      "proxies": {"auto": [{"id": "egress-a", "proxy": "good.example:1080", "kind": "v4"}]}
    }`)
	next := mustConfig(t, `{
      "version": 1, "log-level": "debug", "max-retries": 5,
      "cooldown": {"base": "15s", "max": "10m"}, "dial-timeout": "10s",
      "proxies": {"auto": [{"id": "egress-a", "proxy": "good.example:1080", "kind": "v4"}]}
    }`)
	generations := servingPool(seed)
	store := newFakeStore()
	store.setActive(mustDocument(t, next), 42)
	reconciler := NewReconciler(store, generations, zerolog.Nop(), Options{})

	if err := reconciler.ReconcileOnce(ctx); err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}
	gen := generations.Load()
	if gen.ConfigRevision != 42 {
		t.Errorf("ConfigRevision = %d, want 42", gen.ConfigRevision)
	}
	if gen.Config.LogLevel != "debug" || gen.Config.MaxRetries != 5 {
		t.Errorf("the revision did not take effect: %+v", gen.Config)
	}
}

// Re-reading an unchanged revision must not republish: the steady-state poll of
// a stable configuration costs one query and no generation churn.
func TestReconcileSkipsTheRevisionAlreadyServing(t *testing.T) {
	ctx := context.Background()
	cfg := mustConfig(t, `{
      "version": 1, "log-level": "info", "max-retries": 2,
      "cooldown": {"base": "15s", "max": "10m"}, "dial-timeout": "10s",
      "proxies": {"auto": [{"id": "egress-a", "proxy": "good.example:1080", "kind": "v4"}]}
    }`)
	generations := servingPool(cfg)
	store := newFakeStore()
	store.setActive(mustDocument(t, cfg), 11)
	reconciler := NewReconciler(store, generations, zerolog.Nop(), Options{})

	if err := reconciler.ReconcileOnce(ctx); err != nil {
		t.Fatalf("first ReconcileOnce: %v", err)
	}
	first := generations.Load()
	// Report a failure so a republish would be visible if one happened.
	first.Pool.ReportFailure(first.Pool.RoutePointers()[0], errors.New("dial failed"))

	for range 3 {
		if err := reconciler.ReconcileOnce(ctx); err != nil {
			t.Fatalf("ReconcileOnce on an unchanged revision: %v", err)
		}
	}
	if generations.Load() != first {
		t.Error("an unchanged revision republished a generation")
	}
}

// The invariant the coordinator called most at risk: existing state for an
// unchanged route identity survives a revision change. A rename of the
// operator-facing id is not a route change — identity is canonical URL, kind,
// and origin — so health must not reset.
func TestRouteStateSurvivesARevisionChange(t *testing.T) {
	ctx := context.Background()
	before := mustConfig(t, `{
      "version": 1, "log-level": "info", "max-retries": 2,
      "cooldown": {"base": "15s", "max": "10m"}, "dial-timeout": "10s",
      "proxies": {"auto": [
        {"id": "old-name", "proxy": "a.example:1080", "kind": "v4"},
        {"id": "doomed", "proxy": "gone.example:1080", "kind": "v4"}
      ]}
    }`)
	generations := servingPool(before)
	gen := generations.Load()

	// Give the surviving route a distinctive history, and poison the doomed one
	// so a reset would be visible.
	survivor, doomed := gen.Pool.RoutePointers()[0], gen.Pool.RoutePointers()[1]
	gen.Pool.ReportFailure(survivor, errors.New("dial failed"))
	gen.Pool.ReportFailure(survivor, errors.New("dial failed again"))
	gen.Pool.ReportSuccess(survivor, "target.example:443")
	gen.Pool.ReportTargetFailure(doomed, "blocked.example:443", errors.New("connect refused"))

	stateBefore := routeState(t, gen, "old-name")
	if stateBefore.ConsecutiveFailures == 0 && stateBefore.Successes == 0 && stateBefore.TargetFailures == 0 {
		t.Fatalf("the fixture did not produce any route state to preserve: %+v", stateBefore)
	}

	// The next revision renames the surviving route's id, drops the doomed one,
	// adds a route, and changes an unrelated setting. None of that is a change
	// to the surviving route's identity.
	after := mustConfig(t, `{
      "version": 1, "log-level": "warn", "max-retries": 2,
      "cooldown": {"base": "15s", "max": "10m"}, "dial-timeout": "10s",
      "proxies": {"auto": [
        {"id": "new-name", "proxy": "a.example:1080", "kind": "v4"},
        {"id": "fresh", "proxy": "b.example:1080", "kind": "v4"}
      ]}
    }`)
	store := newFakeStore()
	store.setActive(mustDocument(t, after), 2)
	reconciler := NewReconciler(store, generations, zerolog.Nop(), Options{})
	if err := reconciler.ReconcileOnce(ctx); err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}

	published := generations.Load()
	// The id is the operator's label, and the new revision's label is in force.
	stateAfter := routeState(t, published, "new-name")
	if stateAfter.ConsecutiveFailures != stateBefore.ConsecutiveFailures {
		t.Errorf("consecutive failures reset across a rename: %d then %d",
			stateBefore.ConsecutiveFailures, stateAfter.ConsecutiveFailures)
	}
	if stateAfter.Successes != stateBefore.Successes {
		t.Errorf("successes reset across a rename: %d then %d",
			stateBefore.Successes, stateAfter.Successes)
	}
	// The renamed route is the same Proxy object, not a rebuilt one: identity is
	// canonical URL+kind+origin, and the id is metadata.
	for _, p := range published.Pool.RoutePointers() {
		if p.URL.Host == "a.example:1080" && p != survivor {
			t.Error("the surviving route was rebuilt rather than retained")
		}
	}
	// The dropped route is gone, and the new one starts clean.
	if published.Pool.Size() != 2 {
		t.Errorf("pool size = %d, want 2", published.Pool.Size())
	}
	for _, status := range published.Pool.Snapshot() {
		if status.Proxy == "b.example:1080" && (status.Successes != 0 || status.Failures != 0) {
			t.Errorf("a newly added route inherited state: %+v", status)
		}
		if status.Proxy == "gone.example:1080" {
			t.Error("a removed route is still serving")
		}
	}
}

// The mirror image: changing a route's identity — its canonical URL — is a real
// change, and its old state must not follow it to the new endpoint.
func TestChangingARoutesIdentityStartsFreshState(t *testing.T) {
	ctx := context.Background()
	before := mustConfig(t, `{
      "version": 1, "log-level": "info", "max-retries": 2,
      "cooldown": {"base": "15s", "max": "10m"}, "dial-timeout": "10s",
      "proxies": {"auto": [{"id": "egress-a", "proxy": "a.example:1080", "kind": "v4"}]}
    }`)
	generations := servingPool(before)
	gen := generations.Load()
	gen.Pool.ReportFailure(gen.Pool.RoutePointers()[0], errors.New("dial failed"))
	gen.Pool.ReportFailure(gen.Pool.RoutePointers()[0], errors.New("dial failed again"))

	after := mustConfig(t, `{
      "version": 1, "log-level": "info", "max-retries": 2,
      "cooldown": {"base": "15s", "max": "10m"}, "dial-timeout": "10s",
      "proxies": {"auto": [{"id": "egress-a", "proxy": "other.example:1080", "kind": "v4"}]}
    }`)
	store := newFakeStore()
	store.setActive(mustDocument(t, after), 2)
	if err := NewReconciler(store, generations, zerolog.Nop(), Options{}).ReconcileOnce(ctx); err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}
	state := routeState(t, generations.Load(), "egress-a")
	if state.ConsecutiveFailures != 0 {
		t.Errorf("a new route inherited the old route's failure streak: %+v", state)
	}
}

// A change of egress kind is a change of identity too, even at the same
// endpoint: the provider-backed public address family is part of what a route
// is.
func TestChangingARoutesKindStartsFreshState(t *testing.T) {
	ctx := context.Background()
	before := mustConfig(t, `{
      "version": 1, "log-level": "info", "max-retries": 2,
      "cooldown": {"base": "15s", "max": "10m"}, "dial-timeout": "10s",
      "proxies": {"auto": [{"id": "egress-a", "proxy": "a.example:1080", "kind": "v4"}]}
    }`)
	generations := servingPool(before)
	generations.Load().Pool.ReportFailure(generations.Load().Pool.RoutePointers()[0], errors.New("dial failed"))

	after := mustConfig(t, `{
      "version": 1, "log-level": "info", "max-retries": 2,
      "cooldown": {"base": "15s", "max": "10m"}, "dial-timeout": "10s",
      "proxies": {"auto": [{"id": "egress-a", "proxy": "a.example:1080", "kind": "v6"}]}
    }`)
	store := newFakeStore()
	store.setActive(mustDocument(t, after), 2)
	if err := NewReconciler(store, generations, zerolog.Nop(), Options{}).ReconcileOnce(ctx); err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}
	if state := routeState(t, generations.Load(), "egress-a"); state.ConsecutiveFailures != 0 {
		t.Errorf("a kind change carried the old route's failure streak over: %+v", state)
	}
}

// The subscriber is a hook the process uses for the log level, so it must only
// ever see validated, published configurations — and never run while the
// single-writer gate is held, which would let a slow hook stall every later
// materialization.
func TestSubscribeSeesOnlyPublishedConfigurations(t *testing.T) {
	ctx := context.Background()
	seed := mustConfig(t, `{
      "version": 1, "log-level": "info", "max-retries": 2,
      "cooldown": {"base": "15s", "max": "10m"}, "dial-timeout": "10s",
      "proxies": {"auto": [{"id": "egress-a", "proxy": "good.example:1080", "kind": "v4"}]}
    }`)
	next := mustConfig(t, `{
      "version": 1, "log-level": "debug", "max-retries": 2,
      "cooldown": {"base": "15s", "max": "10m"}, "dial-timeout": "10s",
      "proxies": {"auto": [{"id": "egress-a", "proxy": "good.example:1080", "kind": "v4"}]}
    }`)
	generations := servingPool(seed)
	store := newFakeStore()
	reconciler := NewReconciler(store, generations, zerolog.Nop(), Options{})

	var seen []string
	reconciler.Subscribe(func(cfg *config.RuntimeConfig) { seen = append(seen, cfg.LogLevel) })

	// A rejected revision must not reach the subscriber.
	store.setActive(documentFor(t, `{"version":1,"log-level":"error","max-retries":0,
		"cooldown":{"base":"15s","max":"10m"},"dial-timeout":"10s",
		"proxies":{"auto":[{"id":"egress-a","proxy":"good.example:1080","kind":"v4"}]}}`), 3)
	if err := reconciler.ReconcileOnce(ctx); err == nil {
		t.Fatal("an invalid revision was accepted")
	}
	if len(seen) != 0 {
		t.Fatalf("the subscriber saw %v for a rejected revision", seen)
	}

	store.setActive(mustDocument(t, next), 4)
	if err := reconciler.ReconcileOnce(ctx); err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}
	if len(seen) != 1 || seen[0] != "debug" {
		t.Errorf("subscriber saw %v, want [debug]", seen)
	}

	// A nil callback clears the hook rather than leaving a stale one behind.
	reconciler.Subscribe(nil)
	store.setActive(mustDocument(t, seed), 5)
	if err := reconciler.ReconcileOnce(ctx); err != nil {
		t.Fatalf("ReconcileOnce after clearing the hook: %v", err)
	}
	if len(seen) != 1 {
		t.Errorf("subscriber ran after being cleared: %v", seen)
	}
}

// The single-writer gate covers the whole read-validate-build-publish sequence.
// A control-plane Apply and a local reconcile therefore cannot interleave a read
// of one revision with a publication of another and leave the serving
// generation behind the store.
func TestApplyHoldsTheSingleWriterGateAcrossTheSequence(t *testing.T) {
	ctx := context.Background()
	cfg := mustConfig(t, seedFixture)
	generations := servingPool(cfg)
	reconciler := NewReconciler(newFakeStore(), generations, zerolog.Nop(), Options{})

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	reconciler.Subscribe(func(*config.RuntimeConfig) {
		entered <- struct{}{}
		<-release
	})

	// The first Apply is parked inside its publication, still holding the gate.
	first := make(chan error, 1)
	go func() { first <- reconciler.Apply(ctx, mustDocument(t, cfg), 1) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the subscriber was never invoked")
	}

	// A second Apply must not get past the gate while the first holds it.
	second := make(chan error, 1)
	go func() { second <- reconciler.Apply(ctx, mustDocument(t, cfg), 2) }()
	select {
	case err := <-second:
		close(release)
		<-first
		t.Fatalf("the second Apply returned %v while the first still held the gate", err)
	case <-time.After(200 * time.Millisecond):
	}

	close(release)
	for name, ch := range map[string]chan error{"first": first, "second": second} {
		select {
		case err := <-ch:
			if err != nil {
				t.Errorf("the %s Apply failed: %v", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("the %s Apply never returned", name)
		}
	}
	// Both applied, so the serving generation is the later one: the gate
	// serialized them rather than letting either overwrite the other's read.
	if got := generations.Load().ConfigRevision; got != 2 {
		t.Errorf("the serving generation reports revision %d, want 2", got)
	}
}

// Seed is the bootstrap path: it commits the first revision only into an empty
// store, and a store that already has a revision is converged on rather than
// overwritten.
func TestSeedCommitsTheFirstRevisionOnly(t *testing.T) {
	ctx := context.Background()
	local := mustConfig(t, `{
      "version": 1, "log-level": "info", "max-retries": 2,
      "cooldown": {"base": "15s", "max": "10m"}, "dial-timeout": "10s",
      "proxies": {"auto": [{"id": "local", "proxy": "local.example:1080", "kind": "v4"}]}
    }`)
	store := newFakeStore()
	generations := servingPool(local)
	reconciler := NewReconciler(store, generations, zerolog.Nop(), Options{})

	revision, err := reconciler.Seed(ctx, local)
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if !revision.IsValid() {
		t.Fatal("Seed committed no revision")
	}
	if len(store.committed) != 1 {
		t.Errorf("Seed committed %d revisions, want 1", len(store.committed))
	}
	if got := generations.Load().ConfigRevision; got != int64(revision) {
		t.Errorf("the seeded generation reports revision %d, want %d", got, revision)
	}

	// A second Seed against a store that now has a revision must not append:
	// restarting must not grow history on every boot.
	if _, err := reconciler.Seed(ctx, local); err != nil {
		t.Fatalf("second Seed: %v", err)
	}
	if len(store.committed) != 1 {
		t.Errorf("a repeated Seed appended history: %d revisions", len(store.committed))
	}
}

// A store another instance already seeded is an authority this instance must
// follow, not overwrite: its local file is not allowed to win.
func TestSeedConvergesOnAnExistingRevisionInsteadOfOverwritingIt(t *testing.T) {
	ctx := context.Background()
	local := mustConfig(t, `{
      "version": 1, "log-level": "info", "max-retries": 2,
      "cooldown": {"base": "15s", "max": "10m"}, "dial-timeout": "10s",
      "proxies": {"auto": [{"id": "local", "proxy": "local.example:1080", "kind": "v4"}]}
    }`)
	cluster := mustConfig(t, `{
      "version": 1, "log-level": "debug", "max-retries": 4,
      "cooldown": {"base": "15s", "max": "10m"}, "dial-timeout": "10s",
      "proxies": {"auto": [{"id": "cluster", "proxy": "cluster.example:1080", "kind": "v4"}]}
    }`)
	store := newFakeStore()
	store.setActive(mustDocument(t, cluster), 100)
	generations := servingPool(local)
	reconciler := NewReconciler(store, generations, zerolog.Nop(), Options{})

	revision, err := reconciler.Seed(ctx, local)
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if revision != 100 {
		t.Errorf("Seed returned revision %s, want the store's existing revision-100", revision)
	}
	if len(store.committed) != 0 {
		t.Errorf("Seed appended %d revisions to a store that already had one", len(store.committed))
	}
	gen := generations.Load()
	if gen.ConfigRevision != 100 || gen.Config.LogLevel != "debug" {
		t.Errorf("the local file overwrote the cluster revision: %+v", gen.Config)
	}
}

// Seeding nil is a programming error, not a recoverable condition.
func TestSeedRejectsNil(t *testing.T) {
	reconciler := NewReconciler(newFakeStore(), servingPool(mustConfig(t, seedFixture)), zerolog.Nop(), Options{})
	if _, err := reconciler.Seed(context.Background(), nil); err == nil {
		t.Fatal("Seed(nil) succeeded; want an error")
	}
}

const seedFixture = `{
  "version": 1, "log-level": "info", "max-retries": 2,
  "cooldown": {"base": "15s", "max": "10m"}, "dial-timeout": "10s",
  "proxies": {"auto": [{"id": "egress-a", "proxy": "good.example:1080", "kind": "v4"}]}
}`

// NewReconciler refuses inputs that would make it silently inert: a reconciler
// that cannot read, or cannot publish, must fail loudly at construction.
func TestNewReconcilerRejectsNilDependencies(t *testing.T) {
	generations := servingPool(mustConfig(t, seedFixture))
	for name, build := range map[string]func() *Reconciler{
		"nil store": func() *Reconciler {
			return NewReconciler(nil, generations, zerolog.Nop(), Options{})
		},
		"nil generation store": func() *Reconciler {
			return NewReconciler(newFakeStore(), nil, zerolog.Nop(), Options{})
		},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("NewReconciler accepted a nil dependency")
				}
			}()
			_ = build()
		})
	}
}

// Backoff grows on repeated failure, resets after a success, and is capped —
// the property that keeps a persistently invalid document from flooding the log
// every second while still converging eventually.
func TestNextBackoffGrowsResetsAndCaps(t *testing.T) {
	if got := nextBackoff(0); got != initialBackoff {
		t.Errorf("nextBackoff(0) = %s, want %s", got, initialBackoff)
	}
	previous := nextBackoff(0)
	for range 20 {
		got := nextBackoff(previous)
		if got < previous {
			t.Fatalf("backoff shrank: %s then %s", previous, got)
		}
		if got > maxBackoff {
			t.Fatalf("backoff exceeded the ceiling: %s > %s", got, maxBackoff)
		}
		previous = got
	}
	if previous != maxBackoff {
		t.Errorf("backoff settled at %s, want the ceiling %s", previous, maxBackoff)
	}
}

// Run reconciles until cancelled, and its immediate first pass means a fresh
// start does not serve the seed for a whole interval after the store already
// holds a newer revision.
func TestRunAppliesImmediatelyAndStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cfg := mustConfig(t, seedFixture)
	store := newFakeStore()
	store.setActive(mustDocument(t, cfg), 77)
	generations := servingPool(cfg)

	reconciler := NewReconciler(store, generations, zerolog.Nop(), Options{Interval: time.Hour})
	// A short interval so cancellation, not the ticker, ends the loop.
	reconciler.interval = 5 * time.Millisecond
	done := make(chan struct{})
	go func() {
		defer close(done)
		reconciler.Run(ctx)
	}()

	deadline := time.After(5 * time.Second)
	for generations.Load().ConfigRevision != 77 {
		select {
		case <-deadline:
			t.Fatal("Run did not apply the active revision")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}

// Run keeps retrying a failing reconciliation rather than giving up, and stops
// promptly when the context is cancelled — a wedged store must not turn into a
// process that cannot shut down.
func TestRunRetriesAndStillStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	store := newFakeStore()
	store.readErr = errors.New("connection refused")
	generations := servingPool(mustConfig(t, seedFixture))
	reconciler := NewReconciler(store, generations, zerolog.Nop(), Options{})
	reconciler.interval = time.Millisecond

	done := make(chan struct{})
	go func() {
		defer close(done)
		reconciler.Run(ctx)
	}()
	// Wait for a second attempt rather than sleeping a fixed interval: the first
	// pass fails immediately, so the retry follows one backoff tick, and a slow
	// machine must not make this flaky.
	deadline := time.After(5 * time.Second)
	for store.readAttempts() < 2 {
		select {
		case <-deadline:
			t.Fatal("Run did not retry against a failing store")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return while the store was failing")
	}
	if attempts := store.readAttempts(); attempts < 2 {
		t.Errorf("Run made %d attempts against a failing store; it must keep retrying", attempts)
	}
}

// Concurrent Applies must serialize: two callers materializing different
// revisions cannot interleave a read of one with a publication of another, or the
// serving generation would end up behind the store.
func TestConcurrentAppliesLeaveTheServingGenerationConsistent(t *testing.T) {
	ctx := context.Background()
	cfgA := mustConfig(t, seedFixture)
	cfgB := mustConfig(t, `{
      "version": 1, "log-level": "debug", "max-retries": 9,
      "cooldown": {"base": "15s", "max": "10m"}, "dial-timeout": "10s",
      "proxies": {"auto": [{"id": "egress-a", "proxy": "good.example:1080", "kind": "v4"}]}
    }`)
	generations := servingPool(cfgA)
	reconciler := NewReconciler(newFakeStore(), generations, zerolog.Nop(), Options{})

	const callers = 8
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			doc := mustDocument(t, cfgA)
			revision := configstore.Revision(i + 1)
			if i%2 == 0 {
				doc = mustDocument(t, cfgB)
				revision = configstore.Revision(100 + i)
			}
			if err := reconciler.Apply(ctx, doc, revision); err != nil {
				t.Errorf("Apply: %v", err)
			}
		}(i)
	}
	wg.Wait()

	gen := generations.Load()
	// Whichever caller won, the generation is internally consistent: the
	// revision reported is one that was applied and the configuration serving is
	// the one that revision carried. That is the property the gate exists to
	// keep — never a revision number describing a different configuration.
	switch gen.ConfigRevision {
	case 100, 102, 104, 106:
		if gen.Config.MaxRetries != 9 {
			t.Errorf("revision %d serves max-retries %d, want 9", gen.ConfigRevision, gen.Config.MaxRetries)
		}
	case 2, 4, 6, 8:
		if gen.Config.MaxRetries != 2 {
			t.Errorf("revision %d serves max-retries %d, want 2", gen.ConfigRevision, gen.Config.MaxRetries)
		}
	default:
		t.Errorf("the serving generation reports revision %d, which was never applied", gen.ConfigRevision)
	}
	if gen.Pool.Size() != 1 {
		t.Errorf("the published generation has %d routes, want 1", gen.Pool.Size())
	}
}
