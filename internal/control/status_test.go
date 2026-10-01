package control

import (
	"context"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/configstore"
	"rotation-proxy-gateway/internal/pool"

	"github.com/rs/zerolog"
)

// ObservedRevision is the cached half of the three-scope /status split. It must
// answer what the reconciler last saw the durable pointer name without converting
// every unauthenticated status request into a database query. These tests hold
// the useful edge cases: a revision that cannot materialize is still the active
// pointer, while a failed read is not an observation at all.

func newStatusReconciler(t *testing.T, store *fakeStore) *Reconciler {
	t.Helper()
	cfg := &config.RuntimeConfig{
		MaxRetries:   1,
		DialTimeout:  time.Second,
		CooldownBase: time.Second,
		CooldownMax:  time.Minute,
	}
	generations := pool.NewStore(cfg, pool.NewRoutes(nil, cfg.CooldownBase, cfg.CooldownMax))
	return NewReconciler(store, generations, zerolog.Nop(), Options{})
}

func TestObservedRevisionTracksTheDurablePointerBeforeMaterialization(t *testing.T) {
	store := newFakeStore()
	// A document this binary refuses represents the interesting convergence
	// window: the durable pointer moved, but this replica correctly kept its old
	// generation. /status must expose both facts rather than hiding the new
	// pointer behind a stale "synced" assertion.
	store.setActive(configstore.Document{Version: config.DocumentVersion + 1, JSON: []byte(`{"version":2}`)}, 19)
	reconciler := newStatusReconciler(t, store)

	if err := reconciler.ReconcileOnce(context.Background()); err == nil {
		t.Fatal("ReconcileOnce accepted a document from a newer version")
	}
	if got := reconciler.ObservedRevision(); got != 19 {
		t.Errorf("ObservedRevision = %d, want the durable pointer 19 despite rejection", got)
	}
}

func TestObservedRevisionIsZeroForAnEmptyDurableStore(t *testing.T) {
	store := newFakeStore()
	reconciler := newStatusReconciler(t, store)

	if err := reconciler.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("ReconcileOnce on an empty store: %v", err)
	}
	if got := reconciler.ObservedRevision(); got != 0 {
		t.Errorf("ObservedRevision = %d, want zero with no active durable revision", got)
	}
}

func TestObservedRevisionPreservesTheLastKnownPointerAcrossAReadFailure(t *testing.T) {
	store := newFakeStore()
	cfg := mustConfig(t, `{
		"version": 1, "log-level": "info", "max-retries": 1,
		"cooldown": {"base": "1s", "max": "1m"}, "dial-timeout": "1s",
		"proxies": {"auto": [{"proxy": "route.test:1080", "kind": "v4"}]}
	}`)
	store.setActive(mustDocument(t, cfg), 7)
	reconciler := newStatusReconciler(t, store)
	if err := reconciler.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}

	store.mu.Lock()
	store.readErr = context.DeadlineExceeded
	store.mu.Unlock()
	if err := reconciler.ReconcileOnce(context.Background()); err == nil {
		t.Fatal("ReconcileOnce succeeded despite a store read failure")
	}
	if got := reconciler.ObservedRevision(); got != 7 {
		t.Errorf("ObservedRevision = %d after a failed read, want the last known pointer 7", got)
	}
}
