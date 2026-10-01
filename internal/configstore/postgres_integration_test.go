package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests run against a real PostgreSQL. They are skipped, loudly, when
// RPGW_TEST_CONFIG_STORE_DSN is unset — a store test faked against a stub would
// assert that the stub is correct, which is the one thing it cannot be.
//
// Each test gets its own schema inside the database, so the suite never
// collides with itself and never touches the migrations another test already
// applied. The DSN is read from the environment and never printed: it carries
// the database password.

// testDSN returns the DSN for the integration suite, skipping the test when it
// is absent.
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("RPGW_TEST_CONFIG_STORE_DSN")
	if strings.TrimSpace(dsn) == "" {
		t.Skip("RPGW_TEST_CONFIG_STORE_DSN is unset; skipping the live-PostgreSQL config store test")
	}
	return dsn
}

// isolatedStore returns a migrated store living in its own PostgreSQL schema,
// which is dropped when the test ends.
//
// Per-test isolation is not tidiness: several of these tests deliberately corrupt
// the store's own bookkeeping — a tampered migration checksum, a fabricated
// future schema version — to prove the migrator refuses to work around them.
// Sharing one schema would let such a test leave the damage behind for every
// test that runs after it, so a refusal could be observed as a pass-through.
// Each test gets a schema of its own and takes it with it when it finishes.
//
// The schema name is derived from the test name and sanitized as an SQL
// identifier; no part of it is ever assembled into a statement by hand.
func isolatedStore(t *testing.T) Repository {
	t.Helper()
	schema := createTestSchema(t)
	store, err := openInSchema(context.Background(), schema)
	if err != nil {
		t.Fatalf("open an isolated store: %v", err)
	}
	t.Cleanup(store.Close)
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return store
}

// pinnedSchema creates a schema for the test and returns its name, for the one
// test that needs several stores to converge on the same one.
func pinnedSchema(t *testing.T) string {
	t.Helper()
	return createTestSchema(t)
}

// openInSchema opens a store whose unqualified statements resolve inside schema.
func openInSchema(ctx context.Context, schema string) (Repository, error) {
	// Pinning the search path keeps every production statement exactly as it
	// ships: the repository's own SQL stays unqualified and resolves inside the
	// test's schema, rather than being rewritten for the test's benefit.
	cfg, err := pgxpool.ParseConfig(testDSNContext(ctx))
	if err != nil {
		return nil, err
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	return openPool(ctx, cfg)
}

// createTestSchema creates a schema named after the test and schedules its
// removal.
func createTestSchema(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	base, err := NewPostgres(ctx, testDSN(t))
	if err != nil {
		t.Fatalf("NewPostgres: %v", err)
	}
	defer base.Close()

	schema := pgx.Identifier{"cfgstore_" + strings.Map(sanitizeIdent, t.Name())}.Sanitize()
	if _, err := base.(*pgRepository).pool.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create the test schema: %v", err)
	}
	t.Cleanup(func() {
		dropper, err := NewPostgres(context.Background(), testDSN(t))
		if err != nil {
			t.Logf("reopening to drop the test schema: %v", err)
			return
		}
		defer dropper.Close()
		if _, err := dropper.(*pgRepository).pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`); err != nil {
			t.Logf("dropping the test schema: %v", err)
		}
	})
	return schema
}

// testDSNContext is the DSN for helpers that open stores outside a test body,
// where skipping is not available.
func testDSNContext(context.Context) string { return os.Getenv("RPGW_TEST_CONFIG_STORE_DSN") }

// sanitizeIdent maps a test name to a legal, lowercase SQL identifier fragment.
func sanitizeIdent(r rune) rune {
	switch {
	case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return r
	case r >= 'A' && r <= 'Z':
		return r + ('a' - 'A')
	default:
		return '_'
	}
}

// exec runs a statement against the test's store. The statements below are
// written here, in the test, rather than in the repository: they set up the
// corrupt states the refusals are proved against.
func exec(t *testing.T, store Repository, sql string, args ...any) {
	t.Helper()
	if _, err := store.(*pgRepository).pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("test statement failed: %v", err)
	}
}

// queryInt runs a query returning one integer.
func queryInt(t *testing.T, store Repository, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := store.(*pgRepository).pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("test query failed: %v", err)
	}
	return n
}

// validDocument builds a minimal document through the real encoder, so the
// bytes under test are the ones a writer would actually commit.
func validDocument(t *testing.T) (Document, error) {
	t.Helper()
	cfg, err := config.DecodeDocument([]byte(`{
      "version": 1,
      "log-level": "info",
      "max-retries": 2,
      "cooldown": {"base": "15s", "max": "10m"},
      "dial-timeout": "10s",
      "proxies": {"auto": [{"id": "egress-a", "proxy": "provider.example:1080", "kind": "v4"}]}
    }`))
	if err != nil {
		return Document{}, err
	}
	return NewDocument(cfg)
}

// docWithLogLevel builds a document whose only difference is one setting, so a
// test can tell two revisions apart without disturbing anything else.
func docWithLogLevel(t *testing.T, level string) Document {
	t.Helper()
	cfg, err := config.DecodeDocument([]byte(fmt.Sprintf(`{
      "version": 1,
      "log-level": %q,
      "max-retries": 2,
      "cooldown": {"base": "15s", "max": "10m"},
      "dial-timeout": "10s",
      "proxies": {"auto": [{"id": "egress-a", "proxy": "provider.example:1080", "kind": "v4"}]}
    }`, level)))
	if err != nil {
		t.Fatalf("building a document: %v", err)
	}
	doc, err := NewDocument(cfg)
	if err != nil {
		t.Fatalf("encoding a document: %v", err)
	}
	return doc
}

// The migration is the boot gate: it must be safe to run twice, and running it
// twice must not disturb committed data.
func TestMigrateIsIdempotent(t *testing.T) {
	store := isolatedStore(t)
	ctx := context.Background()

	first, err := store.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if first == 0 {
		t.Fatal("SchemaVersion = 0 after a successful migration")
	}
	for i := range 3 {
		if err := store.Migrate(ctx); err != nil {
			t.Fatalf("re-running Migrate (attempt %d): %v", i+2, err)
		}
	}
	again, err := store.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion after re-runs: %v", err)
	}
	if again != first {
		t.Errorf("schema version moved on a re-run: %d then %d", first, again)
	}

	// Data committed between the runs survives them, which is the property that
	// makes a re-run safe on a live database.
	doc, err := validDocument(t)
	if err != nil {
		t.Fatalf("building a document: %v", err)
	}
	if _, err := store.Commit(ctx, NoRevision, doc, Meta{Author: "tester"}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate after a commit: %v", err)
	}
	active, err := store.Active(ctx)
	if err != nil {
		t.Fatalf("Active after a re-run: %v", err)
	}
	if !active.Revision.IsValid() {
		t.Error("the re-run dropped the active revision")
	}
}

// Concurrent instances must converge on one schema rather than racing DDL. The
// advisory lock is what makes this safe, so the test runs several at once.
func TestMigrateConcurrentlyConverges(t *testing.T) {
	ctx := context.Background()
	schema := pinnedSchema(t)

	// A fresh store per goroutine: each opens its own pool, so each acquires the
	// advisory lock on its own session the way separate processes would. They
	// share one schema, because converging on one schema is the property under
	// test — four instances racing to create the same tables.
	const instances = 4
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		failures []error
	)
	for range instances {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store, err := openInSchema(ctx, schema)
			if err != nil {
				mu.Lock()
				failures = append(failures, fmt.Errorf("open: %w", err))
				mu.Unlock()
				return
			}
			defer store.Close()
			if err := store.Migrate(ctx); err != nil {
				mu.Lock()
				failures = append(failures, fmt.Errorf("migrate: %w", err))
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(failures) > 0 {
		t.Fatalf("concurrent Migrate calls failed: %v", failures)
	}
}

// A migration whose recorded checksum differs from the embedded copy has been
// edited after it ran. Refusing is the point: re-running the new text would
// apply different DDL than the database actually received.
func TestMigrateRefusesAnEditedMigration(t *testing.T) {
	ctx := context.Background()
	store := isolatedStore(t)

	// Rewrite the recorded checksum for the version this build carries, which is
	// exactly the state an edited migration file leaves behind.
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	original := migrations[0].Checksum
	tampered := "0000000000000000000000000000000000000000000000000000000000000000"
	exec(t, store, `UPDATE schema_migrations SET checksum = $1 WHERE version = $2`,
		tampered, migrations[0].Version)
	err = store.Migrate(ctx)
	if err == nil {
		t.Fatal("Migrate accepted a migration whose checksum changed; want refusal")
	}
	if !errors.Is(err, ErrSchemaMismatch) {
		t.Errorf("error %v is not ErrSchemaMismatch", err)
	}
	if !strings.Contains(err.Error(), "was applied with checksum") {
		t.Errorf("error %q does not explain the checksum mismatch", err)
	}
	// The refusal must not have touched the data.
	if _, err := store.SchemaVersion(ctx); err != nil {
		t.Fatalf("SchemaVersion after the refusal: %v", err)
	}
	// schema_migrations records what this build's migrations did to the
	// database, so it is deliberately shared rather than per-test schema; the
	// recorded checksum is therefore restored byte-for-byte, leaving the ledger
	// exactly as it was found.
	t.Cleanup(func() {
		restorer, err := NewPostgres(context.Background(), testDSN(t))
		if err != nil {
			t.Logf("reopening to restore the migration ledger: %v", err)
			return
		}
		defer restorer.Close()
		if _, err := restorer.(*pgRepository).pool.Exec(context.Background(),
			`UPDATE schema_migrations SET checksum = $1 WHERE version = $2`,
			original, migrations[0].Version,
		); err != nil {
			t.Errorf("restoring the recorded migration checksum: %v", err)
		}
	})
}

// A database ahead of the binary has rows this build cannot interpret. Startup
// must fail rather than proceed against a schema read on a guess.
func TestMigrateRefusesAnUnknownFutureSchemaVersion(t *testing.T) {
	ctx := context.Background()
	store := isolatedStore(t)

	// A version higher than any embedded migration, recorded as if a newer
	// instance had applied it.
	exec(t, store,
		`INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`,
		9999, "from_the_future", "0000000000000000000000000000000000000000000000000000000000000000")
	// Removed again for the same reason as the checksum above: the ledger is
	// shared, and a fabricated row must not outlive the test that made it.
	t.Cleanup(func() {
		restorer, err := NewPostgres(context.Background(), testDSN(t))
		if err != nil {
			t.Logf("reopening to restore the migration ledger: %v", err)
			return
		}
		defer restorer.Close()
		if _, err := restorer.(*pgRepository).pool.Exec(context.Background(),
			`DELETE FROM schema_migrations WHERE version = $1`, 9999); err != nil {
			t.Errorf("removing the fabricated schema version: %v", err)
		}
	})
	err := store.Migrate(ctx)
	if err == nil {
		t.Fatal("Migrate accepted a database at a newer schema version; want refusal")
	}
	if !errors.Is(err, ErrSchemaMismatch) {
		t.Errorf("error %v is not ErrSchemaMismatch", err)
	}
	if !strings.Contains(err.Error(), "upgrade the gateway") {
		t.Errorf("error %q does not say what to do about it", err)
	}
}

// The pointer is the authority. Commit with no expectation is the first write,
// and it must both append and become active in one transaction.
func TestCommitActivatesFromAnEmptyStore(t *testing.T) {
	store := isolatedStore(t)
	ctx := context.Background()

	// Nothing committed yet: Active reports the absence, not a zero revision.
	if _, err := store.Active(ctx); !errors.Is(err, ErrNoActiveRevision) {
		t.Errorf("Active on an empty store = %v, want ErrNoActiveRevision", err)
	}
	doc, err := validDocument(t)
	if err != nil {
		t.Fatalf("building a document: %v", err)
	}
	record, err := store.Commit(ctx, NoRevision, doc, Meta{Author: "operator", Note: "first"})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if !record.Revision.IsValid() {
		t.Fatal("the first commit returned no revision")
	}
	if record.DocVersion != doc.Version {
		t.Errorf("DocVersion = %d, want %d", record.DocVersion, doc.Version)
	}
	active, err := store.Active(ctx)
	if err != nil {
		t.Fatalf("Active after the first commit: %v", err)
	}
	if active.Revision != record.Revision {
		t.Errorf("active revision = %s, want %s", active.Revision, record.Revision)
	}
	assertSameDocument(t, doc.JSON, active.Document)
	// The attribution comes back as written; it is free text, not a secret store.
	if active.Author != "operator" || active.Note != "first" {
		t.Errorf("attribution = %q/%q, want operator/first", active.Author, active.Note)
	}
	if active.PointerUpdated.IsZero() {
		t.Error("PointerUpdated is the zero time; a caller cannot tell a pointer move from no move")
	}
}

// The optimistic-concurrency primitive: a writer whose expectation is stale is
// rejected atomically, appending nothing.
func TestCommitRejectsAStaleExpectationAtomically(t *testing.T) {
	store := isolatedStore(t)
	ctx := context.Background()

	first, err := validDocument(t)
	if err != nil {
		t.Fatalf("building a document: %v", err)
	}
	firstRecord, err := store.Commit(ctx, NoRevision, first, Meta{})
	if err != nil {
		t.Fatalf("first Commit: %v", err)
	}
	second := docWithLogLevel(t, "debug")
	secondRecord, err := store.Commit(ctx, firstRecord.Revision, second, Meta{})
	if err != nil {
		t.Fatalf("second Commit: %v", err)
	}

	// The first writer now holds a stale expectation.
	stale := docWithLogLevel(t, "warn")
	_, err = store.Commit(ctx, firstRecord.Revision, stale, Meta{Author: "stale-writer"})
	if !errors.Is(err, ErrRevisionMismatch) {
		t.Fatalf("a stale Commit returned %v, want ErrRevisionMismatch", err)
	}
	// Atomic means atomic: the rejected transaction's insert rolled back with
	// its pointer move, so the history has no trace of it.
	active, err := store.Active(ctx)
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if active.Revision != secondRecord.Revision {
		t.Errorf("active revision = %s after a rejected write, want %s", active.Revision, secondRecord.Revision)
	}
	if _, err := store.Get(ctx, secondRecord.Revision+1); !errors.Is(err, ErrNoRevision) {
		t.Errorf("the rejected write left revision %s behind: %v", secondRecord.Revision+1, err)
	}
	// And a history read confirms only the two committed revisions exist.
	if count := queryInt(t, store, `SELECT count(*) FROM config_revisions`); count != 2 {
		t.Errorf("history holds %d revisions, want 2", count)
	}
}

// Two writers that both believe revision N is active must not both win. Exactly
// one commits; the other is rejected, and the rejection is decided in SQL, so
// there is no read-then-write window for either to slip through.
func TestConcurrentWritersFromTheSameExpectationCannotBothWin(t *testing.T) {
	store := isolatedStore(t)
	ctx := context.Background()

	base, err := validDocument(t)
	if err != nil {
		t.Fatalf("building a document: %v", err)
	}
	baseRecord, err := store.Commit(ctx, NoRevision, base, Meta{})
	if err != nil {
		t.Fatalf("seeding the store: %v", err)
	}

	// Both writers start from the same expectation, which is the whole point:
	// neither has re-read the pointer between deciding and writing.
	const writers = 6
	type outcome struct {
		record Record
		err    error
	}
	results := make([]outcome, writers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			doc := docWithLogLevel(t, []string{"debug", "warn", "error"}[i%3])
			<-start
			record, err := store.Commit(ctx, baseRecord.Revision, doc, Meta{Author: fmt.Sprintf("writer-%d", i)})
			results[i] = outcome{record: record, err: err}
		}(i)
	}
	close(start)
	wg.Wait()

	wins, conflicts := 0, 0
	for i, result := range results {
		switch {
		case result.err == nil:
			wins++
			if !result.record.Revision.IsValid() {
				t.Errorf("writer %d won without a revision", i)
			}
		case errors.Is(result.err, ErrRevisionMismatch):
			conflicts++
		default:
			t.Errorf("writer %d failed with an unexpected error: %v", i, result.err)
		}
	}
	if wins != 1 {
		t.Errorf("%d writers committed from the same expectation; exactly 1 must win", wins)
	}
	if wins+conflicts != writers {
		t.Errorf("%d wins + %d conflicts != %d writers", wins, conflicts, writers)
	}

	// The pointer names the single winner, and the history holds exactly the two
	// revisions that were actually committed.
	active, err := store.Active(ctx)
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if !active.Revision.IsValid() {
		t.Fatal("no active revision after the race")
	}
	if count := queryInt(t, store, `SELECT count(*) FROM config_revisions`); count != 2 {
		t.Errorf("history holds %d revisions, want 2 (the seed and one winner)", count)
	}
}

// History is append-only, so a superseded revision is still readable: that is
// what makes the pointer a rollback rather than a rewrite.
func TestGetReadsHistoryAndActivateRollsBack(t *testing.T) {
	store := isolatedStore(t)
	ctx := context.Background()

	base, err := validDocument(t)
	if err != nil {
		t.Fatalf("building a document: %v", err)
	}
	firstRecord, err := store.Commit(ctx, NoRevision, base, Meta{})
	if err != nil {
		t.Fatalf("first Commit: %v", err)
	}
	secondRecord, err := store.Commit(ctx, firstRecord.Revision, docWithLogLevel(t, "debug"), Meta{})
	if err != nil {
		t.Fatalf("second Commit: %v", err)
	}

	// The superseded revision is still readable, with its original document.
	superseded, err := store.Get(ctx, firstRecord.Revision)
	if err != nil {
		t.Fatalf("Get on a superseded revision: %v", err)
	}
	if superseded.Revision != firstRecord.Revision {
		t.Errorf("Get returned revision %s, want %s", superseded.Revision, firstRecord.Revision)
	}
	assertSameDocument(t, base.JSON, superseded.Document)

	// A rollback under a stale expectation is refused like any other write: the
	// pointer names the second revision, so expecting the first is stale.
	if err := store.Activate(ctx, firstRecord.Revision, secondRecord.Revision); !errors.Is(err, ErrRevisionMismatch) {
		t.Errorf("Activate with a stale expectation = %v, want ErrRevisionMismatch", err)
	}

	// Rolling back is a pointer move, guarded by the same expectation.
	if err := store.Activate(ctx, secondRecord.Revision, firstRecord.Revision); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	active, err := store.Active(ctx)
	if err != nil {
		t.Fatalf("Active after rollback: %v", err)
	}
	if active.Revision != firstRecord.Revision {
		t.Errorf("active revision = %s after rollback, want %s", active.Revision, firstRecord.Revision)
	}
	assertSameDocument(t, base.JSON, active.Document)
}

// assertSameDocument compares two documents by value.
//
// The column is jsonb, so what comes back is PostgreSQL's canonical rendering of
// the JSON value — whitespace normalized, object keys reordered — rather than
// the bytes that were submitted. That is the column earning its keep (the
// database validates the document is JSON at all, and cannot store an unbounded
// blob of anything else), and nothing depends on byte equality: the decoder is
// order-insensitive, so a document that decodes to the same configuration is
// the same document. The bytes written are therefore not asserted equal to the
// bytes read; the values are.
func assertSameDocument(t *testing.T, want, got []byte) {
	t.Helper()
	var wantValue, gotValue any
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatalf("the written document is not JSON: %v", err)
	}
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("the read-back document is not JSON: %v", err)
	}
	if !reflect.DeepEqual(wantValue, gotValue) {
		t.Errorf("document changed across the store:\n wrote: %s\n  read: %s", want, got)
	}
}

// The foreign key is what makes a dangling pointer impossible; the store turns
// the violation into its own error rather than leaking a constraint name.
func TestActivateRefusesAnUncommittedTarget(t *testing.T) {
	store := isolatedStore(t)
	ctx := context.Background()

	base, err := validDocument(t)
	if err != nil {
		t.Fatalf("building a document: %v", err)
	}
	record, err := store.Commit(ctx, NoRevision, base, Meta{})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	err = store.Activate(ctx, record.Revision, record.Revision+99)
	if err == nil {
		t.Fatal("Activate pointed at an uncommitted revision; want refusal")
	}
	if errors.Is(err, ErrRevisionMismatch) {
		t.Error("a missing target reported as a revision mismatch; the two are different faults")
	}
	active, err := store.Active(ctx)
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if active.Revision != record.Revision {
		t.Errorf("active revision moved to %s on a failed activation", active.Revision)
	}
}

// The document ceiling is enforced before the write reaches the database, so an
// oversized blob never occupies history.
func TestCommitRefusesAnOversizedDocument(t *testing.T) {
	store := isolatedStore(t)
	ctx := context.Background()

	oversized := Document{Version: config.DocumentVersion, JSON: []byte(`{"version":1,"pad":"` + strings.Repeat("a", MaxDocumentBytes) + `"}`)}
	_, err := store.Commit(ctx, NoRevision, oversized, Meta{})
	if !errors.Is(err, ErrDocumentTooLarge) {
		t.Fatalf("Commit of an oversized document = %v, want ErrDocumentTooLarge", err)
	}
	if _, err := store.Active(ctx); !errors.Is(err, ErrNoActiveRevision) {
		t.Error("the refused write left an active revision behind")
	}
	// An empty document is refused too: it is not a configuration.
	if _, err := store.Commit(ctx, NoRevision, Document{Version: config.DocumentVersion}, Meta{}); err == nil {
		t.Error("Commit accepted an empty document")
	}
}

// The revision number is assigned by the database and strictly increases, so a
// reconciler can tell "nothing changed" from "changed" by comparing numbers.
func TestRevisionsIncreaseMonotonically(t *testing.T) {
	store := isolatedStore(t)
	ctx := context.Background()

	var previous Revision
	levels := []string{"info", "debug", "warn", "error"}
	for i, level := range levels {
		expected := NoRevision
		if i > 0 {
			expected = previous
		}
		record, err := store.Commit(ctx, expected, docWithLogLevel(t, level), Meta{})
		if err != nil {
			t.Fatalf("Commit %d: %v", i, err)
		}
		if record.Revision <= previous {
			t.Fatalf("revision %s did not increase past %s", record.Revision, previous)
		}
		previous = record.Revision
	}
}

// A rejected write must never echo the document, because the document carries
// route credentials and rotate-API tokens.
func TestStoreErrorsNeverQuoteTheDocument(t *testing.T) {
	store := isolatedStore(t)
	ctx := context.Background()

	secret := "sup3r-secret-token"
	padded := Document{
		Version: config.DocumentVersion,
		JSON:    []byte(`{"version":1,"pad":"` + secret + `"}`),
	}
	// The document is valid JSON but not a valid configuration; the store does
	// not care, and Commit must accept it — the version check happens at the
	// reconciler, not here. What matters is that nothing downstream echoes it.
	if _, err := store.Commit(ctx, NoRevision, padded, Meta{Note: "note"}); err != nil {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("Commit error quotes the document: %v", err)
		}
	}
	if _, err := store.Get(ctx, NoRevision); err != nil && strings.Contains(err.Error(), secret) {
		t.Errorf("Get error quotes the document: %v", err)
	}
}

// The store must tolerate a caller that abandons a context mid-operation
// without leaking the connection or wedging the pool.
func TestOperationsHonourContextCancellation(t *testing.T) {
	store := isolatedStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Active(ctx); err == nil {
		t.Error("Active succeeded with a cancelled context; want an error")
	}
	if err := store.Migrate(ctx); err == nil {
		t.Error("Migrate succeeded with a cancelled context; want an error")
	}
	// The store is still usable afterwards: a cancelled call is a failure, not a
	// broken connection.
	fresh, err := validDocument(t)
	if err != nil {
		t.Fatalf("building a document: %v", err)
	}
	if _, err := store.Commit(context.Background(), NoRevision, fresh, Meta{}); err != nil {
		t.Errorf("Commit after a cancelled call: %v", err)
	}
}

// A DSN that cannot be reached fails startup rather than hanging: a container
// waiting on a database that is not there must become unready, not stall.
func TestNewPostgresRejectsAnUnreachableDatabase(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := NewPostgres(ctx, "postgres://rpgw:rpgw@127.0.0.1:1/rpgw?connect_timeout=1")
	if err == nil {
		t.Fatal("NewPostgres opened a store against a closed port")
	}
	if _, err := NewPostgres(ctx, "   "); err == nil {
		t.Error("NewPostgres accepted an empty DSN")
	}
}
