package controlapi

// The control API's PUT /config wire contract against a real PostgreSQL.
//
// Every other test in this package drives the HTTP layer against an in-memory
// Repository. That proves the handler's own logic — its envelope parsing, its
// status vocabulary, its refusal to quote a document — but it cannot prove the
// one thing this endpoint actually promises: that the store's conditional
// pointer move is what rejects a stale write, and that the handler maps the
// store's own ErrRevisionMismatch onto the right transport status. A stub that
// returns the error a test told it to return only asserts that the test and the
// handler agree about the stub. This file closes that gap.
//
// It reuses the config store suite's live-PostgreSQL discipline rather than
// inventing a second one: the DSN comes from RPGW_TEST_CONFIG_STORE_DSN, an
// unset value skips loudly, and each test runs inside a schema of its own so
// concurrent runs cannot collide.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/configstore"
	"rotation-proxy-gateway/internal/pool"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// maxStaleRetries bounds the read-then-write loop below. A write that is still
// stale after this many attempts is not a race the test is modelling, it is a
// broken store: a second writer would have to be camped on the pointer to keep
// every round losing, and nothing here writes concurrently.
const maxStaleRetries = 10

// testStoreDSN returns the live-PostgreSQL DSN for this file, skipping the test
// when it is absent.
//
// The skip is loud — it names the variable — because a silently skipped
// integration test looks exactly like a passing one in the suite output.
func testStoreDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("RPGW_TEST_CONFIG_STORE_DSN")
	if strings.TrimSpace(dsn) == "" {
		t.Skip("RPGW_TEST_CONFIG_STORE_DSN is unset; skipping the live-PostgreSQL control API test")
	}
	return dsn
}

// liveStore is a migrated store in its own schema, seeded with one committed
// revision, behind a live control API.
//
// The seed is what makes the PUT tests meaningful. The control API refuses a
// missing expectation with 428 and a stale one with 412, so it never commits
// into an empty store — that is the reconciler's seed path, with a NoRevision
// expectation this endpoint deliberately does not offer. A test therefore has to
// seed the store the way the reconciler does, then drive PUT against the
// revision that seed created.
type liveStore struct {
	server *httptest.Server
	store  configstore.Repository
	// revision is the revision the seed committed, which is what a well-formed
	// PUT must name to succeed.
	revision int64
}

// isolatedControlStore opens a migrated store in a schema of its own, seeds
// revision 1 through the store's own unconditional-write path, and returns it
// behind a live control API.
//
// The schema is created and dropped through a pool of its own rather than
// through the store, because the store under test is itself created *inside* the
// schema: its own Migrate has to run there for the test to exercise the real
// migration path, and a store cannot be told to create the schema it lives in.
func isolatedControlStore(t *testing.T) liveStore {
	t.Helper()
	dsn := testStoreDSN(t)
	ctx := context.Background()

	schema := pgx.Identifier{"ctlapi_" + strings.Map(schemaIdent, t.Name())}.Sanitize()
	if err := execSQL(ctx, dsn, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create the test schema: %v", err)
	}
	t.Cleanup(func() {
		if err := execSQL(context.Background(), dsn, "DROP SCHEMA IF EXISTS "+schema+" CASCADE"); err != nil {
			t.Logf("dropping the test schema: %v", err)
		}
	})

	// The schema is pinned through the connection's search_path, so the store's
	// own SQL stays exactly as it ships: unqualified and resolving inside the
	// test's schema rather than rewritten for the test's benefit.
	store, err := configstore.NewPostgres(ctx, withSearchPath(t, dsn, schema))
	if err != nil {
		t.Fatalf("open the isolated store: %v", err)
	}
	t.Cleanup(store.Close)
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// Seed the first revision exactly as the reconciler's seed path does: an
	// unconditional NoRevision commit of a document the build can serve.
	seed, err := configstore.NewDocument(mustRuntimeConfig(t, testDocument))
	if err != nil {
		t.Fatalf("encode the seed document: %v", err)
	}
	record, err := store.Commit(ctx, configstore.NoRevision, seed, configstore.Meta{
		Author: "seed",
		Note:   "integration test seed",
	})
	if err != nil {
		t.Fatalf("seed the first revision: %v", err)
	}

	// A serving generation beside the store. The PUT path never reads it, but the
	// mux requires one, and building it from the same document the seed committed
	// keeps the fixture honest about what an instance would be serving.
	cfg := mustRuntimeConfig(t, testDocument)
	generations := pool.NewStore(cfg, pool.NewRoutes(cfg.AllRoutes(), cfg.CooldownBase, cfg.CooldownMax))
	mux := New(Options{
		Auth:        tokenAuth{token: testToken},
		Generations: generations,
		ConfigStore: store,
		Log:         zerolog.Nop(),
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return liveStore{server: srv, store: store, revision: int64(record.Revision)}
}

// mustRuntimeConfig decodes a document into a serving configuration, shared by
// the seed write and the serving generation so the two cannot describe
// different deployments.
func mustRuntimeConfig(t *testing.T, document []byte) *config.RuntimeConfig {
	t.Helper()
	cfg, err := configstore.Decode(configstore.Document{Version: config.DocumentVersion, JSON: document})
	if err != nil {
		t.Fatalf("the fixture document does not decode: %v", err)
	}
	return cfg
}

// withSearchPath returns dsn with its connection search_path pinned to schema.
//
// The DSN may be given either as a URL or in keyword/value form, so the
// parameter is added in whichever shape it already carries rather than assuming
// one. A wrong guess would silently connect to the default schema and let the
// test read another suite's tables; the two branches below are the difference
// between an isolated test and a flaky one.
func withSearchPath(t *testing.T, dsn, schema string) string {
	t.Helper()
	if strings.Contains(dsn, "://") {
		separator := "?"
		if strings.Contains(dsn, "?") {
			separator = "&"
		}
		return dsn + separator + "search_path=" + url.QueryEscape(schema)
	}
	return dsn + " search_path=" + schema
}

// execSQL runs one fixed statement over a throwaway pool. Every statement here
// is written in this file, so nothing is assembled from a value.
func execSQL(ctx context.Context, dsn, statement string) error {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	_, err = pool.Exec(ctx, statement)
	return err
}

// schemaIdent maps a test name to a legal, lowercase SQL identifier fragment,
// matching the config store suite's own mapping.
func schemaIdent(r rune) rune {
	switch {
	case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return r
	case r >= 'A' && r <= 'Z':
		return r + ('a' - 'A')
	default:
		return '_'
	}
}

// putOverStore posts one PUT /config envelope to a live-backed control server.
func putOverStore(t *testing.T, srv *httptest.Server, expected int64, author string, document json.RawMessage) (*http.Response, []byte) {
	t.Helper()
	envelope, err := json.Marshal(map[string]any{
		"expected_revision": expected,
		"author":            author,
		"note":              "integration test write",
		"document":          document,
	})
	if err != nil {
		t.Fatalf("encode the envelope: %v", err)
	}
	req, err := http.NewRequest(http.MethodPut, srv.URL+PathConfig, strings.NewReader(string(envelope)))
	if err != nil {
		t.Fatalf("build the PUT: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("PUT %s: %v", PathConfig, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read the PUT body: %v", err)
	}
	return resp, body
}

// liveRouteSecret is the credential the committed documents' route line carries.
// It is the same shape a real route uses — `user:pass@host:port` — so the
// credential-free-read assertion below is testing something the store actually
// holds rather than a value that never entered it.
const liveRouteSecret = "live-route-secret-value"

// documentWithLogLevel builds a complete, valid configuration document whose
// only difference between two levels is one setting, so two commits are
// distinguishable without any other field changing. The route line carries a
// credential, so a read of the durable document has something to leak and the
// credential-free assertion can fail.
func documentWithLogLevel(t *testing.T, level string) json.RawMessage {
	t.Helper()
	cfg, err := config.DecodeDocument([]byte(fmt.Sprintf(`{
      "version": 1,
      "log-level": %q,
      "max-retries": 2,
      "cooldown": {"base": "15s", "max": "10m"},
      "dial-timeout": "10s",
      "proxies": {"auto": [{"id": "egress-a", "proxy": "provider-user:%s@provider.example:1080", "kind": "v4"}]}
    }`, level, liveRouteSecret)))
	if err != nil {
		t.Fatalf("build a document: %v", err)
	}
	document, err := config.MarshalDocument(cfg)
	if err != nil {
		t.Fatalf("encode a document: %v", err)
	}
	return document
}

// The whole point of the endpoint: a write that names the active revision
// commits, the pointer moves, and the durable history records it.
func TestLivePutConfigCommitsAndAdvancesThePointer(t *testing.T) {
	live := isolatedControlStore(t)
	ctx := context.Background()

	resp, body := putOverStore(t, live.server, live.revision, testAuthor, documentWithLogLevel(t, "info"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /config = %d, want 200: %s", resp.StatusCode, truncate(body))
	}
	var committed struct {
		Revision int64 `json:"revision"`
		Accepted bool  `json:"accepted"`
	}
	if err := json.Unmarshal(body, &committed); err != nil {
		t.Fatalf("decode the commit body: %v", err)
	}
	if !committed.Accepted || committed.Revision <= live.revision {
		t.Fatalf("commit = %+v, want a new revision past the seed's %d", committed, live.revision)
	}

	active, err := live.store.Active(ctx)
	if err != nil {
		t.Fatalf("Active after the commit: %v", err)
	}
	if int64(active.Revision) != committed.Revision {
		t.Fatalf("the durable pointer is at %d, but the response named %d", active.Revision, committed.Revision)
	}
	if active.Author != testAuthor {
		t.Errorf("stored author = %q, want %q", active.Author, testAuthor)
	}

	// The second write names what the first created, so it must commit too — this
	// is the path a client's read-then-write takes when it wins the race.
	resp, body = putOverStore(t, live.server, committed.Revision, testAuthor, documentWithLogLevel(t, "debug"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the matching second PUT = %d, want 200: %s", resp.StatusCode, truncate(body))
	}
	var advanced struct {
		Revision int64 `json:"revision"`
	}
	if err := json.Unmarshal(body, &advanced); err != nil {
		t.Fatalf("decode the second commit body: %v", err)
	}
	if advanced.Revision <= committed.Revision {
		t.Fatalf("second revision = %d, want it past %d", advanced.Revision, committed.Revision)
	}
}

// 412, and the revision the client must rebase onto, as observed against the
// real pointer.
func TestLiveStalePutConfigIs412AndAppendsNothing(t *testing.T) {
	live := isolatedControlStore(t)
	ctx := context.Background()

	// A peer commits, moving the pointer past the seed...
	if resp, body := putOverStore(t, live.server, live.revision, testAuthor, documentWithLogLevel(t, "warn")); resp.StatusCode != http.StatusOK {
		t.Fatalf("the peer write = %d: %s", resp.StatusCode, truncate(body))
	}
	active, err := live.store.Active(ctx)
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if active.Revision <= configstore.Revision(live.revision) {
		t.Fatalf("the peer did not advance the pointer past the seed's %d", live.revision)
	}

	// ...so a write that still names the seed must be refused, and must tell the
	// client where the pointer actually is.
	resp, body := putOverStore(t, live.server, live.revision, testAuthor, documentWithLogLevel(t, "error"))
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("a stale PUT = %d, want 412: %s", resp.StatusCode, truncate(body))
	}
	var failure struct {
		CurrentRevision int64 `json:"currentRevision"`
		Readable        bool  `json:"readable"`
	}
	if err := json.Unmarshal(body, &failure); err != nil {
		t.Fatalf("decode the 412 body: %v", err)
	}
	if failure.CurrentRevision != int64(active.Revision) || !failure.Readable {
		t.Fatalf("412 named currentRevision=%d readable=%v, want the real %d and readable",
			failure.CurrentRevision, failure.Readable, active.Revision)
	}

	// The store is append-only and the refused write left no trace: the pointer is
	// still where the last successful commit put it.
	after, err := live.store.Active(ctx)
	if err != nil {
		t.Fatalf("Active after the refusal: %v", err)
	}
	if after.Revision != active.Revision {
		t.Fatalf("a refused write moved the pointer from %d to %d", active.Revision, after.Revision)
	}
}

// 428 is the missing expectation, and it is not the same request as a stale one.
func TestLiveMissingExpectationIs428(t *testing.T) {
	live := isolatedControlStore(t)

	resp, body := putOverStore(t, live.server, 0, testAuthor, documentWithLogLevel(t, "info"))
	if resp.StatusCode != http.StatusPreconditionRequired {
		t.Fatalf("a PUT with no expectation = %d, want 428: %s", resp.StatusCode, truncate(body))
	}
}

// The read the client performs before it writes must observe the same pointer
// the store would enforce, or the two-status vocabulary would be a fiction. This
// drives the whole loop against the live store: read, write, re-read on a loss,
// and commit.
func TestLiveReadThenWriteConverges(t *testing.T) {
	live := isolatedControlStore(t)
	ctx := context.Background()

	for attempt := 1; attempt <= maxStaleRetries; attempt++ {
		active, err := live.store.Active(ctx)
		if err != nil {
			t.Fatalf("Active on attempt %d: %v", attempt, err)
		}
		resp, body := putOverStore(t, live.server, int64(active.Revision), testAuthor, documentWithLogLevel(t, "debug"))
		switch resp.StatusCode {
		case http.StatusOK:
			return // converged
		case http.StatusPreconditionFailed:
			// A peer moved the pointer between the read and the write, which is
			// exactly the race the two-status vocabulary exists for. Re-read.
			continue
		default:
			t.Fatalf("attempt %d = %d, want 200 or 412: %s", attempt, resp.StatusCode, truncate(body))
		}
	}
	t.Fatalf("the read-then-write loop did not converge in %d attempts", maxStaleRetries)
}

// A committed revision is readable back through GET /config, credential-free.
func TestLiveGetConfigReportsTheCommittedRevisionWithoutCredentials(t *testing.T) {
	live := isolatedControlStore(t)

	document := documentWithLogLevel(t, "warn")
	resp, body := putOverStore(t, live.server, live.revision, testAuthor, document)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the commit = %d: %s", resp.StatusCode, truncate(body))
	}
	var committed struct {
		Revision int64 `json:"revision"`
	}
	if err := json.Unmarshal(body, &committed); err != nil {
		t.Fatalf("decode the commit body: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, live.server.URL+PathConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err = live.server.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", PathConfig, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read the GET body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /config = %d, want 200: %s", resp.StatusCode, truncate(body))
	}
	view := decodeJSON(t, body)
	if view["revision"] != float64(committed.Revision) {
		t.Errorf("GET /config revision = %v, want the committed %d", view["revision"], committed.Revision)
	}
	if view["editable"] != false {
		t.Errorf("GET /config editable = %v, want false", view["editable"])
	}
	// The durable store holds the committed document; the response must report the
	// route endpoint as host:port, so the credential a route line carries in the
	// store never appears in the view.
	if strings.Contains(string(body), liveRouteSecret) {
		t.Errorf("GET /config leaked a credential: %s", truncate(body))
	}
}
