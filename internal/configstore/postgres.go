package configstore

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// pgRepository is the PostgreSQL implementation of Repository.
//
// Two properties shape the SQL here. First, every statement is parameterized:
// no query concatenates a value into SQL text, including the embedded
// migrations, which are fixed build assets run as whole statements. Second, no
// document content reaches an error string — a failing commit reports its
// revision and column, never the document, which holds route credentials and
// rotate-API tokens.
type pgRepository struct {
	pool *pgxpool.Pool
}

// Meta is the operator attribution attached to a commit. Both fields are
// optional free text and are stored as written, so neither may be used for a
// credential: the store applies no redaction to them because it cannot tell an
// operator note from a secret, and a field nobody may put a secret in needs no
// redaction to be safe.
type Meta struct {
	Author string
	Note   string
}

const (
	// The advisory-lock key. Every instance derives it from this constant, so
	// two instances that understand the same migrations always contend on the
	// same lock; a value that varied per instance would let concurrent DDL
	// through and defeat the point.
	migrationLockKey int64 = 0x72706777_63666731 // "rpgwcfg1"
)

// Query timeouts. Every store call is off the serving path, so these bound a
// control-plane operation rather than a client request. They exist so a wedged
// database cannot hold a caller forever: the reconciler backs off and retries,
// and a boot-time migration fails startup instead of hanging a container that
// will never become ready.
const (
	migrateTimeout = 60 * time.Second
	queryTimeout   = 10 * time.Second
)

// NewPostgres opens the durable store against dsn and verifies it is
// reachable.
//
// The DSN is a secret: it commonly carries the database password. It is passed
// to pgx and never retained on the repository, formatted into an error, or
// logged — the errors below are pgx's own, which reference host and database
// but not the password. Migrate must run against the returned store before the
// process binds listeners.
func NewPostgres(ctx context.Context, dsn string) (Repository, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("the config store DSN must not be empty")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		// pgx's parse error names the offending keyword, never the value; the
		// raw DSN is deliberately not appended here.
		return nil, fmt.Errorf("parse config store DSN: %w", err)
	}
	return openPool(ctx, cfg)
}

// openPool dials a parsed configuration and verifies it answers.
func openPool(ctx context.Context, cfg *pgxpool.Config) (Repository, error) {
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open config store: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("config store unreachable: %w", err)
	}
	return &pgRepository{pool: pool}, nil
}

// Close releases the pool.
func (r *pgRepository) Close() { r.pool.Close() }

// Active reads the revision the singleton pointer names.
//
// The empty store — a pointer row whose revision is NULL, which is the state
// the migration creates and the first commit replaces — is reported as
// ErrNoActiveRevision, so a caller has one way to ask "is anything committed?"
// rather than two.
func (r *pgRepository) Active(ctx context.Context) (Active, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	const q = `
		SELECT r.revision, r.doc_version, r.document, r.author, r.note, a.updated_at
		FROM active_config a
		JOIN config_revisions r ON r.revision = a.revision
		WHERE a.id = 1`
	var (
		active   Active
		document []byte
	)
	// NoRows here means one of two things, and they are the same thing to a
	// caller: either the pointer row is absent (a schema created outside the
	// migration) or it names no revision because nothing is committed yet.
	if err := r.pool.QueryRow(ctx, q).Scan(
		&active.Revision, &active.DocVersion, &document, &active.Author, &active.Note, &active.PointerUpdated,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Active{}, ErrNoActiveRevision
		}
		return Active{}, fmt.Errorf("read active config: %w", err)
	}
	active.Document = document
	return active, nil
}

// Get reads one committed revision.
func (r *pgRepository) Get(ctx context.Context, revision Revision) (Record, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	const q = `SELECT revision, doc_version, document, author, note FROM config_revisions WHERE revision = $1`
	var (
		record   Record
		document []byte
	)
	if err := r.pool.QueryRow(ctx, q, int64(revision)).Scan(
		&record.Revision, &record.DocVersion, &document, &record.Author, &record.Note,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Record{}, fmt.Errorf("%w: %d", ErrNoRevision, int64(revision))
		}
		return Record{}, fmt.Errorf("read config revision: %w", err)
	}
	record.Document = document
	return record, nil
}

// Commit appends a revision and activates it in one transaction, guarding the
// pointer move on expected.
//
// The optimistic-concurrency check and the pointer move are the same
// transaction, and the pointer move is a conditional UPDATE, so two writers
// that both believe revision N is active cannot both win: the first to commit
// moves the pointer, and the second's UPDATE then matches zero rows and rolls
// the whole transaction back — its insert included. There is no read-then-
// write window to lose, because the expectation is never read into application
// memory and compared there; it is a WHERE clause.
//
// A NoRevision expectation is the unconditional first write: nothing is active
// to be stale against. It fills the pointer wherever the pointer currently is —
// NULL for an empty store, or a revision an operator rolled back to — because
// "activate this, do not check" is the only honest reading of an absent
// expectation. A caller that means "only into an empty store" is the seeding
// path, which checks Active first.
//
// The insert takes a sequence value, so a rolled-back transaction leaves a gap in
// the numbering. That is intentional and harmless: a gap makes no revision
// reachable that was not committed, and no reader can observe one through
// active_config.
func (r *pgRepository) Commit(ctx context.Context, expected Revision, doc Document, meta Meta) (Record, error) {
	if len(doc.JSON) == 0 {
		return Record{}, errors.New("a committed config document must not be empty")
	}
	if len(doc.JSON) > MaxDocumentBytes {
		// Reported as a size, never the content: a too-large document is usually
		// a runaway paste, and quoting it would quote the credentials inside it.
		return Record{}, fmt.Errorf("%w: %d bytes (limit %d)", ErrDocumentTooLarge, len(doc.JSON), MaxDocumentBytes)
	}
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Record{}, fmt.Errorf("begin config commit: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	const insert = `
		INSERT INTO config_revisions (doc_version, document, author, note)
		VALUES ($1, $2, $3, $4)
		RETURNING revision, doc_version, document, author, note`
	var (
		record   Record
		document []byte
	)
	// The document is a bound parameter, never interpolated text: it is
	// operator-supplied JSON, and a value spliced into SQL would be an injection
	// surface.
	if err := tx.QueryRow(ctx, insert, doc.Version, doc.JSON, meta.Author, meta.Note).Scan(
		&record.Revision, &record.DocVersion, &document, &record.Author, &record.Note,
	); err != nil {
		return Record{}, fmt.Errorf("append config revision: %w", err)
	}
	record.Document = document

	if expected.IsValid() {
		if err := pointAt(ctx, tx, expected, record.Revision); err != nil {
			return Record{}, err
		}
	} else if err := claimPointer(ctx, tx, record.Revision); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Record{}, fmt.Errorf("commit config revision: %w", err)
	}
	return record, nil
}

// pointAt moves the singleton pointer from expected to target, or reports
// ErrRevisionMismatch. It runs inside the caller's transaction so the check and
// the move are one atomic step.
func pointAt(ctx context.Context, tx pgx.Tx, expected, target Revision) error {
	const update = `UPDATE active_config SET revision = $1, updated_at = now() WHERE id = 1 AND revision = $2`
	tag, err := tx.Exec(ctx, update, int64(target), int64(expected))
	if err != nil {
		return fmt.Errorf("activate config revision: %w", err)
	}
	if tag.RowsAffected() != 1 {
		// The pointer was not where the writer expected. The insert rolls back
		// with the transaction, so a rejected writer appends nothing at all.
		return ErrRevisionMismatch
	}
	return nil
}

// claimPointer moves the singleton pointer unconditionally. It is the
// NoRevision-expectation path — a first write, which has nothing to be stale
// against.
//
// The move and the row's existence are one step, not two: an UPDATE that
// matched no row would leave a committed revision that nothing points at, so
// the missing row is upserted rather than reported. In practice the migration
// creates the row, and this only matters for a schema that did not come from it.
func claimPointer(ctx context.Context, tx pgx.Tx, target Revision) error {
	const upsert = `
		INSERT INTO active_config (id, revision, updated_at)
		VALUES (1, $1, now())
		ON CONFLICT (id) DO UPDATE SET revision = EXCLUDED.revision, updated_at = now()`
	if _, err := tx.Exec(ctx, upsert, int64(target)); err != nil {
		return fmt.Errorf("claim config revision pointer: %w", err)
	}
	return nil
}

// Activate re-points the singleton at an already-committed revision. History is
// never rewritten, so this — not a delete — is how a rollback works.
func (r *pgRepository) Activate(ctx context.Context, expected, target Revision) error {
	if !target.IsValid() {
		return fmt.Errorf("%w: cannot activate %d", ErrNoRevision, int64(target))
	}
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin config activation: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := pointAt(ctx, tx, expected, target); err != nil {
		return err
	}
	// The foreign key is what makes a pointer to a missing revision impossible;
	// this read turns a violation into a clear error rather than a constraint
	// name, inside the transaction so the check and the move commit or abort
	// together.
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT true FROM config_revisions WHERE revision = $1`, int64(target)).Scan(&exists); err != nil {
		return fmt.Errorf("verify target revision: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit config activation: %w", err)
	}
	return nil
}

// SchemaVersion reports the applied schema-migration version. It is the schema
// version axis, independent of any document version.
func (r *pgRepository) SchemaVersion(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	var version int
	err := r.pool.QueryRow(ctx, `SELECT COALESCE(max(version), 0) FROM schema_migrations`).Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	return version, nil
}

// ErrSchemaMismatch reports that the database's schema is not this build's to
// work with. It covers both directions and neither is worked around: a database
// ahead of the binary means a newer instance applied migrations this build does
// not know, and continuing would run against tables whose shape this build
// cannot reason about. Both cases refuse startup — guessing is how a control
// plane starts writing into a schema it misreads.
var ErrSchemaMismatch = errors.New("config store schema version does not match this build")

// Migrate brings the schema up to the latest embedded migration.
//
// Forward-only and checksum-validated. Each applied migration's checksum is
// recorded; a later run recomputes it and refuses on any difference, which is
// what catches an edited migration that has already run against real data. The
// whole sequence runs inside one transaction under a session advisory lock, so
// concurrent instances converge on the same result instead of racing DDL, and a
// failure anywhere leaves the schema exactly as it was.
//
// It must complete before the process binds listeners: serving against a
// half-migrated schema would have the data plane reading tables whose shape the
// code does not expect.
func (r *pgRepository) Migrate(ctx context.Context) error {
	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, migrateTimeout)
	defer cancel()

	// A dedicated connection, because the advisory lock is session-scoped: it
	// must be taken and released on one connection, and pgxpool would otherwise
	// be free to run the statements on a different one.
	conn, err := r.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()

	// Block until every other instance's migration has finished. Held for the
	// whole transaction below, so no other Migrate can interleave DDL with it.
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockKey); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		// A fresh context: ctx may already be cancelled by a timeout, and the
		// lock must be released even then, or the next boot waits out the
		// server's own lock timeout. A failure here is not worth reporting: the
		// backend reclaims a session lock when the session ends regardless.
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationLockKey)
	}()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin migration: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	// The bookkeeping table is created by the migrator itself rather than being
	// one of the embedded files, so the very first run can record itself. The
	// checksum column is what makes an edited migration detectable.
	const bookkeeping = `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    integer     PRIMARY KEY,
			name       text        NOT NULL,
			checksum   text        NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`
	if _, err := tx.Exec(ctx, bookkeeping); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied, newest, err := appliedMigrations(ctx, tx)
	if err != nil {
		return err
	}
	// A database ahead of this build refuses startup. It is not downgraded,
	// ignored, or migrated backwards: a newer instance has already written
	// rows this build's code does not understand, and the safe outcome is to
	// stop rather than serve from a schema read on a guess.
	if newest > migrations[len(migrations)-1].Version {
		return fmt.Errorf("%w: database is at schema version %d, this build knows %d — upgrade the gateway",
			ErrSchemaMismatch, newest, migrations[len(migrations)-1].Version)
	}

	for _, migration := range migrations {
		existing, known := applied[migration.Version]
		if !known {
			// Exec, not QueryRow: a migration file may hold several statements,
			// and Exec over a multi-statement string runs them as one implicit
			// transaction under PostgreSQL's simple-query protocol.
			if _, err := tx.Exec(ctx, migration.SQL); err != nil {
				// The failure names the migration version, not its content.
				return fmt.Errorf("apply migration %d (%s): %w", migration.Version, migration.Name, err)
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`,
				migration.Version, migration.Name, migration.Checksum,
			); err != nil {
				return fmt.Errorf("record migration %d: %w", migration.Version, err)
			}
			continue
		}
		if existing.Checksum != migration.Checksum {
			// Refusing is the whole point of recording the checksum. An edited
			// migration has already run against real data somewhere; re-running
			// the new text would apply different DDL than the database actually
			// received, and skipping it would leave the two silently out of step.
			return fmt.Errorf("%w: migration %d (%s) was applied with checksum %s but this build carries %s — a migration file was edited after it ran",
				ErrSchemaMismatch, migration.Version, migration.Name, existing.Checksum, migration.Checksum)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migrations: %w", err)
	}
	return nil
}

// appliedRecord is one row of the migration bookkeeping table.
type appliedRecord struct {
	Name     string
	Checksum string
}

// appliedMigrations reads the bookkeeping table and reports the highest applied
// version alongside it — the number compared against this build's.
func appliedMigrations(ctx context.Context, tx pgx.Tx) (map[int]appliedRecord, int, error) {
	rows, err := tx.Query(ctx, `SELECT version, name, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, 0, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()
	applied := map[int]appliedRecord{}
	newest := 0
	for rows.Next() {
		var (
			version int
			record  appliedRecord
		)
		if err := rows.Scan(&version, &record.Name, &record.Checksum); err != nil {
			return nil, 0, fmt.Errorf("scan schema_migrations: %w", err)
		}
		applied[version] = record
		if version > newest {
			newest = version
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("read schema_migrations: %w", err)
	}
	return applied, newest, nil
}

// migration is one embedded migration file: its version, its name, its SQL,
// and the checksum of that SQL.
type migration struct {
	Version  int
	Name     string
	SQL      string
	Checksum string
}

// loadMigrations reads the embedded migration files and pairs each with its
// version.
//
// The version comes from the filename prefix, which makes the version ordered
// the same way in the binary, in the database, and in a human's head. A file
// whose name does not parse is a build error rather than a skipped migration:
// silently ignoring one would leave the schema short of what the source tree
// says it should be, with nothing to report it.
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}
	migrations := make([]migration, 0, len(entries))
	seen := make(map[int]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		version, name, err := parseMigrationName(entry.Name())
		if err != nil {
			return nil, err
		}
		if previous, duplicate := seen[version]; duplicate {
			return nil, fmt.Errorf("embedded migrations %s and %s both claim version %d", previous, entry.Name(), version)
		}
		seen[version] = entry.Name()
		body, err := migrationFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read embedded migration %s: %w", entry.Name(), err)
		}
		if len(strings.TrimSpace(string(body))) == 0 {
			return nil, fmt.Errorf("embedded migration %s is empty", entry.Name())
		}
		migrations = append(migrations, migration{
			Version:  version,
			Name:     name,
			SQL:      string(body),
			Checksum: checksum(body),
		})
	}
	if len(migrations) == 0 {
		return nil, errors.New("no embedded migrations found: the config store schema could never be created")
	}
	// Sorted by version rather than by filename, so application order is the
	// numeric order even if a build embeds the files in another order.
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	return migrations, nil
}

// parseMigrationName splits "0001_config_revisions.sql" into its version and
// its name. Both parts are required: the name is what a checksum mismatch or an
// apply failure reports back to the operator, so an unnamed file would produce
// an error nobody could act on.
func parseMigrationName(filename string) (version int, name string, err error) {
	stem := strings.TrimSuffix(filename, ".sql")
	prefix, name, found := strings.Cut(stem, "_")
	if !found || name == "" {
		return 0, "", fmt.Errorf("embedded migration %q must be named NNNN_description.sql", filename)
	}
	version, err = strconv.Atoi(prefix)
	if err != nil || version < 1 {
		return 0, "", fmt.Errorf("embedded migration %q must start with a positive integer version", filename)
	}
	return version, name, nil
}

// checksum is the migration's identity for tamper detection: SHA-256 over the
// exact file bytes, hex-encoded. A one-byte edit anywhere in the file changes
// it, which is the only property it needs.
func checksum(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
