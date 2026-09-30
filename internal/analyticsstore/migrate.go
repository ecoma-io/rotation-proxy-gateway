package analyticsstore

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

// migrationLockKey is the advisory-lock key for analytics DDL. It is a distinct
// constant from the configuration substrate's, so an analytics migration and a
// configuration migration can never queue behind each other while holding
// unrelated locks — and, more importantly, so a caller that took the config
// lock can never be mistaken for one that took this.
const migrationLockKey int64 = 0x72706777_616e6c59 // "rpgwanlY"

const (
	// migrateTimeout bounds DDL at boot. A wedged database must fail startup
	// rather than hang a container that will never become ready.
	migrateTimeout = 60 * time.Second
)

// ErrSchemaMismatch reports that the database's schema is not this build's to
// work with, in either direction. Neither is worked around: a database ahead of
// the binary means a newer instance applied migrations this build does not know,
// and continuing would write into tables whose shape this build misreads.
var ErrSchemaMismatch = errors.New("analytics store schema version does not match this build")

// migration is one embedded migration file: its version, name, SQL, and the
// checksum of that SQL.
type migration struct {
	Version  int
	Name     string
	SQL      string
	Checksum string
}

// Migrate brings the analytics schema up to the latest embedded migration.
//
// Forward-only and checksum-validated, exactly as the configuration substrate's
// migrator is: each applied migration's checksum is recorded, a later run
// recomputes it, and any difference refuses rather than being skipped. A
// migration that was edited after running against real data would otherwise
// leave the file and the database silently out of step. The whole sequence runs
// in one transaction under a session advisory lock, so concurrent instances
// converge instead of racing DDL, and a failure leaves the schema as it was.
//
// schema_migrations is created here rather than being one of the embedded
// files, so the very first run can record itself. It is the same bookkeeping
// table the configuration store uses, and the two share a database happily:
// each migrator only ever looks at its own files, and each advisory lock
// serializes its own DDL.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, migrateTimeout)
	defer cancel()

	// A dedicated connection: the advisory lock is session-scoped, so it must be
	// taken and released on one connection.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire analytics migration connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockKey); err != nil {
		return fmt.Errorf("acquire analytics migration lock: %w", err)
	}
	defer func() {
		// A fresh context: ctx may already be cancelled by its timeout, and the
		// lock must be released even then. A failure here is not worth
		// reporting — the backend reclaims a session lock when the session ends.
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationLockKey)
	}()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin analytics migration: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

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
	// A database ahead of this build refuses. It is not downgraded, ignored, or
	// migrated backwards.
	if newest > migrations[len(migrations)-1].Version {
		return fmt.Errorf("%w: database is at schema version %d, this build knows %d — upgrade the gateway",
			ErrSchemaMismatch, newest, migrations[len(migrations)-1].Version)
	}

	for _, m := range migrations {
		existing, known := applied[m.Version]
		if !known {
			// Exec, not QueryRow: a migration file may hold several statements,
			// and Exec over a multi-statement string runs them as one implicit
			// transaction under PostgreSQL's simple-query protocol.
			if _, err := tx.Exec(ctx, m.SQL); err != nil {
				// The failure names the migration version, not its content.
				return fmt.Errorf("apply analytics migration %d (%s): %w", m.Version, m.Name, err)
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`,
				m.Version, m.Name, m.Checksum,
			); err != nil {
				return fmt.Errorf("record analytics migration %d: %w", m.Version, err)
			}
			continue
		}
		if existing != m.Checksum {
			return fmt.Errorf("%w: migration %d (%s) was applied with checksum %s but this build carries %s — a migration file was edited after it ran",
				ErrSchemaMismatch, m.Version, m.Name, existing, m.Checksum)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit analytics migrations: %w", err)
	}
	return nil
}

// appliedMigrations reads the bookkeeping table, reporting the highest applied
// version alongside the recorded checksums.
func appliedMigrations(ctx context.Context, tx pgx.Tx) (map[int]string, int, error) {
	rows, err := tx.Query(ctx, `SELECT version, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, 0, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()
	applied := map[int]string{}
	newest := 0
	for rows.Next() {
		var (
			version  int
			checksum string
		)
		if err := rows.Scan(&version, &checksum); err != nil {
			return nil, 0, fmt.Errorf("scan schema_migrations: %w", err)
		}
		applied[version] = checksum
		if version > newest {
			newest = version
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("read schema_migrations: %w", err)
	}
	return applied, newest, nil
}

// SchemaVersion reports the applied schema-migration version. It is the schema
// version axis, independent of any document version.
func SchemaVersion(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var version int
	if err := pool.QueryRow(ctx, `SELECT COALESCE(max(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		return 0, fmt.Errorf("read analytics schema version: %w", err)
	}
	return version, nil
}

// loadMigrations reads the embedded migration files and pairs each with its
// version, which comes from the filename prefix so the version is ordered the
// same way in the binary, the database, and a human's head. A file whose name
// does not parse is a build error rather than a skipped migration: ignoring one
// would leave the schema short of what the source tree says it should be, with
// nothing to report it.
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read embedded analytics migrations: %w", err)
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
			return nil, fmt.Errorf("embedded analytics migrations %s and %s both claim version %d", previous, entry.Name(), version)
		}
		seen[version] = entry.Name()
		body, err := migrationFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read embedded analytics migration %s: %w", entry.Name(), err)
		}
		if len(strings.TrimSpace(string(body))) == 0 {
			return nil, fmt.Errorf("embedded analytics migration %s is empty", entry.Name())
		}
		migrations = append(migrations, migration{
			Version:  version,
			Name:     name,
			SQL:      string(body),
			Checksum: checksum(body),
		})
	}
	if len(migrations) == 0 {
		return nil, errors.New("no embedded analytics migrations found: the analytics schema could never be created")
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	return migrations, nil
}

// parseMigrationName splits "0001_durable_analytics.sql" into its version and
// name. Both are required: the name is what a checksum mismatch or an apply
// failure reports back to the operator.
func parseMigrationName(filename string) (version int, name string, err error) {
	stem := strings.TrimSuffix(filename, ".sql")
	prefix, name, found := strings.Cut(stem, "_")
	if !found || name == "" {
		return 0, "", fmt.Errorf("embedded analytics migration %q must be named NNNN_description.sql", filename)
	}
	version, err = strconv.Atoi(prefix)
	if err != nil || version < 1 {
		return 0, "", fmt.Errorf("embedded analytics migration %q must start with a positive integer version", filename)
	}
	return version, name, nil
}

// checksum is the migration's identity for tamper detection: SHA-256 over the
// exact file bytes, hex-encoded. A one-byte edit anywhere changes it, which is
// the only property it needs.
func checksum(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
