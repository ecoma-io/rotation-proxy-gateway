// Package configstore is the durable, revisioned home of the gateway's runtime
// configuration. It replaces the polled configuration file as the runtime
// authority: revisions are committed here, and every instance materializes the
// active revision into a local serving generation.
//
// Three objects, deliberately separated:
//
//   - Migrations are the *schema* version axis: the version of the table
//     layout, tracked in schema_migrations and advanced by embedded,
//     checksum-validated SQL.
//   - Documents are the *document* version axis: the version of the JSON
//     configuration shape, carried per revision as doc_version.
//
// The two never share a number. A schema migration must not require a document
// rewrite, and a document bump must not require a migration.
//
// Nothing here interprets configuration. Validation belongs to
// internal/config (see config.Document); this package moves opaque documents
// and answers questions about which revision is active.
//
// Secret handling: a document carries route credentials and rotate-API
// headers. No method here logs, formats, or wraps one into an error, and the
// repository's own errors name columns and revisions only. Callers are
// responsible for treating a loaded document as secret material for its whole
// lifetime.
package configstore

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Revision identifies one committed configuration document. It is assigned by
// the database and is strictly increasing across the cluster, so it doubles as
// the optimistic-concurrency token: a writer states the revision it believes
// is active, and the update succeeds only if that is still the active pointer.
type Revision int64

// NoRevision is the zero Revision, used as the expected_revision of an
// unconditional first write.
const NoRevision Revision = 0

// Revision is a valid, committed revision number.
func (r Revision) IsValid() bool { return r > 0 }

// String renders the revision for logs and status fields. It carries no
// document content.
func (r Revision) String() string { return fmt.Sprintf("revision-%d", int64(r)) }

// Record is one committed revision as read back from the store. The Document
// bytes are the configuration itself and are secret material: they are
// returned only to the reconciler's load path and must never be logged,
// echoed in an error, or included in an HTTP response.
type Record struct {
	Revision   Revision
	DocVersion int
	Document   []byte
	Author     string
	Note       string
}

// Active is the currently authoritative revision together with the document it
// carries.
type Active struct {
	Record
	// PointerUpdated is the database clock's timestamp of the last pointer
	// move, so a caller can tell "no change since" from "re-pointed at the
	// same revision" without re-reading the document. It is a time.Time rather
	// than an epoch integer because the column is timestamptz and the database
	// clock is not the caller's to reinterpret.
	PointerUpdated time.Time
}

// ErrRevisionMismatch reports a rejected optimistic-concurrency update: the
// active revision was not the one the writer expected. The store-side
// primitive; mapping it to a transport status (412 on a stale If-Match, 428 on
// a missing one) belongs to the HTTP layer that owns that vocabulary.
//
// It is not a transient failure and retrying the identical write will fail
// identically — the caller must re-read the active revision and decide again.
var ErrRevisionMismatch = errors.New("config revision mismatch")

// ErrNoActiveRevision reports that no revision is committed yet. The store
// models the empty state as a pointer row that names nothing rather than as the
// absence of a row, so this is a real state a seed writes the first revision
// into, not a missing table.
//
// It is deliberately not ErrRevisionMismatch. "Nothing is active" is a state to
// materialize a first generation from, not a conflict to reject a writer over.
var ErrNoActiveRevision = errors.New("no active config revision")

// ErrDocumentTooLarge reports a document beyond the store's byte ceiling. The
// bound exists so one writer cannot push an unbounded blob into the history
// that every instance will read on every materialization.
var ErrDocumentTooLarge = errors.New("config document too large")

// MaxDocumentBytes bounds one configuration document. A configuration
// document is route lines plus knobs; a megabyte is far past any real
// deployment, so exceeding it is a mistake rather than a large fleet.
const MaxDocumentBytes = 1 << 20

// ErrNoRevision is returned when a specific revision cannot be read back.
// The store never deletes history, so this means the revision never existed.
var ErrNoRevision = errors.New("unknown config revision")

// Repository is the durable configuration authority. Every method takes a
// context; none of them is on the serving path — the gateway reads the applied
// revision from its local pool.Generation and never queries the store to serve
// a request.
//
// Implementations must be safe for concurrent use.
type Repository interface {
	// Active reads the revision the pointer currently names, together with
	// its document. It returns ErrNoActiveRevision when nothing is committed.
	Active(ctx context.Context) (Active, error)

	// Get reads one committed revision by number. Append-only history means
	// this can never return a superseded version of that number; it returns
	// ErrNoRevision when the number was never committed.
	Get(ctx context.Context, revision Revision) (Record, error)

	// Commit appends a new revision carrying document and makes it active in the
	// same transaction. When expected is valid, the pointer move is conditional
	// on the pointer naming expected at that moment: a mismatch returns
	// ErrRevisionMismatch and appends nothing, so two writers racing from the
	// same expectation can never both win — exactly one transaction observes
	// the pointer at expected and commits, and the other either loses the
	// pointer race or finds the pointer already moved.
	//
	// A NoRevision expectation is unconditional: it appends and takes over the
	// pointer without checking it, which is the first-write path and the only
	// one a seed should use. "Activate this, do not check" is what an absent
	// expectation means; a caller that means "only into an empty store" is the
	// seeding path, which reads Active first.
	//
	// Commit is idempotent by content, not by request: committing the same
	// document twice appends two revisions. Callers that need
	// retry-resilience must first check whether the document they hold is
	// already active (or read the active revision and skip), because a retried
	// write after a lost response cannot know whether its first attempt
	// committed.
	Commit(ctx context.Context, expected Revision, doc Document, meta Meta) (Record, error)

	// Activate points the active revision at an already-committed revision,
	// again only when the pointer currently names expected. This is the
	// rollback primitive: history is never rewritten, only re-pointed. The
	// same ErrRevisionMismatch rules apply.
	Activate(ctx context.Context, expected, target Revision) error

	// Migrate brings the schema up to the latest embedded migration. It is
	// forward-only, checksum-validated, and runs under an advisory lock so
	// concurrent instances converge instead of racing DDL. It must be called
	// before the process binds listeners, and an unknown future schema version
	// is an error rather than something to work around.
	Migrate(ctx context.Context) error

	// SchemaVersion reports the schema-migration version currently applied in
	// the database. It is the schema version axis, independent of any
	// document version.
	SchemaVersion(ctx context.Context) (int, error)

	// Close releases the underlying connections.
	Close()
}
