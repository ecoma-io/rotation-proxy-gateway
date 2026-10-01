-- 0001: the durable configuration substrate.
--
-- Two tables and no more. The unit of configuration is one immutable JSON
-- document per revision, not a normalized set of rows: the document is what
-- gets validated and materialized, so normalizing it would mean re-deriving
-- every cross-field rule in SQL instead of reusing the one validator the
-- gateway already has.
--
-- config_revisions is append-only history. A row is never updated and never
-- deleted; "active" is expressed solely by the active_config pointer below.
-- That separation is what makes a revision permanent: rolling back is
-- repointing the pointer at an existing row, never rewriting one.
--
-- The advisory lock taken by the migrator (see store.go) is what serializes
-- this DDL against a second instance starting concurrently. The lock is a
-- session-level pg_advisory_lock held by the migrating connection, so it is
-- released even if that connection dies — a crashed migrator cannot wedge the
-- next boot.

-- The sequence backing config_revisions.revision. Declared first because the
-- table's column default names it: PostgreSQL resolves the default at CREATE
-- TABLE time, so a sequence created afterwards would make the statement fail.
-- OWNED BY ties the sequence's lifetime to the column.
CREATE SEQUENCE IF NOT EXISTS config_revision_seq AS bigint START WITH 1 INCREMENT BY 1;

CREATE TABLE IF NOT EXISTS config_revisions (
    -- Monotonic and strictly increasing. Assigned by the sequence inside the
    -- same transaction that inserts the row, so revision numbers order commits
    -- exactly. A rolled-back insert does consume a sequence value and leaves a
    -- gap in the numbering, which is harmless: a gap makes no uncommitted
    -- revision readable, and revision alone orders history, never contiguity.
    revision     bigint      PRIMARY KEY DEFAULT nextval('config_revision_seq'),
    -- The document version this revision carries. This is the *document*
    -- version axis, deliberately independent of the schema-migration version in
    -- schema_migrations: bumping the document's shape says nothing about the
    -- table layout, and migrating the tables says nothing about the shape of
    -- the documents already stored.
    doc_version  integer     NOT NULL CHECK (doc_version >= 1),
    -- One immutable configuration document, JSON. It carries route
    -- credentials and rotate-API headers, so this column is secret material:
    -- it is never logged, never echoed in an error, and never returned by
    -- anything except the reconciler's own load path.
    document     jsonb       NOT NULL,
    -- Free-form operator attribution, no credentials. Optional.
    author       text,
    note         text,
    -- Creation time is the database's clock, not the writer's: revisions are
    -- ordered by revision, and a writer with a skewed clock must not be able
    -- to reorder history.
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- The history is read newest-first by the reconciler and by any audit view.
-- created_at is a secondary key: revision alone is authoritative.
CREATE INDEX IF NOT EXISTS config_revisions_created_at_idx
    ON config_revisions (created_at DESC);

-- The singleton pointer to the revision that is authoritative right now.
--
-- One row, enforced rather than assumed: the primary key is a constant, so a
-- second row cannot be inserted even by a concurrent writer. Revision is a
-- foreign key with ON DELETE RESTRICT, which is the physical form of "the
-- pointer can only ever name a revision that exists" — and RESTRICT rather
-- than CASCADE, because deleting history out from under a pointer is exactly
-- the failure append-only history exists to prevent.
--
-- revision is nullable for exactly one state: an empty store. It is NOT NULL
-- from the first commit onward, because every commit moves the pointer inside
-- its own transaction. An empty store is a real state a seed writes into, and
-- modelling it as a row beats modelling it as the absence of a row: the absence
-- would make "no configuration has been committed yet" a second code path
-- through every reader, and would break the single-writer atomicity that keeps a
-- rolled-back commit from leaving a pointer behind.
--
-- updated_at is the database clock for the same reason created_at is: the
-- writer's clock is not trusted with ordering.
CREATE TABLE IF NOT EXISTS active_config (
    id          smallint    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    revision    bigint      REFERENCES config_revisions (revision)
                            ON UPDATE RESTRICT ON DELETE RESTRICT,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Exactly one row from the moment the table exists, so the pointer is never
-- absent and no reader has to handle "no active config" as a distinct state at
-- the SQL level. The revision stays NULL when history is empty — that is the
-- empty store — and is back-filled with the oldest committed revision when the
-- migration runs against a store that already has history.
--
-- ON CONFLICT makes concurrent first boots converge on one row instead of
-- colliding on the primary key.
INSERT INTO active_config (id, revision)
SELECT 1, min(revision) FROM config_revisions
ON CONFLICT (id) DO NOTHING;