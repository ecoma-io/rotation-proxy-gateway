-- 0001: the durable analytics / history substrate.
--
-- Four tables, and one rule that shapes all of them: nothing here is a source of
-- truth. Route health, cooldown, eligibility and rotation state live in
-- internal/pool, in this process's memory, and stay there. These tables are
-- write-only from the runtime's point of view — the gateway appends observations
-- to them and never reads one back to decide what to serve. That is what makes
-- a lagging, empty, or failed analytics store unable to change proxy behavior:
-- losing all of it is a loss of history, never a correctness or availability bug.
--
-- Every event row carries `event_id`, a stable per-observation identity minted
-- once from crypto/rand at the moment the observation is emitted. It is the
-- idempotency key: a writer that crashes after the server accepted an INSERT but
-- before it learned of it retries the identical row, the primary key rejects it,
-- and the replay is a no-op instead of a double count. A retry is safe because it
-- carries the same event_id, and nothing ever mints one twice.
--
-- The two aggregate tables have no event_id, because they are counters rather
-- than events: their primary key IS the bucket identity, and a flush carries the
-- delta since the previous flush rather than a cumulative total, so a replayed
-- flush adds the same delta twice. The writer therefore never re-presents a
-- delta it has already presented — a delta leaves the buffer exactly once — and
-- the ON CONFLICT DO UPDATE is a safety net for the one case a buffer cannot
-- cover (a process that dies after the server committed but before the writer
-- learned of it), not the design's load-bearing path.
--
-- The version axis here is the schema-migration version in schema_migrations,
-- the same axis internal/configstore advances. It says nothing about the shape of
-- any configuration document; the two axes stay apart for the same reason they
-- do there.
--
-- The advisory lock taken by the migrator (see store.go) serializes this DDL
-- against a second instance starting concurrently, exactly as it does for the
-- configuration substrate.

-- One rotation attempt, from drain to terminal outcome.
--
-- A row is written once, at the end of the attempt, whether it rotated or not.
-- The writer retries on failure with the same event_id, so a crash between the
-- attempt and its INSERT costs one history row, never two.
--
-- IP columns are `inet`, and the writer canonicalizes every address through
-- netip.Addr.Unmap() before binding it. PostgreSQL does NOT do this itself: an
-- IPv4-mapped IPv6 literal is a distinct family-6 inet that compares UNEQUAL to
-- the IPv4 address it denotes, so '::ffff:1.2.3.4' <> '1.2.3.4' under `=`. The
-- canonical form is therefore stored, which is what makes one egress address one
-- identity across the whole store rather than two spellings of it — the same
-- invariant internal/pool enforces through IPIdentity and CanonicalIP.
CREATE TABLE IF NOT EXISTS rotation_history (
    -- The stable identity of this attempt record. Minted once, when the attempt
    -- is emitted, and reused verbatim by every retry of that record: a second
    -- INSERT of the same event_id is rejected by the primary key, which is what
    -- makes a replay a no-op rather than a duplicate row.
    event_id        text        PRIMARY KEY,
    -- The instance that ran the procedure, so a cluster's history says which
    -- replica performed which attempt.
    instance        text        NOT NULL,
    -- Route identity: canonical URL host, egress kind, and origin. The full
    -- canonical route ID is deliberately NOT stored, because it embeds the
    -- route's SOCKS userinfo and a durable row outlives the config that made it
    -- secret. Host only, exactly as the logs and /status report a route.
    route_host      text        NOT NULL,
    route_kind      text        NOT NULL,
    route_origin    text        NOT NULL,
    -- Always 'manual' in this build: the rotation engine only ever drives manual
    -- routes. Carried as a column rather than baked into the table so a future
    -- mode does not have to reinterpret existing rows.
    mode            text        NOT NULL,
    -- The route's rotation generation this attempt ran under, read from
    -- pool.Proxy.RotationEpoch. Anything stamped with an older epoch provably
    -- predates the route's next verified egress IP, so this column is what lets a
    -- reader tell which rotation generation a recorded IP belonged to.
    rotation_epoch  bigint      NOT NULL,
    started_at      timestamptz NOT NULL,
    ended_at        timestamptz NOT NULL,
    duration_ms     bigint      NOT NULL CHECK (duration_ms >= 0),
    -- A small closed vocabulary, never an error string. The CHECK is what keeps
    -- an out-of-vocabulary value from arriving through a code path that forgot
    -- to map its outcome.
    outcome         text        NOT NULL CHECK (outcome IN (
                       'rotated', 'unchanged_ip', 'api_failed', 'aborted'
                   )),
    -- Fixed labels only, never sanitized error text: 'none' when the attempt
    -- reached a verified terminal state, otherwise why it did not.
    failure_kind    text        NOT NULL DEFAULT 'none',
    -- Canonical (Unmap'd) egress IPs. NULL when the attempt learned none: an
    -- unverified baseline, a provider that never answered, a route removed
    -- mid-procedure.
    baseline_ip     inet,
    observed_ip     inet,
    -- How many times this attempt ran: rotate-API call count, and the
    -- verify-window probe count that produced the observed address. 0 when
    -- either stage never ran.
    api_attempts    integer     NOT NULL DEFAULT 0 CHECK (api_attempts >= 0),
    probe_attempts  integer     NOT NULL DEFAULT 0 CHECK (probe_attempts >= 0),
    -- The configuration revision serving at the attempt's start, or NULL when
    -- the instance was running on its local seed file rather than a durable
    -- revision. Audit metadata only: it is read from the generation the
    -- procedure already held and never queried for.
    config_revision bigint,
    -- The run of consecutive same-IP outcomes ending at this attempt. A rotated
    -- attempt records 0, because a successful rotation clears the run.
    consecutive_same_ip integer NOT NULL DEFAULT 0 CHECK (consecutive_same_ip >= 0),
    recorded_at     timestamptz NOT NULL DEFAULT now()
);

-- History is read newest-first for an audit view, and filtered by route for a
-- per-route question ("when did this route last change IP").
CREATE INDEX IF NOT EXISTS rotation_history_recorded_at_idx
    ON rotation_history (recorded_at DESC);

CREATE INDEX IF NOT EXISTS rotation_history_route_idx
    ON rotation_history (route_host, route_kind, recorded_at DESC);

-- One egress IP a route was observed serving from, over time.
--
-- The question this table answers is "which IP did this route serve, when, and
-- did it revisit an earlier one" — so a row is one observation, and the revisit
-- flag is stored rather than reconstructed by a reader.
--
-- The primary key is the observation identity: (route, instant, address).
-- Re-recording the same observation of the same address at the same instant is
-- the same row, so a writer retrying an insert cannot double it. One route
-- cannot produce two genuinely distinct observations of one address at one
-- instant, so collapsing them loses nothing.
CREATE TABLE IF NOT EXISTS ip_history (
    route_host   text        NOT NULL,
    route_kind   text        NOT NULL,
    route_origin text        NOT NULL,
    egress_ip    inet        NOT NULL,
    observed_at  timestamptz NOT NULL,
    -- How this address came to be known: the boot baseline probe, or a verified
    -- rotation commit.
    source       text        NOT NULL CHECK (source IN ('baseline', 'rotation')),
    -- Whether this route had already verified this address earlier in its
    -- lifetime. It is pool.Proxy.EndRotation's revisit decision, recorded at
    -- commit time — the one place that decision is made, not a reader's
    -- reconstruction of it.
    revisit      boolean     NOT NULL DEFAULT false,
    rotation_epoch bigint     NOT NULL,
    instance     text        NOT NULL,
    -- A readable rendering of egress_ip, so an operator query and an exported
    -- report do not each have to remember PostgreSQL's inet formatting. Written
    -- from the same canonical value the inet column is bound from.
    egress_ip_text text      NOT NULL,
    PRIMARY KEY (route_host, route_kind, observed_at, egress_ip)
);

-- Read newest-first per route; also the path for "did this route ever use this
-- address", which is the revisit question.
CREATE INDEX IF NOT EXISTS ip_history_route_time_idx
    ON ip_history (route_host, route_kind, observed_at DESC);

CREATE INDEX IF NOT EXISTS ip_history_address_idx
    ON ip_history (egress_ip, observed_at DESC);

-- Rolled-up request and traffic counters.
--
-- There is deliberately no per-request table, and adding one is the mistake this
-- schema exists to prevent: a proxy's request rate is unbounded and its request
-- content is client-controlled. The request path only increments counters held
-- in memory (see Recorder.Observe); the writer folds them into a bucket row
-- here. Nothing on the serving path ever writes this table.
CREATE TABLE IF NOT EXISTS request_aggregates (
    bucket_start  timestamptz NOT NULL,
    route_host    text        NOT NULL,
    route_kind    text        NOT NULL,
    route_origin  text        NOT NULL,
    -- The listener the request arrived on, and the family the request asked
    -- for. Both are coarse, non-identifying views an operator aggregates by;
    -- the client's correlation id and its target host are deliberately absent.
    listener      text        NOT NULL,
    family        text        NOT NULL,
    requests      bigint      NOT NULL DEFAULT 0 CHECK (requests >= 0),
    successes     bigint      NOT NULL DEFAULT 0 CHECK (successes >= 0),
    failures      bigint      NOT NULL DEFAULT 0 CHECK (failures >= 0),
    -- Tunnel bytes in both directions, summed. Counts, never payload.
    to_client_bytes   bigint NOT NULL DEFAULT 0 CHECK (to_client_bytes >= 0),
    to_upstream_bytes bigint NOT NULL DEFAULT 0 CHECK (to_upstream_bytes >= 0),
    -- The instance that accumulated this bucket. A cluster's rows from different
    -- replicas sum, and this column says which contributed what.
    instance      text        NOT NULL,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (bucket_start, route_host, route_kind, listener, family)
);

-- The read an operator actually runs: totals per route over a window.
CREATE INDEX IF NOT EXISTS request_aggregates_route_idx
    ON request_aggregates (route_host, route_kind, bucket_start DESC);

-- Failure analytics, bucketed by outcome rather than recorded raw.
--
-- A failure is counted against (route, error kind, target host) inside a time
-- bucket. The target host is host-only: no port, no path, no query, and never a
-- userinfo-shaped value. The error_kind vocabulary is a small closed set, and
-- the human-readable text stays in the process log where the log's own
-- redaction applies.
CREATE TABLE IF NOT EXISTS failure_events (
    bucket_start  timestamptz NOT NULL,
    route_host    text        NOT NULL,
    route_kind    text        NOT NULL,
    -- One of the stable error-kind labels internal/proxyserver logs: setup,
    -- proxy_connect, socks_connect, auth_route, connect_target, no_route,
    -- retry_exhausted. A closed vocabulary, never an error string.
    error_kind    text        NOT NULL,
    -- Host-only target, from the same helper the logs use. The empty string
    -- rather than NULL means "this failure had no target" (an upstream never
    -- reached, a request rejected before a target was parsed). A nullable column
    -- cannot participate in a primary key, and the bucket identity must include
    -- this dimension or failures of the same kind on the same route but
    -- different targets would collapse into one row. The CHECK keeps ''
    -- meaning exactly that, and keeps a userinfo-shaped value out of a durable
    -- row even if a future caller forgets to strip it.
    target_host   text        NOT NULL DEFAULT '',
    listener      text        NOT NULL,
    family        text        NOT NULL,
    failures      bigint      NOT NULL DEFAULT 0 CHECK (failures >= 0),
    instance      text        NOT NULL,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (bucket_start, route_host, route_kind, error_kind, target_host, listener, family),
    CHECK (target_host = '' OR target_host !~ '@')
);

-- Bucketed reads: "failures of this kind on this route over this window".
CREATE INDEX IF NOT EXISTS failure_events_kind_idx
    ON failure_events (error_kind, bucket_start DESC);

CREATE INDEX IF NOT EXISTS failure_events_route_idx
    ON failure_events (route_host, route_kind, bucket_start DESC);
