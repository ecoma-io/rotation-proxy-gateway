// Package analyticsstore is the durable, append-only home of the gateway's
// operational history: rotation attempts, the egress IPs routes served from,
// rolled-up request and traffic counters, and bucketed failure analytics.
//
// The one property everything here is built around: this store is never a
// source of truth. Route health, cooldown, eligibility, and rotation state live
// in internal/pool, in this process's memory, and stay there. Nothing in the
// serving path reads a row from this package to decide what to do — a request's
// entire interaction with the store is an in-memory counter increment, and the
// writer goroutine turns those into rows later. A store that is empty, behind,
// or entirely down therefore costs history and nothing else: the proxy keeps
// serving with unchanged health, unchanged selection, and unchanged latency.
//
// Two write paths, with different identities:
//
//   - Event rows (rotation_history, ip_history) carry an EventID minted once
//     from crypto/rand when the observation is emitted. A retry re-presents the
//     same ID, the primary key rejects it, and the replay is a no-op. This is
//     what makes a crash between "the server accepted the INSERT" and "the
//     writer learned of it" cost nothing.
//   - Aggregate rows (request_aggregates, failure_events) are counters, not
//     events. Their primary key is the bucket identity and a flush carries the
//     delta since the previous flush, so they have no per-observation ID to
//     dedupe on; the buffer instead guarantees a delta leaves it exactly once
//     and the upsert adds rather than replaces.
//
// Secret handling: no route credential, inbound account, Proxy-Authorization
// value, rotate-API URL, header, or body reaches this package as data at all.
// Route identity is host + kind + origin, and egress IPs and target hosts are
// the only other values stored. The store's errors name tables, columns, and
// counts only.
package analyticsstore

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"
)

// EventID is the stable identity of one recorded observation. It is minted from
// crypto/rand and never re-minted for the same observation, which is what makes
// a write idempotent: replaying a batch re-presents the same IDs, and the
// tables' primary keys reject them.
type EventID string

// String renders the id for logs and error text. It carries no observation
// content, only the random identity.
func (e EventID) String() string { return string(e) }

// IsZero reports an unassigned id. A zero id is never minted and never written;
// treating one as an error rather than a row is what stops a caller that
// forgot to mint from inserting a constant primary key that would collide with
// every later one.
func (e EventID) IsZero() bool { return e == "" }

// RotationOutcome is how a rotation attempt ended. A small closed vocabulary:
// the store's own CHECK constraint rejects anything outside it, so a new
// terminal state has to be added here and migrated deliberately rather than
// arriving as a free-text string from a code path that forgot to map it.
type RotationOutcome string

const (
	// OutcomeRotated: the route committed a verified egress IP that differed
	// from its baseline. The only outcome that advances the route's rotation
	// counter.
	OutcomeRotated RotationOutcome = "rotated"
	// OutcomeUnchangedIP: verification ran and the egress IP did not change. The
	// route keeps serving in the stale state and retries with backoff.
	OutcomeUnchangedIP RotationOutcome = "unchanged_ip"
	// OutcomeAPIFailed: the provider's rotate call returned a non-2xx or could
	// not be made. The route is unchanged by the call, though a provider can
	// still have rotated anyway — which is why verification still ran.
	OutcomeAPIFailed RotationOutcome = "api_failed"
	// OutcomeAborted: the attempt ended without a terminal rotation state — the
	// engine is shutting down, or a reload removed or replaced the route. Not a
	// failure of the provider, and deliberately not counted as one.
	OutcomeAborted RotationOutcome = "aborted"
)

// RouteKey is how a route is identified in every row of this store: the
// canonical URL host, the egress kind, and the origin.
//
// Host-only on purpose. config.CanonicalRouteID embeds the route's SOCKS
// userinfo ("socks5://user:pass@host:port"), which is correct for an in-memory
// identity key and wrong for a durable row: an analytics row outlives the
// configuration revision that made the credential secret, and an operator
// querying history should never be handed a password. So this package records
// the host, and the same rule the logs and /status already follow applies.
type RouteKey struct {
	// Host is the route URL's Host (host:port), which excludes URL userinfo.
	Host string
	// Kind is the provider-backed public egress IP family, "v4" or "v6".
	Kind string
	// Origin is "auto" or "manual".
	Origin string
}

// RouteKeyFor derives the analytics identity of a route from the pool route it
// serves. It reads only the credential-free parts of the URL, so no caller can
// pass userinfo through by accident.
func RouteKeyFor(urlHost, kind, origin string) RouteKey {
	return RouteKey{Host: urlHost, Kind: kind, Origin: origin}
}

// String renders the key for a log line or an error. Host-only by construction.
func (k RouteKey) String() string {
	return k.Host + "|" + k.Kind + "|" + k.Origin
}

// IPHistorySource is how an egress address came to be known.
type IPHistorySource string

const (
	// SourceBaseline: the boot precheck probe, before any rotation ran.
	SourceBaseline IPHistorySource = "baseline"
	// SourceRotation: a verified rotation commit.
	SourceRotation IPHistorySource = "rotation"
)

// RotationAttempt is one rotation procedure, from drain to terminal outcome.
//
// Every field is either a fixed label, a count, a canonical IP, or a host. The
// attempt's error text is deliberately absent: a rotate-API failure's message
// can quote the provider's URL, and the human-readable detail belongs in the
// process log, where internal/sanitize already governs it.
type RotationAttempt struct {
	// EventID is the attempt's idempotency key. The caller mints it once, when
	// the attempt is emitted, and the writer reuses it across every retry.
	EventID EventID
	// Instance names the process that ran the attempt, so a cluster's history
	// says which replica performed it.
	Instance string
	Route    RouteKey
	// Mode is "manual" in this build: the rotation engine drives only manual
	// routes.
	Mode string
	// RotationEpoch is the route's rotation generation this attempt ran under,
	// read from pool.Proxy.RotationEpoch. Anything stamped with an older epoch
	// provably predates the route's next verified egress IP.
	RotationEpoch uint64
	StartedAt     time.Time
	EndedAt       time.Time
	Outcome       RotationOutcome
	// FailureKind is a fixed label ("none" when the attempt reached a verified
	// terminal state), never sanitized error text.
	FailureKind string
	// BaselineIP and ObservedIP are already canonical; the store canonicalizes
	// again on the way in, so a caller that pre-canonicalized and one that did
	// not store the same value.
	BaselineIP string
	ObservedIP string
	// APIAttempts and ProbeAttempts count the rotate call and the verify
	// probes this attempt made.
	APIAttempts   int
	ProbeAttempts int
	// ConfigRevision is the durable configuration revision serving at the
	// attempt's start, or zero for an instance running on its local seed file.
	ConfigRevision int64
	// ConsecutiveSameIP is the run of same-IP outcomes ending at this attempt.
	ConsecutiveSameIP int
}

// Duration reports the attempt's wall duration, floored at zero so a clock
// adjustment mid-attempt cannot produce a negative stored value.
func (a RotationAttempt) Duration() time.Duration {
	d := a.EndedAt.Sub(a.StartedAt)
	if d < 0 {
		return 0
	}
	return d
}

// IPObservation is one egress address a route was seen serving from.
type IPObservation struct {
	Route RouteKey
	// IP is canonicalized through Unmap before storage, so an IPv4-mapped IPv6
	// literal and the IPv4 address it denotes are one identity here exactly as
	// they are in internal/pool.
	IP         string
	ObservedAt time.Time
	Source     IPHistorySource
	// Revisit is pool.Proxy.EndRotation's decision, recorded at commit time —
	// the one place it is made, not a reader's reconstruction of it.
	Revisit       bool
	RotationEpoch uint64
	Instance      string
}

// RequestSample is the rolled-up contribution of one (route, listener, family,
// bucket) to request_aggregates: deltas since the previous flush, never a
// cumulative total. A delta leaves the buffer exactly once, which is what makes
// a replay impossible rather than merely unlikely.
type RequestSample struct {
	Route    RouteKey
	Listener string
	Family   string
	// BucketStart is the start of the time bucket these counters belong to,
	// truncated by the writer to the bucket width.
	BucketStart time.Time
	Requests    int64
	Successes   int64
	Failures    int64
	// ToClientBytes and ToUpstreamBytes are tunnel byte counts. Counts only,
	// never payload: no byte of proxied content is ever stored.
	ToClientBytes   int64
	ToUpstreamBytes int64
	Instance        string
}

// FailureSample is the rolled-up contribution of one (route, error kind, target
// host, listener, family, bucket) to failure_events. Bucketed, never raw: the
// error text is not part of it.
type FailureSample struct {
	Route     RouteKey
	ErrorKind string
	// TargetHost is host-only, from the same helper the logs use. Empty means
	// the failure had no target.
	TargetHost  string
	Listener    string
	Family      string
	BucketStart time.Time
	Failures    int64
	Instance    string
}

// ErrEmptyIdentity reports a write whose idempotency key was never assigned. It
// is a programming error rather than a store condition: a zero EventID would
// collide with every other zero EventID, so it is refused instead of stored.
var ErrEmptyIdentity = errors.New("analytics event id must not be empty")

// ErrNoDSN reports that no durable analytics store is configured. Every
// recording path returns it — or simply does nothing, when the caller holds a
// nil Recorder — so "analytics is off" is one state with one name rather than a
// scattering of silent nil checks.
var ErrNoDSN = errors.New("no durable analytics store is configured")

// canonicalizeIP returns the one identity an address literal has, or "" for a
// value that is not an address at all.
//
// Unmap is the whole point: it folds an IPv4-mapped IPv6 address
// (::ffff:1.2.3.4) onto the IPv4 address it denotes (1.2.3.4), so the two
// spellings of one egress address cannot become two rows or two identities. This
// mirrors internal/pool's IPIdentity/CanonicalIP, which enforce the same
// invariant in memory, and it is done here rather than in SQL because
// PostgreSQL's inet does not do it: '::ffff:1.2.3.4' is a family-6 inet that
// compares unequal to '1.2.3.4'.
//
// A value that does not parse is rejected rather than stored verbatim. A probe
// only ever yields a parsed address, so a non-address here is a caller bug, and
// storing it would create an identity that can never match anything — the exact
// defect internal/pool's parseIPLine guards against.
func canonicalizeIP(value string) (string, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return "", fmt.Errorf("analytics IP %q is not an address literal", value)
	}
	return addr.Unmap().String(), nil
}

// optionalIP canonicalizes an address that may legitimately be absent — a
// rotation attempt that learned no baseline, an observation with no address. An
// empty input stays empty; a non-empty unparseable one is still an error.
func optionalIP(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	return canonicalizeIP(value)
}

// bucketOf truncates t to the start of its bucket of the given width. Buckets
// are aligned to the width in wall-clock terms, so two instances with skewed
// clocks still land in the same bucket for the same instant only if their
// clocks agree; the width is minutes, which is far coarser than the skew a
// cluster tolerates.
func bucketOf(t time.Time, width time.Duration) time.Time {
	if width <= 0 {
		return t
	}
	return t.Truncate(width)
}

// DefaultBucketWidth is the aggregation window. One minute is short enough that
// a recent window is answerable and long enough that a busy proxy's flush rate
// is a small fraction of its request rate.
//
// It is the unit the aggregation tables are keyed by, so it is exported: a
// reader querying request_aggregates or failure_events has to know it, and a
// caller building a label needs the same value the writer uses. Changing it
// needs a migration, because a bucket_start already written under the old width
// is not comparable with one written under a new one.
const DefaultBucketWidth = time.Minute

// Count reports the writer's drop accounting. Every field is a monotonic count
// of samples the buffer refused to hold; none of them is an error, because none
// of them changed what the proxy did.
type Count struct {
	// RotationAttempts, IPObservations, RequestSamples and FailureSamples are
	// event rows written since the writer started.
	RotationAttempts uint64
	IPObservations   uint64
	RequestSamples   uint64
	FailureSamples   uint64
	// Dropped* count samples discarded because the buffer was full. The oldest
	// sample of the same kind is dropped, so what survives is the most recent
	// history rather than a prefix of it.
	DroppedRotationAttempts uint64
	DroppedIPObservations   uint64
	DroppedRequestSamples   uint64
	DroppedFailureSamples   uint64
	// Flushes counts successful batch commits; Failures counts failed ones
	// (each of which is retried with backoff).
	Flushes  uint64
	Failures uint64
}

// String renders the counts for a log line. Numbers only.
func (c Count) String() string {
	return "rotations=" + strconv.FormatUint(c.RotationAttempts, 10) +
		" dropped_rotations=" + strconv.FormatUint(c.DroppedRotationAttempts, 10) +
		" request_samples=" + strconv.FormatUint(c.RequestSamples, 10) +
		" dropped_request_samples=" + strconv.FormatUint(c.DroppedRequestSamples, 10) +
		" failures_samples=" + strconv.FormatUint(c.FailureSamples, 10) +
		" flushes=" + strconv.FormatUint(c.Flushes, 10) +
		" write_failures=" + strconv.FormatUint(c.Failures, 10)
}

// AnalyticsStatus is the safe operational view of the writer, shaped for /status.
//
// It carries counters only. There is no DSN, no host, no table name, no schema
// version, and no sample content anywhere in it: /status is an unauthenticated
// endpoint on an admin listener whose exposure is the operator's decision, so
// anything added here is public by default and must be worth being public.
//
// The drop counts are the reason this type exists at all. A quiet
// request_aggregates table is ambiguous between "no traffic" and "the buffer
// overflowed and the rows were never written", and only the second one loses
// history. Publishing the drops makes the distinction answerable without a
// database query and without trusting the table.
type AnalyticsStatus struct {
	Enabled bool `json:"enabled"`
	// Instance names the process the rows come from, matching the instance
	// column, so a cluster's /status figures can be attributed.
	Instance string `json:"instance"`
	// BucketWidth is the aggregation window request_aggregates and
	// failure_events are keyed by. It is reported because a reader of those
	// tables needs it and because it is the only way to interpret a bucket count
	// as a rate.
	BucketWidth string `json:"bucketWidth"`
	// BufferSize is the per-kind in-memory bound. An operator comparing it with
	// Dropped* can see how far past the bound the instance is running.
	BufferSize int `json:"bufferSize"`
	Count
}

// Status reports the safe operational view. It is nil-safe, so /status can call
// it on a disabled recorder and receive an explicit Enabled:false rather than
// having to branch.
func (r *Recorder) Status() AnalyticsStatus {
	if !r.Enabled() {
		return AnalyticsStatus{}
	}
	return AnalyticsStatus{
		Enabled:     true,
		Instance:    r.instance,
		BucketWidth: r.writer.opts.BucketWidth.String(),
		BufferSize:  r.writer.opts.BufferSize,
		Count:       r.writer.Count(),
	}
}
