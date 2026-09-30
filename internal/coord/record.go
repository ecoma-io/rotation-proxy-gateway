package coord

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Record is one manual route's shared rotation state, as the cluster sees it.
//
// It is coordination and diagnostic metadata: which instance is rotating the
// route, at what cluster epoch, with which fencing token, and what egress IPs
// were involved. It holds no credentials — no route URL, no userinfo, no
// rotate-API URL or header, no inbound account. Route identity is the canonical
// route id the pool already uses (canonical URL plus kind), and egress IPs are
// bare addresses, neither of which is secret.
//
// Every IP in this record is canonicalized on the way in (see canonicalIP), so
// `::ffff:1.2.3.4` and `1.2.3.4` are one identity both in storage and in every
// comparison made against it.
type Record struct {
	// Route is the canonical route id: canonical URL plus kind, matching
	// pool.Lookup. It is an identity, not a usable endpoint — it names which
	// route, not how to reach it.
	Route string
	// Epoch is the cluster rotation epoch this rotation committed at, the
	// value the cluster counter actually reached.
	Epoch Epoch
	// State is the phase, one of the RotationState constants.
	State RotationState
	// Owner is the instance identifier that performed the rotation.
	Owner string
	// Token is the fencing token the owner presented and the authority
	// checked when accepting the write. It identifies the acquisition, and
	// therefore the attempt, this record was written by.
	Token uint64
	// StartedAt is when the rotation began, on the owner's clock.
	StartedAt time.Time
	// BaselineIP is the egress IP observed before the rotate call, canonical.
	// Empty when the pre-rotation probe failed.
	BaselineIP string
	// ObservedIP is the egress IP committed after verification, canonical.
	// Empty until a rotation commits.
	ObservedIP string
	// NextRetryAt is when a stale route will retry. Zero when not retrying.
	NextRetryAt time.Time
	// UpdatedAt is when the record was last written, on the owner's clock.
	UpdatedAt time.Time
}

// Commit is the request to record a rotation outcome — either an in-progress
// phase or, with ObservedIP set and state StateCommitted, a terminal success.
type Commit struct {
	// Lease is the caller's held lease. Its Token is the fencing token, and
	// it identifies this rotation attempt.
	Lease Lease
	// Route is the canonical route id.
	Route string
	// BaselineIP is the pre-rotation egress IP. Empty when unverified.
	BaselineIP string
	// ObservedIP is the verified new egress IP. Canonicalized here.
	ObservedIP string
	// StartedAt is when the rotation began, on the caller's clock.
	StartedAt time.Time
}

// commitScript is the single point where the cluster's rotation state changes.
//
// The ARGV order is fixed and mirrored by the named arguments at the Go call
// site in CommitRotation. It is spelled out here because the fencing check is
// the central invariant of this package and the reader must be able to see
// which argument is the fencing token:
//
//	ARGV[1]  fencing token presented by the holder
//	ARGV[2]  owner presenting it
//	ARGV[3]  canonical route id
//	ARGV[4]  observed egress IP (already canonical)
//	ARGV[5]  rotation started_at, unix millis
//	ARGV[6]  baseline egress IP (already canonical)
//	ARGV[7]  write timestamp, unix millis
//	ARGV[8]  record TTL, millis
//
// It does four things atomically:
//
//  1. Fencing, at the point of mutation. A token below the highest this record
//     has already seen is refused outright, and the presented owner must still
//     hold the lease. Both are checked here, on the write path — never at
//     acquisition, which a stale holder passed long ago.
//
//  2. Exactly-once. The record names one attempt via its fencing token, and the
//     authority issues a new token on every acquisition. A commit that lands
//     with a token the record already committed under is therefore a retry of
//     an attempt that already succeeded, and it changes nothing: no second
//     epoch bump, no second record write. This is what makes a duplicated
//     request — a client retry after a timeout, a pub/sub message delivered
//     twice — safe.
//
//  3. Epoch. INCR allocates the new cluster epoch, and the record is stamped
//     with that value in the same step, so there is no window in which the
//     record names an epoch the counter has not reached.
//
//  4. Liveness. PEXPIRE sets the TTL on the whole record, refreshed by every
//     write, so a record is a coherent snapshot rather than fields written at
//     unrelated times.
//
// All four are one script because none of them can be done as a client-side
// read followed by a write: two concurrent commits would both read the
// pre-state and both conclude they were first.
var commitScript = redis.NewScript(`
local record_token = redis.call('HGET', KEYS[4], 'fencing_token')
local issued_token = redis.call('GET', KEYS[2])
local token = tonumber(ARGV[1])

-- 1. Fencing, at the point of mutation.
--
-- The high-water mark is the greater of two values the authority already
-- holds: the token on this route's record, and the lease's own INCR counter,
-- which is every token this lease has ever issued. The counter is the one that
-- matters most, because it is non-zero from the lease's first acquisition —
-- comparing only against the record would leave a stale token unrefused
-- whenever no record had been written yet, which is exactly the window a
-- replaced holder resumes in.
--
-- Taking the maximum is defensive rather than required: a record token is
-- always one this counter issued, so the counter is already at least as high.
-- Expressing it as a maximum keeps the two high-water marks named, so a future
-- change to either cannot silently weaken the other.
local high = tonumber(issued_token or '0')
if record_token and tonumber(record_token) > high then
  high = tonumber(record_token)
end
if high > token then
  return {0, 0, 'fenced'}
end

-- The presented owner must still hold the lease. This is what catches a
-- holder that lost the lease but kept a current-looking token.
if redis.call('GET', KEYS[1]) ~= ARGV[2] then
  return {0, 0, 'not_holder'}
end

-- 2. Exactly-once. A committed record already carrying this token means this
-- exact attempt already committed; a retry must not bump the epoch again.
if record_token and tonumber(record_token) == token
   and redis.call('HGET', KEYS[4], 'state') == 'committed' then
  return {0, tonumber(redis.call('GET', KEYS[3]) or '0'), 'duplicate'}
end

-- 3. Epoch, allocated in the same step as the record write.
local epoch = redis.call('INCR', KEYS[3])

redis.call('HSET', KEYS[4],
  'route', ARGV[3],
  'rotation_epoch', epoch,
  'state', 'committed',
  'owner', ARGV[2],
  'fencing_token', token,
  'started_at', ARGV[5],
  'baseline_ip', ARGV[6],
  'observed_ip', ARGV[4],
  'next_retry_at', '',
  'updated_at', ARGV[7])

-- 4. Liveness: the TTL covers the whole record.
redis.call('PEXPIRE', KEYS[4], ARGV[8])

return {1, epoch, 'committed'}
`)

// CommitRotation records a verified new egress IP as the cluster's answer for a
// route and advances the cluster epoch — atomically, exactly once, and only for
// a holder whose fencing token is still current.
//
// It is the mutation the whole package exists to make safe:
//
//   - A stale holder is refused with ErrFenced. Its token is below the highest
//     the authority recorded for this route, so it does not mutate cluster
//     rotation state, and the record still names the winner's rotation.
//   - A retry of an attempt that already committed is a no-op: no second epoch
//     bump, no second write. The returned epoch is the record's current one.
//   - The epoch is advanced by INCR in the same atomic step as the record, so
//     rotation_epoch is always a value the cluster counter has reached.
//
// The returned Epoch is the new cluster rotation generation. A caller must hand
// it to every instance's warm pool, because a warm connection stamped with an
// older epoch is discarded by internal/warmpool's own epoch check — that is
// what makes the epoch cluster-wide rather than local.
//
// ErrNotHolder reports that the presented owner no longer holds the lease. It is
// distinct from ErrFenced: the token may be current while the lease has moved.
func (s *Store) CommitRotation(ctx context.Context, c Commit) (Epoch, bool, error) {
	if c.Lease.IsZero() {
		return NoEpoch, false, ErrNoLease
	}
	if c.Route == "" {
		return NoEpoch, false, errors.New("a commit must name a route")
	}
	observed := canonicalIP(c.ObservedIP)
	if observed == "" {
		// Refuse to record an address we cannot canonicalize. An unparsed
		// value could never be compared correctly later, so storing it would
		// guarantee some future rotation misreads it as a change of address.
		return NoEpoch, false, errors.New("a commit must carry a parseable observed egress IP")
	}
	baseline := canonicalIP(c.BaselineIP)
	now := time.Now()
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()

	// The argument order below is the one commitScript documents. The fencing
	// token is ARGV[1] and is deliberately the first thing the Lua reads.
	res, err := commitScript.Run(ctx, s.rdb,
		[]string{s.leaseKey(c.Lease.Name), s.leaseSeqKey(c.Lease.Name), s.epochKey(), s.rotationKey(c.Route)},
		strconv.FormatUint(c.Lease.Token, 10), // 1 fencing token
		c.Lease.Owner,                         // 2 owner
		c.Route,                               // 3 canonical route id
		observed,                              // 4 observed egress IP
		strconv.FormatInt(c.StartedAt.UnixMilli(), 10), // 5 started_at
		baseline,                               // 6 baseline egress IP
		strconv.FormatInt(now.UnixMilli(), 10), // 7 updated_at
		strconv.FormatInt(RecordTTL.Milliseconds(), 10), // 8 record TTL
	).Slice()
	if err != nil {
		return NoEpoch, false, fmt.Errorf("commit rotation: %w", err)
	}
	if len(res) != 3 {
		return NoEpoch, false, fmt.Errorf("commit rotation: unexpected script reply of %d fields", len(res))
	}
	ok, _ := res[0].(int64)
	epochVal, err := asUint(res[1])
	if err != nil {
		return NoEpoch, false, fmt.Errorf("commit rotation: reading the cluster epoch: %w", err)
	}
	status, _ := res[2].(string)
	switch {
	case ok == 1:
		return Epoch(epochVal), true, nil
	case status == "fenced":
		return NoEpoch, false, ErrFenced
	case status == "not_holder":
		return NoEpoch, false, ErrNotHolder
	case status == "duplicate":
		// This attempt already committed. The epoch the record holds is
		// returned so a retrying caller still learns the cluster generation,
		// but nothing was mutated.
		return Epoch(epochVal), false, nil
	default:
		return NoEpoch, false, fmt.Errorf("commit rotation: unexpected script status %q", status)
	}
}

// phaseScript writes an in-progress rotation phase into the record, fenced the
// same way a commit is.
//
// Phase writes are fenced because a replaced holder must not be able to
// overwrite the record's state field with a phase from a rotation the cluster
// has already superseded — that would make /status and any peer reading the
// record report a rotation that never won. A phase write never advances the
// epoch and never sets observed_ip; only CommitRotation does that.
//
// The epoch argument is the epoch the writer believes is current, purely as
// record metadata. It is not allocated here: allocating it in a phase write
// would advance the cluster generation on a rotation that has not succeeded.
var phaseScript = redis.NewScript(`
local record_token = redis.call('HGET', KEYS[3], 'fencing_token')
local issued_token = redis.call('GET', KEYS[2])
local token = tonumber(ARGV[1])

-- The same high-water mark as commitScript: the greater of the record's token
-- and the lease's INCR counter. A phase write from a replaced holder must be
-- refused for exactly the same reason a commit would be — otherwise a stale
-- holder could still overwrite the state field of a rotation it lost.
local high = tonumber(issued_token or '0')
if record_token and tonumber(record_token) > high then
  high = tonumber(record_token)
end
if high > token then
  return 0
end
if redis.call('GET', KEYS[1]) ~= ARGV[2] then
  return -1
end

redis.call('HSET', KEYS[3],
  'route', ARGV[3],
  'rotation_epoch', ARGV[4],
  'state', ARGV[5],
  'owner', ARGV[2],
  'fencing_token', token,
  'started_at', ARGV[6],
  'baseline_ip', ARGV[7],
  'observed_ip', ARGV[8],
  'next_retry_at', ARGV[9],
  'updated_at', ARGV[10])

redis.call('PEXPIRE', KEYS[3], ARGV[11])
return 1
`)

// Phase records an in-progress rotation phase for a route.
//
// A fenced holder gets ErrFenced and a holder that lost the lease gets
// ErrNotHolder, neither of which changes the record. Phase never advances the
// cluster epoch and never sets observed_ip; a stale route's next retry is
// carried in nextRetry so a peer can see when the route will try again.
func (s *Store) Phase(ctx context.Context, c Commit, state RotationState, epoch Epoch, nextRetry time.Time) error {
	if c.Lease.IsZero() {
		return ErrNoLease
	}
	if c.Route == "" {
		return errors.New("a phase must name a route")
	}
	baseline := canonicalIP(c.BaselineIP)
	observed := canonicalIP(c.ObservedIP)
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()

	// Same fixed order phaseScript documents; the token is ARGV[1].
	res, err := phaseScript.Run(ctx, s.rdb,
		[]string{s.leaseKey(c.Lease.Name), s.leaseSeqKey(c.Lease.Name), s.rotationKey(c.Route)},
		strconv.FormatUint(c.Lease.Token, 10),          // 1 fencing token
		c.Lease.Owner,                                  // 2 owner
		c.Route,                                        // 3 canonical route id
		strconv.FormatUint(uint64(epoch), 10),          // 4 believed epoch
		string(state),                                  // 5 state
		strconv.FormatInt(c.StartedAt.UnixMilli(), 10), // 6 started_at
		baseline, // 7 baseline egress IP
		observed, // 8 observed egress IP
		strconv.FormatInt(nextRetry.UnixMilli(), 10),    // 9 next_retry_at
		strconv.FormatInt(time.Now().UnixMilli(), 10),   // 10 updated_at
		strconv.FormatInt(RecordTTL.Milliseconds(), 10), // 11 record TTL
	).Int64()
	switch {
	case errors.Is(err, redis.Nil):
		return ErrNoLease
	case err != nil:
		return fmt.Errorf("record rotation phase: %w", err)
	}
	switch {
	case res == 1:
		return nil
	case res == 0:
		return ErrFenced
	default:
		return ErrNotHolder
	}
}

// Rotation reads a route's shared rotation record.
//
// A route with no record is not an error: it means the route has not rotated
// since the record TTL lapsed, which is a state to serve from, not a failure.
// The error is a report; the caller's previous local state is unchanged either
// way.
func (s *Store) Rotation(ctx context.Context, route string) (Record, bool, error) {
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	fields, err := s.rdb.HGetAll(ctx, s.rotationKey(route)).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return Record{Route: route}, false, fmt.Errorf("read shared rotation record: %w", err)
	}
	if len(fields) == 0 {
		return Record{Route: route}, false, nil
	}
	rec := Record{
		Route:       fields[FieldRoute],
		State:       RotationState(fields[FieldState]),
		Owner:       fields[FieldOwner],
		BaselineIP:  fields[FieldBaselineIP],
		ObservedIP:  fields[FieldObservedIP],
		StartedAt:   unixMilli(fields[FieldStartedAt]),
		NextRetryAt: unixMilli(fields[FieldNextRetryAt]),
		UpdatedAt:   unixMilli(fields[FieldUpdatedAt]),
	}
	if v, err := strconv.ParseUint(fields[FieldEpoch], 10, 64); err == nil {
		rec.Epoch = Epoch(v)
	}
	if v, err := strconv.ParseUint(fields[FieldToken], 10, 64); err == nil {
		rec.Token = v
	}
	return rec, true, nil
}

// unixMilli parses a millisecond timestamp field, returning the zero time for
// absent or unparseable values so a partially-written record stays readable
// rather than becoming an error.
func unixMilli(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.UnixMilli(v)
}
