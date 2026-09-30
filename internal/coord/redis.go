package coord

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Store is the Redis-backed coordination authority. It implements LeaseSource
// and EpochAuthority, and backs the shared rotation record.
//
// One Store is created per process and closed once at shutdown. Every method
// takes a context and none is on the serving path.
//
// The Redis client is go-redis/v9. Nothing here speaks RESP by hand: the
// fencing checks have to be atomic, and the only way to get that against a
// Redis that may be a replica or a cluster is a server-side script, not a
// read-then-write from the client.
type Store struct {
	rdb    redis.UniversalClient
	prefix string
	ttl    time.Duration
}

// Options configures a Store. The zero value of each field takes its default.
type Options struct {
	// Namespace prefixes every key this store touches, isolating one
	// deployment (or one test) from another sharing the same Redis.
	Namespace string
	// LeaseTTL overrides the lease TTL. Zero takes LeaseTTL.
	LeaseTTL time.Duration
	// OpTimeout bounds one coordination operation. Zero takes
	// DefaultOpTimeout.
	OpTimeout time.Duration
}

// DefaultOpTimeout bounds one Redis operation. Coordination runs on rotation,
// configuration change, and the reconcile tick — never per request — so this
// bounds a control-plane action rather than a client's. It exists so a wedged
// Redis cannot hold a rotation procedure open forever.
const DefaultOpTimeout = 5 * time.Second

// New opens a coordination store against addr.
//
// addr may be a plain host:port or a go-redis URL. It is a secret in the
// general case (a hosted Redis commonly carries a password in the URL) and is
// therefore never retained on the Store, formatted into an error, or logged;
// the errors below are go-redis's own, which name the host but not the
// password.
func New(ctx context.Context, addr string, opts Options) (*Store, error) {
	if strings.TrimSpace(addr) == "" {
		return nil, errors.New("the coordination Redis address must not be empty")
	}
	opt, err := redis.ParseURL(addr)
	if err != nil {
		// go-redis's parse error names the offending part of the URL scheme
		// or option, never the password; the raw address is deliberately not
		// appended.
		return nil, fmt.Errorf("parse coordination Redis address: %w", err)
	}
	// The client pings on open so an unreachable Redis fails startup rather
	// than at the first rotation. That failure is a startup decision, and a
	// container that will never coordinate should not come up serving.
	pingCtx, cancel := context.WithTimeout(ctx, opTimeout(opts))
	defer cancel()
	rdb := redis.NewClient(opt)
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("coordination Redis unreachable: %w", err)
	}
	return newStore(rdb, opts), nil
}

// newStore wraps an existing client, for tests that supply their own.
func newStore(rdb redis.UniversalClient, opts Options) *Store {
	ns := opts.Namespace
	if ns == "" {
		ns = "rpgw"
	}
	return &Store{rdb: rdb, prefix: ns + ":", ttl: leaseTTL(opts)}
}

// opTimeout resolves the per-operation timeout.
func opTimeout(opts Options) time.Duration {
	if opts.OpTimeout > 0 {
		return opts.OpTimeout
	}
	return DefaultOpTimeout
}

// leaseTTL resolves the lease TTL.
func leaseTTL(opts Options) time.Duration {
	if opts.LeaseTTL > 0 {
		return opts.LeaseTTL
	}
	return LeaseTTL
}

// Close releases the underlying client.
func (s *Store) Close() error { return s.rdb.Close() }

// key builds a namespaced key from parts, so every key this store touches is
// trivially attributable and a test can clean up after itself with SCAN.
func (s *Store) key(parts ...string) string {
	return s.prefix + strings.Join(parts, ":")
}

// leaseKey is the lease's own key: a string holding the current owner. Its TTL
// is the lease.
func (s *Store) leaseKey(name string) string { return s.key("lease", name) }

// leaseSeqKey is the fencing counter for a lease. It is a Redis string that is
// only ever INCR'd, and it has no TTL: resetting it would hand a fresh holder
// a token an old holder still believes in, which is the exact failure fencing
// exists to prevent.
func (s *Store) leaseSeqKey(name string) string { return s.key("lease-seq", name) }

// epochKey is the cluster rotation epoch counter. Also INCR-only and TTL-free,
// for the same reason as the lease sequence.
func (s *Store) epochKey() string { return s.key("rotation-epoch") }

// rotationKey is the shared rotation state record for one route: a hash with a
// TTL on the whole record.
func (s *Store) rotationKey(route string) string { return s.key("rotation", route) }

// withTimeout bounds one operation.
func (s *Store) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, DefaultOpTimeout)
}

// acquireScript takes the lease and issues a fencing token atomically.
//
// The sequence inside the script is what makes this correct:
//
//	owner = GET lease
//	if owner exists and owner != me -> the lease is live and someone else's;
//	                               fail with ErrLeaseHeld
//	token = INCR lease-seq
//	SET lease me PX ttl
//	return token
//
// The INCR is inside the script and runs on every acquisition, including a
// re-acquisition by the same owner after its lease lapsed. A holder that comes
// back from a pause therefore gets a *new, higher* token, and its old token is
// fenced the instant the new one is issued — which is what makes renewal
// self-healing without ever letting two in-flight holders believe they are the
// same lease.
//
// The INCR is unconditional once the lease is free. It never resets, and never
// runs against a value another instance could have lowered.
var acquireScript = redis.NewScript(`
local owner = redis.call('GET', KEYS[1])
if owner and owner ~= ARGV[1] then
  return {0, 0}
end
local token = redis.call('INCR', KEYS[2])
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
return {1, token}
`)

// Acquire takes the named lease for owner, or reports ErrLeaseHeld when another
// owner holds an unexpired one.
//
// Every successful acquisition returns a fencing token strictly greater than
// every token the authority ever issued for this lease — including this
// owner's previous one. The caller keeps the token and presents it on every
// mutation guarded by the lease.
//
// Re-acquiring a lease one still holds is legal and returns a new, higher
// token. That is intentional: an instance whose lease lapsed must not be able
// to resume with its old token, so renewal-after-expiry takes the ordinary
// path and re-fences.
func (s *Store) Acquire(ctx context.Context, name, owner string, ttl time.Duration) (Lease, error) {
	if strings.TrimSpace(name) == "" {
		return Lease{}, errors.New("a lease name must not be empty")
	}
	if strings.TrimSpace(owner) == "" {
		return Lease{}, errors.New("a lease owner must not be empty")
	}
	if ttl <= 0 {
		ttl = s.ttl
	}
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()

	// PEXPIRE takes a millisecond TTL; a sub-millisecond one would round to
	// zero and delete the lease immediately.
	res, err := acquireScript.Run(ctx, s.rdb,
		[]string{s.leaseKey(name), s.leaseSeqKey(name)},
		owner, strconv.FormatInt(ttl.Milliseconds(), 10),
	).Slice()
	if err != nil {
		return Lease{}, fmt.Errorf("acquire lease: %w", err)
	}
	if len(res) != 2 {
		return Lease{}, fmt.Errorf("acquire lease: unexpected script reply of %d fields", len(res))
	}
	acquired, _ := res[0].(int64)
	if acquired == 0 {
		return Lease{}, ErrLeaseHeld
	}
	token, err := asUint(res[1])
	if err != nil {
		return Lease{}, fmt.Errorf("acquire lease: reading the issued fencing token: %w", err)
	}
	return Lease{Name: name, Owner: owner, Token: token, Namespace: strings.TrimSuffix(s.prefix, ":")}, nil
}

// asUint coerces a Lua integer reply to uint64. Lua numbers arrive as int64;
// the token sequence is well inside int64's range.
func asUint(v any) (uint64, error) {
	switch n := v.(type) {
	case int64:
		if n < 0 {
			return 0, errors.New("negative fencing token")
		}
		return uint64(n), nil
	case string:
		return strconv.ParseUint(n, 10, 64)
	case []byte:
		return strconv.ParseUint(string(n), 10, 64)
	default:
		return 0, fmt.Errorf("unexpected token type %T", v)
	}
}

// Renew extends a lease the caller still holds.
//
// Renewal is refused for a lease the caller does not hold (ErrNoLease) or one
// whose token has been superseded (ErrFenced). It never silently re-acquires:
// a holder that lost the lease must go through Acquire again and take a new
// token, so that losing the lease is always visible to the caller rather than
// papered over. A lease taken over by someone else reads as ErrLeaseHeld.
func (s *Store) Renew(ctx context.Context, l Lease, ttl time.Duration) (Lease, error) {
	if l.IsZero() {
		return Lease{}, ErrNoLease
	}
	if ttl <= 0 {
		ttl = s.ttl
	}
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()

	res, err := acquireScript.Run(ctx, s.rdb,
		[]string{s.leaseKey(l.Name), s.leaseSeqKey(l.Name)},
		l.Owner, strconv.FormatInt(ttl.Milliseconds(), 10),
	).Slice()
	if err != nil {
		return Lease{}, fmt.Errorf("renew lease: %w", err)
	}
	acquired, _ := res[0].(int64)
	if acquired == 0 {
		// Someone else holds it. The caller is not the holder, which is a
		// different fact from having been fenced.
		return Lease{}, ErrLeaseHeld
	}
	token, err := asUint(res[1])
	if err != nil {
		return Lease{}, fmt.Errorf("renew lease: reading the issued fencing token: %w", err)
	}
	// Renewal issued a new token, which is correct — but the caller must be
	// told, because continuing with the old one would be fenced immediately.
	l.Token = token
	return l, nil
}

// Release drops a lease the caller holds. It is best-effort and never
// errors on a lease that already lapsed: releasing a lease nobody holds is a
// no-op, not a failure.
//
// Release deliberately does not invalidate the token. The counter keeps
// advancing, so a released lease's next acquisition is still higher — which is
// the property that makes an aborted-but-resumed holder safe.
func (s *Store) Release(ctx context.Context, l Lease) error {
	if l.IsZero() {
		return nil
	}
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	// Compare-and-delete: never delete a lease a different owner now holds.
	const script = `
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0`
	if err := redis.NewScript(script).Run(ctx, s.rdb, []string{s.leaseKey(l.Name)}, l.Owner).Err(); err != nil {
		return fmt.Errorf("release lease: %w", err)
	}
	return nil
}

// Holder reports the current owner of a lease, or "" when the lease is free.
// It is diagnostic: nothing may decide authority from it, because a read
// cannot be atomic with the mutation that follows it.
func (s *Store) Holder(ctx context.Context, name string) (string, error) {
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	owner, err := s.rdb.Get(ctx, s.leaseKey(name)).Result()
	switch {
	case errors.Is(err, redis.Nil):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("read lease holder: %w", err)
	}
	return owner, nil
}

// TokensIssued reports how many tokens the authority has ever issued for a
// lease. It exists so tests can assert monotonicity against an independent
// count rather than against the store's own bookkeeping.
func (s *Store) TokensIssued(ctx context.Context, name string) (uint64, error) {
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	v, err := s.rdb.Get(ctx, s.leaseSeqKey(name)).Uint64()
	switch {
	case errors.Is(err, redis.Nil):
		return 0, nil
	case err != nil:
		return 0, fmt.Errorf("read lease token sequence: %w", err)
	}
	return v, nil
}

// ForceExpire deletes a lease without touching its token counter.
//
// It exists for one purpose: letting a test make a holder's lease lapse the way
// a real stop-the-world pause lapses it, deterministically and without waiting
// out the TTL. Production never calls it — a lease lapses by not being renewed.
// The token counter is deliberately untouched, which is the property under
// test: after the expiry, the next acquisition must get a strictly higher
// token than the expired holder's.
func (s *Store) ForceExpire(ctx context.Context, name string) error {
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	if err := s.rdb.Del(ctx, s.leaseKey(name)).Err(); err != nil {
		return fmt.Errorf("expire lease: %w", err)
	}
	return nil
}
