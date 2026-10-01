# Cluster coordination

Multiple gateway instances can share one Redis so that manual-route rotation
happens once per cluster instead of once per instance. Coordination is **opt-in
and off by default**: with `RPGW_COORD_REDIS_ADDR` unset every instance rotates
independently, exactly as it did before this subsystem existed.

| Env                         | Default | Meaning                                                     |
| --------------------------- | ------: | ----------------------------------------------------------- |
| `RPGW_COORD_REDIS_ADDR`     | _unset_ | Coordination authority. Unset disables cluster coordination |
| `RPGW_COORD_WATCH_INTERVAL` |    `1s` | Authoritative reconcile period, independent of pub/sub      |

Both are bootstrap-only and require a restart. The address commonly embeds a
password, so it is treated as a secret: it is never logged, never reported by
`/status`, and never appears in an error. An unreachable Redis fails startup
rather than degrading to un-coordinated rotation — an instance that cannot reach
the authority would rotate as if it were alone, which is the failure this
subsystem exists to remove.

## Why a lease alone is not enough

The obvious design is a lock: `lock = instance-id + TTL`. It is wrong, and the
failure is not subtle.

An instance acquires the lock and then pauses — a long GC, a stop-the-world
suspend, a SIGSTOP, a hypervisor pause, a lost network partition. Its lease
expires. A second instance sees the lock free, takes it, and completes a
rotation. The first instance wakes up. It still believes it holds the lock,
because nothing ever told it otherwise, and it commits its rotation.

The TTL cannot detect this. A TTL distinguishes _a holder that is quiet_ from
_a holder that is working_, and a paused holder is quiet. Nothing in the system
observes the difference, so the lock expires, and the paused holder resumes
into a world where its lock no longer exists.

What closes the gap is a **fencing token**: a number the authority issues on
every acquisition, strictly greater than every number it ever issued before.
The paused instance holds token 1. The taker holds token 2, and 3, and 4. When
the paused instance finally tries to write, it presents token 1, and the
authority compares it against the highest it has seen and refuses.

Two things follow, and both are load-bearing:

- **The token is issued by the authority and is never reused.** A counter that
  restarted — because it was stored in the lease key and the lease key expired
  with it — would hand a new holder a token the old holder still believes in,
  which is no better than no token at all. The counter here is `INCR`-only and
  carries no TTL, so the sequence cannot restart.
- **Fencing is checked at the point of mutation, not at acquisition.** The
  check at acquisition can only tell you who holds the lease _now_. The check
  that matters is the one performed by the operation that writes, because that
  is the operation a paused instance reaches after the world moved on.

## Where fencing is enforced

Enforcement is not spread across Go code. It is inside a Redis Lua script, so
the check and the mutation are one atomic step. A check-then-act performed by
the client in two round trips has exactly the race this design exists to close:
a peer could commit between the read and the write.

`Store.CommitRotation` in `internal/coord/record.go` runs one script against
four keys:

| Key                 | Contents                                            |
| ------------------- | --------------------------------------------------- |
| `KEYS[1]` lease     | the lease holder, with a TTL                        |
| `KEYS[2]` lease seq | the `INCR`-only token counter, no TTL               |
| `KEYS[3]` epoch     | the cluster rotation epoch, `INCR`-only, no TTL     |
| `KEYS[4]` rotation  | the shared rotation state record, a hash with a TTL |

and takes its inputs as named arguments — `ARGV[1]` is the fencing token being
presented, `ARGV[2]` the owner claiming it, and so on. The script runs in this
order, and the order is the contract:

1. **Fence.** `high = max(token ever issued for this lease, token on the
record)`. If `high > ARGV[1]`, return `fenced` and mutate nothing. Note that
   the issued counter is consulted as well as the record: fencing only against
   the record would leave a stale token unrefused whenever no record exists
   yet, which is precisely the window a first-time rotated route lives in.
2. **Holder check.** If the lease key no longer names `ARGV[2]`, return
   `not_holder`. This is a second, independent guard: a takeover that happened
   without a token bump (an operator deleting a key, a restore from a
   snapshot) is caught here.
3. **Exactly-once.** If the record's token equals `ARGV[1]` and its state is
   `committed`, return `duplicate` without mutating. One token is one
   acquisition is one rotation attempt, so a retried or duplicated request
   carrying the same token commits once. This check lives in the same script as
   the write for the reason in the paragraph above.
4. **Commit.** `INCR` the epoch, write the record fields, set the record TTL,
   and return the new epoch.

A caller that is refused touches no local state. That matters: an instance that
had already advanced its own view must not half-apply a rotation the cluster
rejected.

`Store.Phase` — the `draining` / `rotating` / `verifying` / `stale` progress
updates — runs the same fence and holder checks before it writes. A stale
instance cannot publish a phase over a live one's rotation either.

## The cluster rotation epoch

The epoch is a single `INCR`-only counter, monotonic for the life of the
cluster, bumped by every successful rotation commit. It is the cluster's answer
to "which generation is current", and it is what invalidates every instance's
local warm connections.

The warm pool already stamps each parked connection with the route's rotation
epoch and discards any connection whose stamp does not match the route's
current epoch — see [`warm-pool.md`](warm-pool.md). Cluster coordination feeds
that same check rather than introducing a second mechanism:

- each instance watches the authority and, when the epoch moves, calls
  `pool.Store.AdoptClusterEpoch`;
- that advances each route's local rotation epoch to the cluster value, and
  returns the number of routes that actually moved;
- the existing warm-pool check then discards every parked connection stamped
  with an earlier epoch, on every instance, without coordination touching a
  single connection.

The moved-route count comes from the pool, not from the controller. A count
invented by the caller is a number an operator will trust and that nothing
enforces.

## Pub/sub is a hint, never the authority

A commit publishes a message on `<namespace>:events`, and each instance
subscribes to it. The subscription makes the common case fast: an instance
learns of a rotation in about a millisecond instead of waiting out an interval.

It is also fire-and-forget. Redis pub/sub drops messages when no subscriber is
present, offers no delivery guarantee, and gives the receiver no way to know a
message was lost. If the message were the authority, one dropped message would
leave an instance serving stale cluster state indefinitely — potentially until
the next restart. So:

- a received message is never believed. Nothing in the body is consulted — not
  the epoch, not the route, not the writer. The message is a request to go look,
  and the watcher re-reads the store authoritatively.
- a dropped message costs at most one `RPGW_COORD_WATCH_INTERVAL`. The periodic
  re-read is the actual guarantee of convergence; pub/sub only makes arriving
  sooner.
- a publication that fails is logged, not acted on. The publisher has already
  committed its mutation, and the asymmetry is deliberate: a lost publish costs
  a peer one interval of latency, whereas refusing to publish would cost the
  cluster a rotation.
- a failed re-read keeps the last known epoch serving and warns. The next tick
  retries. Resetting to "no epoch" instead would make an instance believe it had
  never rotated, and re-adopt stale warm connections.

## Keys, TTLs, and what is never stored

| Key             | Type   | TTL       | Reset on loss                      |
| --------------- | ------ | --------- | ---------------------------------- |
| lease           | string | lease TTL | yes — a lapsed lease is free       |
| lease seq       | string | **none**  | no — the sequence must not restart |
| epoch           | string | **none**  | no — same reason                   |
| rotation record | hash   | 1 hour    | no — it is a live record           |

The rotation record carries `route`, `rotation_epoch`, `state`, `owner`,
`fencing_token`, `started_at`, `baseline_ip`, `observed_ip`, `next_retry_at`,
and `updated_at`.

Every IP in it is canonicalized with `netip.Addr.Unmap()` before it is stored
and again before it is compared, so `::ffff:1.2.3.4` and `1.2.3.4` are one
identity. Without that, a route could report a changed egress IP that is the
same address in another notation, and a rotation would be treated as verified
when it had not changed at all. An unparseable IP is refused rather than stored.

**No credential, `Proxy-Authorization` value, inbound account, rotate-API URL,
rotate-API header, rotate-API body, or raw route userinfo is ever written to
Redis.** The record holds a route _id_, never a route line. The store is
reachable by anything holding the Redis password, so it is treated as a lower
trust boundary than the process's own logs, which pass through
`internal/sanitize`.

## Coordination is off the request path

A proxied request never touches Redis. There is no coordination read, write, or
lookup on the serving path, and none may be added: coordination happens on
rotation, on config change, and on the reconcile tick, and nowhere else. The
epoch a route serves under is already in process memory, adopted by the
watcher, so borrowing a warm connection or selecting a route costs no
coordination work at all.

## Rotation admission

An instance that does not hold the lease does not rotate. It stands down rather
than rotating un-coordinated, and it also stands down when coordination itself
errors — an instance that cannot tell whether it holds the lease must not
assume it does.

When a rotation commits locally but the cluster refuses it, that is a `warn`:
the local route has already changed its egress IP and the cluster has not
recorded it. It is a real divergence and an operator should see it. A duplicate
is `debug` — it is the exactly-once guard working, which is the normal outcome of
a retried commit.

## Testing

`internal/coord` runs against a real Redis. The suite is skipped **loudly** when
`RPGW_TEST_REDIS_ADDR` is unset, and it is never faked: the entire point of the
package is that fencing is enforced atomically inside a script, and a stub client
would assert that the stub is correct, which is the one thing it cannot be.

```bash
docker run -d --name rpgw-redis-test -p 56379:6379 redis:7-alpine
RPGW_TEST_REDIS_ADDR=redis://127.0.0.1:56379/0 go test -race ./internal/coord/
```

Each test gets its own key namespace and drops it afterwards. Isolation is not
tidiness: several tests deliberately expire leases and advance the epoch, and a
shared namespace would let one test's counter bump read as another's.

The scenario the design exists for is driven by **two real processes** against
one Redis, in `TestTwoProcessesFenceAReplacedHolder`. Instance A acquires the
lease and is paused with `SIGSTOP` — a genuine stop-the-world pause, not a fake
clock. The lease expires on Redis's own clock. Instance B takes over and commits
a rotation. A is resumed with `SIGCONT` and tries to commit. The test asserts
that A's commit is refused **and** that reading the record back out of Redis
still shows B's rotation. That second assertion is the one that matters: a
read-then-act would let A mutate and only afterwards be told it had lost, so an
error return alone would not prove the invariant held.

The pub/sub tests are verified non-vacuous by disabling the reconcile tick,
which makes the message-loss test fail with a timeout rather than pass slowly.
