# Phase 5 — multi-instance coordination — working notes

## Isolation / branch

- Worktree: `/home/johnitvn/ecoma-io/rpgw-phase5` (NOT the orca `afanc` checkout,
  NOT `~/ecoma-io/rotation-proxy-gateway`).
- Branch: `johnitvn/phase5-coordination`
- Base: `origin/johnitvn/configstore-durable` (80d8e67) **merged with**
  `origin/johnitvn/phase1-freeze-behavior-safety` (91f3559) as `e36bd91`.
  configstore was branched before Phase 2 landed; the two touch disjoint files
  and `git merge-tree` confirmed a clean, conflict-free merge.
- Rebase story: if Phase 2 and configstore both land, `git rebase
origin/main` on this branch replays the merge + my commits; only the merge
  commit itself may need re-resolution, and it is currently conflict-free.

## Environment facts established

- Live Redis: `redis:7-alpine` container `rpgw-redis-phase5` on host port
  **56379** (`docker exec rpgw-redis-phase5 redis-cli ping` → `PONG`).
  Live Postgres exists too (`rpgw-pg`, host 55432).
- No `redis-server`/`redis-cli` binary on PATH; Docker is the only route.
- Dep added: `github.com/redis/go-redis/v9 v9.22.0`.

## Done

- `internal/coord/lease.go` — package doc carrying the whole fencing rationale;
  `Lease`, `ErrFenced`, `ErrNotHolder`, `ErrNoLease`, `ErrLeaseHeld`, `LeaseTTL`.
- `internal/coord/redis.go` — `Store` (go-redis/v9), namespaced keys, `Acquire`
  and `Renew` both driving the **same** `acquireScript` (INCR inside the script,
  on every acquisition), `Release`, `Holder`, `TokensIssued`, `ForceExpire`
  (test-only lease lapse that deliberately leaves the token counter alone).
- `internal/coord/epoch.go` — `Epoch`, `CurrentEpoch`, `BumpEpoch` (INCR-only,
  TTL-free), record field-name constants, `RotationState` constants,
  `canonicalIP` via `netip.ParseAddr(...).Unmap()`, `sameIP`, `RecordTTL`.
- `internal/coord/record.go` — **DONE**. `Record`, `Commit`, `commitScript`,
  `CommitRotation`, `phaseScript`, `Phase`, `Rotation`.

### Exactly-once guard (settled — do not redesign)

Keyed on **`fencing_token` + `state == 'committed'`**, checked inside the _same_
Lua script that performs the mutation:

```lua
if record_token and tonumber(record_token) == token
   and redis.call('HGET', KEYS[3], 'state') == 'committed' then
  return {0, tonumber(redis.call('GET', KEYS[2]) or '0'), 'duplicate'}
end
```

Rationale: the authority issues a **new token on every acquisition**, so a token
identifies exactly one rotation attempt. Same token + already committed ⇒ this
exact attempt already succeeded ⇒ no-op, no second epoch bump. A check-then-act
in two round trips would have the same race configstore correctly avoided with
`expected_revision` in a SQL `WHERE`; doing it in the script is the Redis
equivalent.

Script argument order is documented as an explicit `ARGV[1]..ARGV[8]` list at
the top of `commitScript`, with the fencing token as `ARGV[1]` and named
arguments at the Go call site.

## Where I am / what remains

1. `internal/coord/watch.go` — pub/sub nudge + periodic reconcile.
2. Epoch adoption into `internal/warmpool` (`store/coord` publishes epoch → each
   route's local `rotationEpoch`).
3. `internal/rotation` wiring + `cmd/rotation-proxy-gateway` bootstrap env.
4. Tests: unit (token monotonicity, stale rejection, epoch bump, double-commit,
   TTL expiry, pub/sub loss + reconcile) + **two-process live-Redis integration**
   gated on `RPGW_TEST_REDIS_ADDR`.
5. Gate: issue → push → draft PR.

## Test helper note

`redis-cli` is not installed; tests use go-redis directly (namespace per test
name + cleanup via SCAN), so no shelling out is needed.
