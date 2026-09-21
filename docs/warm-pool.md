# Warm upstream pool

The optional `warm-pool` block (off by default) keeps a bounded set of
half-established upstream connections ready in the background: TCP connected,
SOCKS greeting and authentication done, **no `CONNECT` sent**. A parked
connection knows nothing about any target — the gateway never pre-connects to a
destination — so borrowing one removes the upstream TCP-connect and greeting
round trips from a request's setup. Route selection, cooldown, auth-block, and
rotation state are untouched by the pool.

## Settings

```yaml
warm-pool:
  enabled: false
  min-idle-per-proxy: 1
  max-idle-per-proxy: 2
  max-total-idle: 64
  max-replenish-concurrency: 2
  # max-replenish-per-route: 1
  idle-ttl: 45s
```

| Setting                     | Default | Meaning                                                           |
| --------------------------- | ------: | ----------------------------------------------------------------- |
| `enabled`                   | `false` | Off unless this says otherwise                                    |
| `min-idle-per-proxy`        |     `1` | Parked connections kept per route at minimum                      |
| `max-idle-per-proxy`        |     `2` | Parked connections per route at most                              |
| `max-total-idle`            |    `64` | Process-wide ceiling on idle parked connections across all routes |
| `max-replenish-concurrency` |     `2` | Background replenish dials in flight, process-wide                |
| `max-replenish-per-route`   |     `0` | Replenish dials in flight toward one route (`0` = uncapped)       |
| `idle-ttl`                  |   `45s` | A parked connection nobody borrowed is closed after this long     |

Validation runs even while the pool is disabled, so a bad bound is reported on
the reload that introduces it rather than on the day the pool is switched on:
`max-idle-per-proxy`, `max-total-idle`, and `max-replenish-concurrency` must be
≥ 1; `min-idle-per-proxy` and `max-replenish-per-route` ≥ 0; `min-idle-per-proxy`
must not exceed `max-idle-per-proxy`; `max-total-idle` must be at least
`max-idle-per-proxy`; `idle-ttl` must be positive. Counts must be whole numbers
(fractional values are rejected, not truncated). Every setting is validated and
applied on [reload](configuration.md#reload-behavior) without a restart.

## The serving path

A request that has selected a route first tries to borrow a parked connection
and falls back to the ordinary cold dial when none exists. Borrowing never
waits: the pool is a non-blocking pop, so a burst simply drains it and serves
cold — load above the bounds gets the no-pool behavior, not a queue. Failure
classification is identical on both paths. A borrowed connection whose endpoint
refuses the `CONNECT` is an ordinary `connect_target` with its pair-scoped
cooldown; one whose transport died is discarded together with its parked
siblings without touching route health, and the cold dial — with its usual
reporting — decides.

The pool itself never writes route health: routes that are rotating,
auth-blocked, or cooling get their replenishment paused, not recorded.
Replenishment follows consumption — a borrow wakes the replenisher — so the
pool keeps up with steady traffic instead of refilling on a fixed tick alone.
Repeated replenish dial failures back off exponentially per route.

## Rotation, reload, and shutdown

Rotation remains a hard lifecycle boundary. Each parked connection is stamped
with the route's rotation epoch before its dial; a rotation invalidates the
old generation, and a connection that straddles the boundary is closed rather
than served into the new egress IP. Reloads behave like any runtime setting:
disabling the block or removing a route closes that route's parked connections
within one poll cycle, and shutdown closes every parked connection before the
listener drain starts.

## Bounds

Everything is bounded: `min-idle-per-proxy` and `max-idle-per-proxy` per route,
a process-wide `max-total-idle`, at most `max-replenish-concurrency` background
dials in total, and — when `max-replenish-per-route` is set (default `0`,
uncapped) — at most that many replenish dials in flight toward any single
route. The fleet cap bounds the process; the per-route cap protects a provider:
a pool that mixes providers can hand each one only the concurrent handshakes it
tolerates (a provider with R routes in the pool sees at most
R × `max-replenish-per-route` concurrent warm dials). The remaining bounds are
the exponential backoff on replenish dial failures and the `idle-ttl` that
expires connections nobody borrowed.

## Measured impact

Whether the pool pays is measured, not assumed: the paired `WarmAB`/`WarmHA`
benchmarks in [`e2e/BENCH.md`](../e2e/BENCH.md) run identical scenarios with the
pool disabled and enabled side by side. The first recorded measurement showed
remote upstreams (10-30 ms RTT) gaining ~50 % setup latency with a borrow ratio
near 1.0, near-loopback upstreams gaining only ~20 %, and concurrent route
failures costing a few extra failed operations per window — the
discard-and-redial leg of a dying route's borrowed connection. Enable it where
upstream round trips are real.
