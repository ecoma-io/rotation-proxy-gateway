# Admin and observability

The always-on admin listener (default `0.0.0.0:30120`, HTTP) exposes the health
and status endpoints. The process listener deliberately binds all interfaces
inside its network namespace; operators control exposure through Docker port
publishing, Docker networks, and firewall policy.

```bash
curl http://127.0.0.1:30120/healthz # body: ok\n
curl http://127.0.0.1:30120/status
RPGW_ADMIN_ADDR=127.0.0.1:30120 ./bin/rpgw healthcheck
./bin/rpgw version
```

`healthcheck` is a binary subcommand (used by the Docker healthcheck): it loads
only the bootstrap environment and probes the admin listener's `/healthz` — it
deliberately does not parse runtime YAML, so a bad reload cannot make an
otherwise-running process fail the probe. Wildcard listener addresses are
mapped to their loopback equivalent for the probe.

## `/status` contract

`GET /status` returns JSON with:

| Field       | Meaning                                                                                                  |
| ----------- | -------------------------------------------------------------------------------------------------------- |
| `version`   | Build version                                                                                            |
| `uptime`    | Process uptime (duration string, second precision)                                                       |
| `requests`  | Global `requests` sum over the proxy listeners                                                           |
| `failovers` | Global `failovers` sum over the proxy listeners                                                          |
| `listeners` | Per-listener object (`mixed`, `v4`, `v6` — enabled listeners only), each with `requests` and `failovers` |
| `pool`      | Array of redacted route states (below)                                                                   |
| `rotations` | Completed manual-route rotations that observed a changed egress IP                                       |
| `warmPool`  | Warm-pool view (below)                                                                                   |

Counter semantics:

- A listener's `requests` advances only on a valid `CONNECT` command that
  reaches route selection. A greeted client rejected during protocol
  negotiation — no acceptable method, unsupported command, malformed frame —
  and a client rejected by inbound authentication never advance it.
- `failovers` counts in-band route fallbacks: a failed attempt handed off to
  another attempt. It is a listener metric and is distinct from `rotations`.
- `rotations` counts completed manual-route rotations that observed a changed
  egress IP.

Each route in `pool` carries: `proxy` (always `host:port`, never userinfo),
`kind`, `origin` (`auto` or `manual`), `available`, `inFlight`,
`consecutiveFailures`, `cooldownFor`, `successes`, `failures`, `lastDialError`
(when set), `authFailures`, `authBlocked`, `lastAuthError` (when set), and the
pair-scoped summary counts `targetCooldowns` and `targetFailures`. `failures`
and `lastDialError` cover endpoint dial and route-level SOCKS handshake
failures (`proxy_connect`, `socks_connect`); authentication failures are
counted separately in `authFailures`, and `lastAuthError` is one of a fixed
set of safe labels, never raw error text. `targetCooldowns` counts the route's
(route, target) pairs currently cooling from refused CONNECTs and
`targetFailures` counts those refusals cumulatively — summary counts only,
never the targets themselves. Manual routes additionally carry a `rotation`
object (`state`, `lastIP`, `lastRotationAt`, `nextRetryIn`,
`consecutiveSameIP`) — see [rotation states](rotation.md#states).

`warmPool` reports `enabled` (false while the `warm-pool` block is absent or
says so), `stopped`, `workers`, the configured bounds
(`minIdlePerProxy`, `maxIdlePerProxy`, `maxTotalIdle`,
`maxReplenishConcurrency`, `maxReplenishPerRoute`, `idleTtl`), `idleTotal`,
the cumulative counters `created`, `borrowed`, `discardedStale`,
`discardedOverflow`, `generationInvalidated`, `connectFailed`, and
`replenishAttempts`, plus per-route `idle`/`pending`/`flying` (the last is
that route's in-flight replenish dials) — upstream identities are `host:port`
only, as everywhere else. See [warm upstream pool](warm-pool.md).

Rotate-API headers, bodies, and URLs never appear anywhere in the output.

## Logging

Logs are structured JSON lines on stdout (`zerolog`: fields such as `level`,
`time`, `msg`, `listener`, `request_id`), sized for the compose `json-file`
driver; set `log-level` in the runtime YAML to raise verbosity without a
restart.

Each request has a process-local `request_id`. Log lines additionally include
`listener=mixed|v4|v6`, host-only `target` and `upstream`, retry attempt
counts, the error kind (`proxy_connect`, `auth_route`, `socks_connect`,
`connect_target`, `setup`, `no_route`, `retry_exhausted`), and the applied
cooldown for endpoint
dial, SOCKS handshake, and refused connect-target failures. They never log
full URLs, headers, bodies, userinfo, the inbound account, or the rotate-API
configuration.

Levels: `debug` shows flow (tunnel start, route selection, tunnel close),
`info` terminal successes, and `warn` fallback/terminal failures. Every
established tunnel also logs a close record with its lifetime, per-direction
byte counts, and which side ended the stream first (`close_reason`). Close
records log at `debug`; a tunnel broken by an upstream-side error logs at
`warn`, making mid-stream provider drops attributable.
