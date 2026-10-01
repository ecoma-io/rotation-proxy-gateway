# Admin and observability

The always-on admin listener (default `0.0.0.0:30120`, HTTP) exposes the health,
readiness, and status endpoints. The process listener deliberately binds all
interfaces inside its network namespace; operators control exposure through
Docker port publishing, Docker networks, and firewall policy.

```bash
curl http://127.0.0.1:30120/healthz # body: ok\n
curl http://127.0.0.1:30120/readyz  # 200 ok\n serving, 503 draining/stopped
curl http://127.0.0.1:30120/status
RPGW_ADMIN_ADDR=127.0.0.1:30120 ./bin/rpgw healthcheck
./bin/rpgw version
```

`healthcheck` is a binary subcommand (used by the Docker healthcheck): it loads
only the bootstrap environment and probes the admin listener's `/readyz` — it
deliberately does not parse runtime YAML, so a bad reload cannot make an
otherwise-running process fail the probe. Wildcard listener addresses are
mapped to their loopback equivalent for the probe.

## `/healthz` and `/readyz`

They answer different questions, and conflating them is the bug this split
exists to prevent.

| Endpoint   | Answers                       | While draining       |
| ---------- | ----------------------------- | -------------------- |
| `/healthz` | "is this process alive?"      | `200`                |
| `/readyz`  | "send this instance traffic?" | `503` from the start |

`/healthz` is unconditional: it answers `200 "ok\n"` for the entire remaining
life of the process, drain window included. It must stay that way. The
container health check reads it, and a liveness probe that failed while the
process is stopping correctly would tell Docker to kill it mid-drain, with live
tunnels on it.

`/readyz` goes `503` the instant the drain begins and stays there for good —
before any listener socket closes, and while every listener is still accepting
for a 5 second head start (see
[deployment](deployment.md#shutdown-sizing)). That window is the whole point: a
load balancer that still believes the instance is ready gets told otherwise
while the socket it is routing to is still answering.

| State    | Status | Body         |
| -------- | ------ | ------------ |
| ready    | `200`  | `ok\n`       |
| starting | `503`  | `starting\n` |
| draining | `503`  | `draining\n` |
| stopped  | `503`  | `stopped\n`  |

The state is a monotonic machine, not a flag: a process only moves forward
through it, so a late or duplicated transition cannot re-advertise an instance
that already told its load balancer to stop. The body is the state token and
nothing else — readiness is a statement about this process alone, never derived
from a route's cooldown, the warm pool, or an upstream provider, so there is
nothing in it to leak. Responses are `Cache-Control: no-store`: a cached `200`
replayed after the drain began would route traffic into a socket about to close.
A non-GET is `405` with `Allow: GET`.

`/readyz` is an admin-plane path alongside `/status`, not part of any wire
contract the gateway speaks to a client, so it is plain text with no envelope.

## `/status` contract

`GET /status` returns JSON with:

| Field        | Meaning                                                                                                               |
| ------------ | --------------------------------------------------------------------------------------------------------------------- |
| `version`    | Build version                                                                                                         |
| `uptime`     | Process uptime (duration string, second precision)                                                                    |
| `requests`   | Global `requests` sum over the proxy listeners                                                                        |
| `failovers`  | Global `failovers` sum over the proxy listeners                                                                       |
| `listeners`  | Per-listener object (`mixed`, `v4`, `v6` — enabled listeners only), each with `requests` and `failovers`              |
| `pool`       | Array of redacted route states (below)                                                                                |
| `rotations`  | Completed manual-route rotations that observed a changed egress IP (process-lifetime total)                           |
| `ipRevisits` | Of those rotations, the ones that committed an egress IP the same route had already verified (process-lifetime total) |
| `warmPool`   | Warm-pool view (below)                                                                                                |

Counter semantics:

- A listener's `requests` advances only on a valid `CONNECT` command that
  reaches route selection. A greeted client rejected during protocol
  negotiation — no acceptable method, unsupported command, malformed frame —
  and a client rejected by inbound authentication never advance it.
- `failovers` counts in-band route fallbacks: a failed attempt handed off to
  another attempt. It is a listener metric and is distinct from `rotations`.
- `rotations` counts completed manual-route rotations that observed a changed
  egress IP.
- `ipRevisits` counts the subset of those rotations that committed an address
  the same route had already verified earlier in its lifetime, the baseline
  included. It is the aggregate of the per-route `ipRevisitCount`, aggregated
  the same way `rotations` aggregates the per-route `rotationCount`, and it
  never exceeds `rotations`. A revisit is still a successful rotation; it is
  not the same condition as `consecutiveSameIP`, which counts attempts that
  failed to change the IP — see [rotation states](rotation.md#states).

Each route in `pool` carries: `proxy` (always `host:port`, never userinfo),
`kind`, `origin` (`auto` or `manual`), `id` (the operator-facing
[routing label](configuration.md#route-ids); omitted when the route is
unnamed), `available`, `inFlight`,
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
object (`state`, `lastIP`, `lastRotationAt`, `nextRetryIn`, `consecutiveSameIP`,
`rotationCount`, `ipRevisitCount`) — see [rotation states](rotation.md#states).
`available` is the same predicate `PickFor` applies, so a route reporting
`false` is one the gateway will not pick for any target — auth-blocked, cooling,
or out of picks for a rotation reason. A `seamless` route held across a changeover
reports `false` while it is held, and returns to `true` when the changeover
settles or the hold's bound passes; its `rotation.state` stays whatever it was,
because a hold is not a rotation in flight.

`rotationCount` is that route's successful rotations and `ipRevisitCount` the
subset of them that returned to an address the route had already verified; both
are always present, so a zero is explicit, and both are per-route counters that
survive an identity-preserving reload (a route whose identity changes restarts
its history). `lastIP` is stored in canonical form — IPv4 and its IPv4-mapped
IPv6 form are one address, equivalent IPv6 textual forms are one address — and
every rotation comparison is made under that same identity. The verified-IP
history behind `ipRevisitCount` is internal: it is
never exposed as a list, never logged, and never approximated.

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

Each request has a process-local `request_id` — the ordinal, not a client value,
because it is what the per-listener `requests` figure in `/status` counts. A
client may supply its own correlation id with
[`x-ecoma-request-id`](inbound-http.md#x-ecoma-request-id); it is resolved once
before route selection, bounded and validated, and appears on every record of
that request's attempt chain as `correlation_id`. An id the gateway did not
accept is replaced by a generated one marked with a leading `r-`, so a
client-vouched id and a minted one are distinguishable by the prefix rather
than by inspection. `request_id` and `correlation_id` travel together on every
record of a request, so a client id can always be joined to the gateway's own
ordinal.

Log lines additionally include
`listener=mixed|v4|v6`, host-only `target` and `upstream`, retry attempt
counts, the error kind (`proxy_connect`, `auth_route`, `socks_connect`,
`connect_target`, `setup`, `no_route`, `retry_exhausted`, plus the ingress-local
`bad_request` and `auth_rejected`), and the applied
cooldown for endpoint
dial, SOCKS handshake, and refused connect-target failures. With a
[routing block](configuration.md#request-routing-routing-block) configured,
`route selected` (debug) carries the picked route's `route_id`, and the
terminal `tunnel failed` (warn) carries `routing_candidates` — the size of the
candidate set the policy left open for that target (absent when no routing
block is configured; `0` is the fail-closed unmatched target). The same terminal
record carries `kind_routes`, the size of the candidate set after the listener's
kind filter and any
[`x-ecoma-proxy-family`](inbound-http.md#x-ecoma-proxy-family) constraint — so
`0` there with a non-zero `pool_size` is a family or listener filter that left
no candidate, not an empty pool. They never log
full URLs, headers, bodies, userinfo, the inbound account, the rotate-API
configuration, or the value of a refused control header.

Levels: `debug` shows flow (tunnel start, route selection, tunnel close),
`info` terminal successes, and `warn` fallback/terminal failures. Every
established tunnel also logs a close record with its lifetime, per-direction
byte counts, and which side ended the stream first (`close_reason`). Close
records log at `debug`; a tunnel broken by an upstream-side error logs at
`warn`, making mid-stream provider drops attributable.
