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

`GET /status` is unauthenticated and returns an uncacheable JSON snapshot
(`Cache-Control: no-store`). Its pre-control-API top-level keys remain present
for backward compatibility, and the same facts are also grouped under three
explicit scope objects. A client should use the scope objects for new work:
their `scope` marker makes the ownership of every figure explicit rather than
letting one replica's state look like a fleet-wide fact.

| Scope         | What it means                                                                                                                                                                                                    | Fields                                                                                                      |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `cluster`     | Durable/shared state that replicas converge on. `activeRevision` is the reconciler's **cached** last successful durable-pointer observation; it does not make a database query for this unauthenticated request. | `scope`, `configRevision` (this instance's serving revision), `storeConfigured`, `activeRevision`, `synced` |
| `distributed` | Runtime figures meaningful only after aggregating every replica. One response is this instance's slice, not an invented fleet total.                                                                             | `scope`, `requests`, `failovers`, `rotations` and `ipRevisits` when the rotation engine is wired            |
| `instance`    | State meaningful only for this process.                                                                                                                                                                          | `scope`, `version`, `uptime`, `pool`, and `warmPool` when the warm pool is wired                            |

`cluster.synced` is true only when the reconciler's cached active durable
revision equals the generation this process is serving. It is false during
normal convergence and when the active revision cannot be materialized by this
build; it is not a health or readiness signal. A temporarily unreachable store
leaves the last cached observation intact rather than fabricating revision zero.

The flat compatibility keys are:

| Field            | Meaning                                                                                                           |
| ---------------- | ----------------------------------------------------------------------------------------------------------------- |
| `version`        | Build version (instance-local; also under `instance`)                                                             |
| `uptime`         | Process uptime (duration string, second precision; instance-local)                                                |
| `requests`       | This instance's sum over proxy listeners; aggregate across replicas for a fleet total                             |
| `failovers`      | This instance's sum over proxy listeners; aggregate across replicas for a fleet total                             |
| `listeners`      | Per-listener object (`mixed`, `v4`, `v6` — enabled listeners only), each with `requests` and `failovers`          |
| `pool`           | Array of redacted route states local to this process (below)                                                      |
| `configRevision` | Durable revision this instance is serving, or zero in file-seeded mode                                            |
| `rotations`      | Completed manual-route rotations that observed a changed egress IP (this process lifetime total)                  |
| `ipRevisits`     | Of those rotations, ones that committed an egress IP the same route had already verified (process-lifetime total) |
| `warmPool`       | Warm-pool view local to this process (below)                                                                      |

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

## Authenticated control API

When `RPGW_CONFIG_STORE_DSN` is configured, the same admin listener also mounts
an authenticated control surface beneath `/control`. Its token is configured by
`RPGW_ADMIN_TOKEN`; see
[configuration](configuration.md#rpgw_config_store_dsn-rpgw_reconcile_interval-and-rpgw_admin_token)
for the fail-closed startup rule. `/healthz`, `/readyz`, and `/status` remain
unauthenticated so orchestrator probes keep working exactly as before.

Every control endpoint requires **exactly one**
`Authorization: Bearer <token>` header. The bearer scheme is case-insensitive;
the opaque presented token is limited to 512 bytes before it is HMACed and
constant-time compared to the configured token's digest. Missing, malformed,
non-Bearer, wrong, over-long, or repeated `Authorization` headers all return:

```http
401 Unauthorized
WWW-Authenticate: Bearer realm="rotation-proxy-gateway"
Cache-Control: no-store
```

This is intentionally `401`, not the proxy listeners' `407`. `407` and
`Proxy-Authorization` remain exclusively for `RPGW_ACCOUNT` on the HTTP
forward-proxy listeners. Every control response is JSON and
`Cache-Control: no-store`.

`x-ecoma-request-id` is accepted on a control call under the proxy listeners'
same grammar (one value, 1–64 bytes, `[A-Za-z0-9-_.:]`) and echoed on the
response only when accepted. All `x-ecoma-*` request headers are consumed at
the boundary; no endpoint forwards them. The correlation id is not an
authorization credential.

### Resources

All paths below are relative to `/control`.

| Method and path      | What it honestly serves                                                                                                                                                                                                                                                 |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /proxies`       | The active **durable** revision's configured route inventory and its revision. It reports endpoints as `host:port`, never route userinfo. An unreadable or empty store is `503`; an active document this build cannot decode is `503`, not an invented empty inventory. |
| `GET /routes`        | This instance's serving generation (`configRevision`) and its redacted, live pool health snapshot. It is deliberately not a claim about another replica.                                                                                                                |
| `GET /routing-rules` | The routing policy this instance is actually applying. `configured:false` means no routing block (unrestricted policy); an empty configured block remains distinguishable as the fail-closed policy.                                                                    |
| `GET /rotations`     | This instance's manual-route rotation state, safe settings, and process-lifetime aggregates. It reports the resolved concurrency cap, not provider secrets. Rotation aggregates are omitted when no engine is wired rather than invented as zero.                       |
| `GET /config`        | The active durable revision's credential-free declared view, with `editable:false`. It is deliberately not a round-trippable document: returning masked route credentials or rotate-API material would either leak them or make a client overwrite them.                |
| `PUT /config`        | A validated operator-supplied durable document, committed with optimistic concurrency (below). It never echoes the submitted document or a validation error that could quote a secret.                                                                                  |
| `GET /analytics`     | `501 Not Implemented` with `{"error":"not_available","available":false}`. This build has no durable analytics source, so it refuses rather than inventing an empty series or a plausible number.                                                                        |

No control response, error response, or control log contains route userinfo, the
inbound `RPGW_ACCOUNT`, the admin bearer token, rotate-API URLs/headers/bodies,
or the rotation IP-check URL. Provider rotation is rendered only as
`rotateAPIConfigured: true|false`; public rotation IPs are canonicalized with
IPv4-mapped addresses unmapped before they leave the process.

### `PUT /config` concurrency

The body is a strict JSON envelope:

```json
{
  "expected_revision": 42,
  "author": "operator@example.com",
  "note": "explain the change",
  "document": { "version": 1 }
}
```

`document` must be a complete valid runtime document, including the credentials
an operator who writes it already holds. It is bounded to the durable document
ceiling before parsing; unknown envelope fields and malformed JSON are `400`.

The conditional pointer move is made by the durable store, not by a
read-then-write check in HTTP. The response distinguishes two precondition
failures deliberately:

- **`428 Precondition Required`** — `expected_revision` is absent, zero, or
  negative. The request made no usable conditional write; retrying it unchanged
  would remain unsafe.
- **`412 Precondition Failed`** — an expectation was supplied but did not match
  the active pointer when the store committed. The response includes
  `currentRevision` and `readable`; when `readable:true`, read that revision,
  rebase intentionally, and retry. When the store could not be read,
  `readable:false` and revision `0` say to wait/re-read rather than pretend zero
  is a real active revision.

A successful commit returns `200` with the newly appended durable `revision` and
`accepted:true`. Acceptance is not a claim that every replica has materialized
it yet; use `/status`'s `cluster` scope on each replica to observe convergence.

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
