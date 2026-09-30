# Architecture and behavioral contract

This document records the behavior implemented by release `0.6.0` before the
breaking HTTP-forward-proxy migration tracked in [#92]. It is an evidence-led
baseline for preserving safety properties across the migration; the detailed
protocol and operational contract remains in the linked pages.

## Scope and intentional replacement

At this baseline the data plane is an inbound SOCKS5 server. One shared route
pool is exposed as mixed, v4-only, and v6-only listener views. Each valid
inbound `CONNECT` results in one SOCKS5 upstream `CONNECT`; a domain target is
carried to the upstream as a domain address, so DNS occurs at the upstream
route.

The migration intentionally replaces only the inbound protocol and its
listener/authentication configuration. HTTP forward-proxy ingress will become
the sole data plane, supporting `CONNECT` and absolute-form HTTP. Outbound
SOCKS5H remains the transport and target-hostname preservation requirement.
No compatibility ingress is retained.

## Immutable serving generation

`pool.Generation` is the serving snapshot: validated runtime configuration, a
route-pool snapshot, and the compiled routing policy publish together through
an atomic pointer ([`internal/pool/generation.go`](../internal/pool/generation.go)).
A request loads one generation and uses it for its entire attempt chain. An
invalid file reload never calls `Store.Publish`, so the prior generation keeps
serving. Reconfiguration retains mutable route state only where the canonical
route identity is unchanged.

The persistent configuration materializer must keep this shape:

```text
committed durable revision
        ↓
load and validate complete candidate
        ↓
build immutable configuration + pool + router generation
        ↓
atomic local publication
```

A failed load, validation, or materialization must leave the serving generation
unchanged. The durable revision is metadata of the generation, not an input to
route identity or a reason to reset unchanged route state.

## Route identity and configuration ownership

A route's canonical identity normalizes scheme, host case, port spelling, and
escaped credentials. Its pool reuse key additionally includes egress kind and
origin ([`internal/config/config.go`](../internal/config/config.go),
[`internal/pool/pool.go`](../internal/pool/pool.go)). Therefore:

- Changed URL credentials, kind, or auto/manual origin create a new route state.
- Renaming an operator-facing route ID does **not** reset health: a generation
  has a frozen ID-to-route view, and a request resolves its candidate set to
  concrete route pointers once.
- Equivalent IPv4 and IPv4-mapped IPv6 egress-IP spellings are the same IP
  identity, represented by canonical 16-byte form.

Configuration has two layers at baseline: restart-only bootstrap settings and
file-backed runtime policy. The migration keeps only appropriate bootstrap
process settings, moves runtime policy to durable revisioned storage, and
removes the runtime file poller as authority. Requests must not query the
control database or Redis for ordinary selection.

## Selection, routing, and failure health

The pool is the only authority for eligibility and order. It selects eligible
allowed routes by least recency pass, first-seen tie break, and falls back to
the soonest recovering allowed route only when all non-auth-blocked,
non-rotating routes are cooling. Every successful pick holds an in-flight
reference until the failed attempt ends or the established tunnel closes.

Routing resolves an inbound target once at request start. It only narrows the
candidate route set; it cannot inspect stream bytes, select routes, bypass
health, or fall back outside that set. Request family is likewise a
request-scoped candidate constraint, not part of route identity and not a
reason to resolve the target locally.

The following scopes are separate and must remain so:

| Class                                                                        | Effect                                               |
| ---------------------------------------------------------------------------- | ---------------------------------------------------- |
| Endpoint DNS/TCP or pre-tunnel SOCKS framing failure                         | Route cooldown and distinct-route retry.             |
| SOCKS upstream authentication failure                                        | Auth-block route; no cooldown; distinct-route retry. |
| Upstream explicit non-success SOCKS `CONNECT` reply                          | `(route, target)` cooldown and distinct-route retry. |
| Local setup, malformed inbound request, cancellation, or post-tunnel failure | No route-health mutation and no retry.               |

Each request attempt chain excludes a route after it fails, so it never retries
the same route. Retrying ends as `no_route` when no eligible untried candidate
remains, or `retry_exhausted` when the configured budget ends while candidates
remain. A successful established tunnel must never retroactively change health
because target stream bytes or a mid-stream connection failure fail later.

For HTTP ingress, the old SOCKS reply bytes are superseded by correct HTTP
proxy response/error behavior; the health classification and retry authority
are not.

## Rotation and egress-IP identity

Manual routes have mutable rotation state separate from immutable policy. At
baseline `BeginRotation` makes the route ineligible and advances its epoch
before the procedure runs. The procedure drains in-flight traffic, obtains a
baseline, calls the provider API directly, probes, canonicalizes the observed
IP, checks collision, and atomically commits only if the route is still in the
live generation. A successful commit:

- records exactly one canonical egress IP,
- detects per-route revisits,
- prevents another manual route from holding the same canonical IP,
- clears route and `(route,target)` cooldowns earned by the old egress IP, and
- advances the epoch used to isolate warm connections.

Same-IP results return the route in `stale` state with bounded exponential,
jittered retry rather than falsely treating the rotation as successful. Removed
or identity-replaced routes reject late commits. Provider request URLs,
headers, bodies, and credentials never reach logs or status.

The distributed replacement must make the equivalent transitions conditional
on a current lease, fencing token, and route epoch. A former owner whose lease
expired must be unable to commit a late result after a newer owner succeeds.
The durable store is authoritative for committed history; Redis coordinates
ownership and current runtime state.

## Warm connections and connection ownership

The warm pool contains local half-established SOCKS connections only; it never
shares live sockets or writes route health. Borrow is non-blocking. A borrowed
connection whose target `CONNECT` is refused follows the ordinary
`(route,target)` classification; a dead borrowed transport discards local
siblings and cold-dials without reporting route health.

Every parked connection is stamped with the route rotation epoch and may only
be borrowed if it matches the current route epoch. The migration must compare
against the distributed epoch: a pre-commit seamless connection can remain
locally parked until commit, but it cannot be borrowed after the epoch changes.
Disruptive rotation must make admission, tunnel termination, and warm
invalidation explicit rather than relying on incidental socket failure.

## Lifecycle, status, and secret boundaries

`/healthz` is unconditional liveness. `/readyz` returns `503` at the first
instant graceful drain begins while listeners still accept for the bounded
readiness head start. Shutdown then stops rotation, stops warm replenishment,
closes every listener, drains them against one shared deadline, and force-closes
remaining sessions only when the deadline expires.

At baseline `/status` reports a process-local snapshot: listener request and
failover counters, current pool health and rotation fields, and optional warm
pool state. Persistent analytics must distinguish durable cluster history from
distributed coordination state and instance-local gauges; it must never imply
that a local TCP connection or process counter survived restart.

Credentials, inbound authentication values, route userinfo, target pair keys,
and provider rotation materials must not appear in logs, errors, responses,
metrics labels, or status. HTTP control headers are untrusted: the new request
ID must be bounded and sanitized before structured logging, and every
`x-ecoma-*` control header must be stripped before forwarding upstream.

## Baseline evidence

- [`docs/failure-and-health.md`](failure-and-health.md) — health scopes,
  selection, retry exclusion, and target-byte non-interference.
- [`docs/rotation.md`](rotation.md) and
  [`internal/pool/rotation.go`](../internal/pool/rotation.go) — rotation,
  atomic collision commit, and canonical IP behavior.
- [`docs/warm-pool.md`](warm-pool.md) and
  [`internal/warmpool/warmpool.go`](../internal/warmpool/warmpool.go) — local
  half-connection lifecycle and epoch isolation.
- [`internal/pool/generation.go`](../internal/pool/generation.go) — atomic
  immutable generation publication and retained state.
- [`internal/proxyserver/server.go`](../internal/proxyserver/server.go) and
  [`internal/proxyserver/lifecycle.go`](../internal/proxyserver/lifecycle.go)
  — request lifetime, session drain, readiness, liveness, and status behavior.
- [`internal/socksdial/socksdial.go`](../internal/socksdial/socksdial.go) —
  SOCKS target type preservation and remote DNS for domain targets.
