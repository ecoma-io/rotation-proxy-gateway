# Manual rotation routes

`proxies.manual` routes are static SOCKS routes whose **public egress IP is
changed through a provider HTTP API** on a per-route schedule. The gateway
drives that schedule itself: it probes the route's current egress IP, calls the
provider's rotate endpoint, verifies the egress IP actually changed, and records
the outcome. Manual routes serve ordinary traffic like any other route between
rotations.

## Route configuration

```yaml
proxies:
  manual:
    - proxy: username:password@provider.example:1080
      kind: v6
      rotate-interval: 90s
      api:
        url: https://provider.example/api/rotate-ip
        method: POST
        headers:
          Content-Type: application/json
        body: '{"subnet": 3}'
        timeout: 10s
```

- `rotate-interval` (required, positive duration): minimum time between
  rotation attempts of this route. After a verified rotation the next attempt is
  scheduled one interval out; after an unchanged-IP outcome it is scheduled by
  the retry backoff instead.
- `api` (required): the provider call that requests a new egress IP. `url` is
  required (absolute http or https). `method` defaults to `POST` and must be a
  valid HTTP method token. `timeout` defaults to `10s` and bounds one call.
  Header names are MIME-canonicalized (`content-type` behaves like
  `Content-Type`); `headers` and `body` are otherwise sent verbatim. Redirects
  are never followed — a `3xx` fails the call like any other non-2xx status, so
  a redirect cannot replay the credentials to another host.
  **Headers and body may carry provider credentials: they are never logged,
  never echoed in errors, and never exposed by `/status`.** The call is made
  directly from the gateway process and never through the route pool, so a
  failing provider API cannot affect route health.
- `kind` keeps its usual meaning: the provider-backed public egress IP family.
  It does not restrict target address families, and no family is inferred from
  the SOCKS endpoint address (see [configuration](configuration.md#route-lines)).

## Rotation settings

```yaml
rotation:
  max-concurrent: 1
  drain-timeout: 55s
  rotate-on-start: false
  ip-check-url: https://www.cloudflare.com/cdn-cgi/trace
  ip-check-timeout: 20s
  ip-check-interval: 2s
  retry-backoff-max: 15m
```

| Setting             |          Default | Meaning                                                                                                                                                                                                     |
| ------------------- | ---------------: | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `max-concurrent`    |              `1` | Rotation procedures running at once: a fixed count, or `"NN%"` of the manual routes (a whole number 1-100, rounded up, at least 1, never more than the route count). Resolved fresh every scheduling cycle. |
| `drain-timeout`     |            `55s` | How long a procedure waits for the route's in-flight requests to finish before force-rotating. Expiry does not wait longer; requests already in flight may continue on the old egress IP.                   |
| `rotate-on-start`   |          `false` | Rotate every manual route at process start, under the same cap and staggering, instead of waiting one interval.                                                                                             |
| `ip-check-url`      | Cloudflare trace | HTTPS URL whose response body contains an `ip=` line. **Must be `https`.** The probe always verifies TLS independently of any route setting.                                                                |
| `ip-check-timeout`  |            `20s` | Total window for one verification: how long a procedure watches for a changed IP before giving up on that attempt.                                                                                          |
| `ip-check-interval` |             `2s` | Pause between verification probes inside that window; must not exceed `ip-check-timeout`.                                                                                                                   |
| `retry-backoff-max` |            `15m` | Ceiling of the same-IP retry backoff.                                                                                                                                                                       |

`rotation.drain-timeout` and `RPGW_SHUTDOWN_GRACE` are unrelated budgets. The
drain timeout bounds one route's pre-rotation quiesce; the shutdown grace bounds
the whole process's listener drain. They never interact: a rotation procedure
never extends shutdown, and shutdown never waits on a rotation.

## Procedure contract

Each attempt runs: **drain → baseline probe → rotate call → verify**.

1. **Drain.** The route stops receiving new picks immediately and stays
   ineligible for the whole procedure. The procedure waits for the route's
   in-flight connections to finish, bounded by `drain-timeout`; expiry proceeds
   anyway, and the in-flight requests keep running on their existing tunnels —
   they finish on the old egress IP, none are broken. Draining a route that
   serves no other purpose can make requests fail with the ordinary `no_route`
   general-failure reply (`05 01`) until the window ends.
2. **Baseline probe.** The gateway dials through the route (SOCKS, then TLS)
   to `ip-check-url` and reads the `ip=` line. Three attempts; if all fail the
   procedure continues with no known baseline (**unverified mode**), and later
   verification only requires an IP that differs from the route's last verified
   address and collides with no other manual route.
3. **Rotate call.** One call to the route's `api`. Transport errors, non-2xx
   statuses, and timeouts end the call; the procedure still probes once, because
   the provider may have rotated despite reporting failure. A `429` response
   with `Retry-After: N` raises the next attempt's wait to at least `N` seconds
   — still capped by `retry-backoff-max`, so one response cannot silence the
   route's retries for days.
4. **Verify.** The gateway re-probes until `ip-check-timeout` elapses. The
   attempt **succeeds only if the reported IP differs from the baseline and is
   not the current IP of any other manual route** (a cross-route collision does
   not count). Every comparison is made under one canonical IP identity: two
   spellings of one address — IPv4 and its IPv4-mapped IPv6 form, expanded and
   compressed IPv6 — are one address, so a provider that switches spellings has
   not rotated anything. Success records the new IP as the route's baseline and advances
   the route's `rotationCount` — plus its `ipRevisitCount` when the new address
   is one the route had already verified (see [states](#states)) — clears both
   dial-cooldown scopes learned against the old IP — the route-scope cooldown
   and every pair-scoped (route, target) cooldown, whose refusals were answered
   from the old address — and never clears an authentication block:
   credentials did not rotate with the IP.

**An unchanged IP is not a failure of the route.** The route returns to serving
immediately in the `stale` state, and the gateway retries forever — the next
attempt waits one `rotate-interval`, doubling per consecutive unchanged result
(`interval`, `2×`, `4×`, …) with ±10% jitter, capped at `retry-backoff-max`, and
floored by any `Retry-After`. Stale routes are pushed to the back of the
recency order so fresher routes absorb traffic first, but they keep serving
normally.

A route whose provider hands out non-sticky addresses cannot be rotated
reliably. At boot — when `rotate-on-start` is off — the gateway probes each
manual route twice and logs a warning when the two probes differ.

## States

`/status` reports each manual route's rotation view:

| State       | Meaning                                                                      |
| ----------- | ---------------------------------------------------------------------------- |
| `idle`      | Serving; last verified rotation observed a changed IP (or none has run yet). |
| `draining`  | Mid-procedure: ineligible for picks, waiting for in-flight work.             |
| `rotating`  | Mid-procedure: baseline learned, rotate API call in progress.                |
| `verifying` | Mid-procedure: watching for a changed egress IP.                             |
| `stale`     | Serving; the last attempt(s) did not change the IP; next retry is scheduled. |

Each view additionally shows:

| Field               | Meaning                                                                                                                                                             |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `lastIP`            | The last verified egress IP — operational data, not a credential.                                                                                                   |
| `lastRotationAt`    | When that rotation was recorded (RFC 3339).                                                                                                                         |
| `nextRetryIn`       | How long until the next attempt (stale routes only).                                                                                                                |
| `consecutiveSameIP` | Attempts **in a row that did not change the IP** — the provider declining to rotate. Resets on a verified rotation.                                                 |
| `rotationCount`     | Successful rotations **this route** has committed: verified, changed, non-colliding IPs. The per-route form of the global `rotations`, whose meaning is unchanged.  |
| `ipRevisitCount`    | Of those, how many committed an IP **this same route had already verified earlier in its lifetime** — the baseline included. Always emitted, so a zero is explicit. |

A **revisit** is a success that was not a surprise: the rotation worked, the
egress IP really changed, and the provider handed back an address this route
had already used. That is a different condition from `consecutiveSameIP`, and an
operator must not read the two as one failure: `consecutiveSameIP = 4` means
four consecutive rotation attempts **failed to change the current IP** (the
provider ignored the call — the route keeps serving and retries with backoff),
whereas `ipRevisitCount = 3` means three successful rotations **changed the IP
to an address the route had used before** (the provider's pool is recycling —
rotations are happening, but the route's egress diversity is not growing). The
remediation differs too: the first points at the rotate call, the second at the
size or turnover of the provider's address pool.

Counters move only on a commit. An unchanged attempt, a failed rotate API call,
a candidate rejected because another manual route currently holds it, and a
candidate that loses the late-collision race at commit time move neither counter
and leave no trace in the history. The ordering inside one critical section is:
verify → commit succeeds → the committed IP's membership in the route's history
is decided → the IP is recorded → `rotationCount` advances → `ipRevisitCount`
advances when it was already there.

The history behind `ipRevisitCount` is **internal**: it is never exposed as a
list, never logged, and never approximated — the count is exact by design,
because a bounded or probabilistic structure would under-count precisely when a
provider recycles addresses. The cost is memory: an exact lifetime set of an
address's 16 canonical bytes plus map overhead per manual route, on the order of
10 MB per route per year for a route rotating every 90 s.

Every rotation-path comparison that means "is this the same egress IP" uses the
same canonical identity — the 16-byte form of the address, with IPv4 and its
IPv4-mapped IPv6 form one identity and equivalent IPv6 textual forms one
identity. It governs the baseline check, the unverified-mode current-IP check,
the cross-route collision check, and history membership alike, and what gets
recorded as `lastIP` is always the canonical text, never the spelling a probe
happened to return. It is also deliberately distinct from the revisit question:
a successful rotation **may still be a revisit**, and `ipRevisitCount` never
means "the IP did not change". The history survives an identity-preserving
reload (the same URL, kind, and origin keep the same route state); a route whose
identity changes starts a fresh history, and so do its counters. The full
`/status` contract is in [observability](observability.md).

## Reload and shutdown interplay

Manual routes reload like everything else: new or changed entries are picked up
on the next one-second scheduling cycle, and unchanged identities keep their
rotation state — the successful-rotation counters and the verified-IP history
behind them included. A route removed (or whose URL, kind, or origin changes) while
its procedure runs has that procedure abandoned at the next checkpoint; the
provider API is not called again for it and no outcome is recorded.

The checkpoint the removal check cannot cover is the commit itself. A commit is
always addressed to a generation, and it decides three things as one critical
section under the pool lock, **atomically with recording the candidate**:

- the pool it is addressed to is still the generation's live pool;
- the route is still a member of that pool;
- no other manual route claims the candidate IP.

Both of the first two are needed. A reload publishes a whole new pool, so a
procedure still holding the one it started against addresses a pool that no
longer serves — even when the reload changed nothing about this route, in which
case the route state is deliberately reused and the same route **is** a member
of the new pool. Membership alone therefore cannot tell that case apart from a
current commit, and the generation itself is what is compared.

A commit that fails either check is refused as route-gone: nothing is recorded —
no `lastIP`, no `lastRotationAt`, no counters, no history, no global aggregates —
and the procedure unwinds without treating the attempt as a rotation failure, so
a route no longer serving traffic is never reported stale. The commit result is
exactly `success | collision | route-gone`; a commit that is not addressed to
the live pool can never produce a successful rotation event, and a rotation
verified just before an identity-preserving reload still commits — exactly once,
into the generation that serves now.

Shutdown cancels the rotation engine first, so every mid-flight procedure stops
immediately and leaves the route in its last serving state; rotations never
extend `RPGW_SHUTDOWN_GRACE` and tunnels are never broken by shutdown sequencing
beyond the ordinary listener drain (see [deployment](deployment.md)).

## Request-path interaction

Rotation procedures run outside the request path: probe traffic bypasses pool
health entirely and never creates cooldowns or failures. Requests picked before
a rotation began keep running on their tunnels — even when the drain timeout
expires, they simply finish on the old egress IP. Requests arriving during a
procedure select other routes, or receive the ordinary `no_route`
general-failure reply (`05 01`) when none exist
([failure and route health](failure-and-health.md)).
