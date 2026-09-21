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
   not count). Success records the new IP as the route's baseline, clears both
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

Each view additionally shows `lastIP` (the last verified egress IP — this is
operational data, not a credential), `lastRotationAt` (RFC 3339), `nextRetryIn`
(stale routes only), and `consecutiveSameIP`. The full `/status` contract is in
[observability](observability.md).

## Reload and shutdown interplay

Manual routes reload like everything else: new or changed entries are picked up
on the next one-second scheduling cycle, and unchanged identities keep their
rotation state. A route removed (or whose URL, kind, or origin changes) while
its procedure runs has that procedure abandoned at the next checkpoint; the
provider API is not called again for it and no outcome is recorded.

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
