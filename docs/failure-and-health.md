# Failure and route health

The pool is one shared set of upstream routes with health state visible through
every listener. This page is the normative contract for how failures are
classified, how routes are selected, and what each outcome does to health.

## Failure classes

- **`proxy_connect`**: DNS resolution or TCP dialing of the configured SOCKS
  endpoint fails.
- **`auth_route`**: a connected SOCKS endpoint cannot authenticate the
  configured route.
- **`socks_connect`**: the SOCKS handshake with a connected endpoint fails
  before the target tunnel is established: greeting, method or authentication
  framing, CONNECT framing or reply I/O, and bound-address reads. No client
  bytes have crossed the tunnel yet, so these are route failures, not request
  failures.
- **`connect_target`**: a connected endpoint answered the CONNECT request
  itself with an explicit non-zero reply code (RFC 1928 REP). The greeting
  succeeded and a complete reply arrived, so the route demonstrably works;
  what is refused is this target. The failure logs under its own kind and is
  retried like any other handshake-stage failure, but the cooldown it creates
  is scoped to the (route, target) pair — see
  [Cooldown scopes](#cooldown-scopes).
- **`setup`**: local SOCKS request errors that behave the same on every route
  (malformed target encoding, oversized configured credentials, invalid
  target) and every error after the tunnel is established, including target
  reads, writes, cancellation, and established-tunnel failures.
- **`no_route`**: no eligible untried route remains.
- **`retry_exhausted`**: the `max-retries` budget was spent while eligible
  untried routes still remained — the pool ran out of retries, not routes.
  The client still receives `05 01`; the distinct kind only tells the
  operator which condition ended the chain.

| Outcome                                                                                                                       | Pool handling                                                                 | Request handling                                                                 |
| ----------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| SOCKS endpoint DNS/TCP dial fails                                                                                             | Record `proxy_connect`, exponential cooldown                                  | Retry a distinct eligible route; `05 01` general-failure reply when none remains |
| SOCKS endpoint cannot authenticate                                                                                            | Auth-block the route; no dial cooldown                                        | Retry a distinct eligible route; `05 01` general-failure reply when none remains |
| SOCKS handshake fails before the tunnel is established (no explicit refusal)                                                  | Record `socks_connect`, exponential route cooldown                            | Retry a distinct eligible route; `05 01` general-failure reply when none remains |
| Upstream refuses the CONNECT request with a non-zero reply                                                                    | Record `connect_target`, exponential cooldown scoped to the route+target pair | Retry a distinct eligible route; `05 01` general-failure reply when none remains |
| Local SOCKS request error (invalid target encoding, credentials, invalid target) or any error after the tunnel is established | No health mutation and no retry                                               | Close loop; `05 01` general-failure reply for inbound setup errors               |
| Target reads/writes fail or the target response is malformed                                                                  | No health mutation and no retry                                               | Close tunnel                                                                     |
| Client cancellation/disconnect                                                                                                | No health mutation and no retry                                               | Close connection                                                                 |
| Established tunnel breaks                                                                                                     | No health mutation                                                            | Close tunnel                                                                     |

A request tries at most `max-retries` distinct eligible routes in total (see
[configuration](configuration.md#runtime-yaml)); a request never tries the same
route twice. When the chain stops, the terminal record distinguishes which
condition did it: if a pick found no eligible untried route the kind is
`no_route`, and if the retry budget expired first while eligible routes
remained the kind is `retry_exhausted`.

## Selection

The pool serves the eligible route with the smallest recency pass: every pick
and every completed request advances the route's pass by one step, and
first-seen order breaks ties, giving true round-robin across the eligible set.
A route returned to serving after a stale rotation is pushed behind the whole
pool so fresher routes absorb traffic first; a route that joins through a
reload is picked next. A pick from the all-cooling fallback advances the pass
like any other.

Cooling routes are skipped when a usable eligible route exists; when all
eligible non-auth-blocked routes cool down, the one recovering soonest is
tried — blind to selection order, because soonest recovery is the only
criterion that matters there. The kind filter applies to ordinary selection and
to the all-cooling fallback alike: a listener never falls through to a route of
another kind. Authentication blocks remain until the route identity changes on
reload.

Cooldowns run on a monotonic clock, so wall-clock steps (NTP corrections,
manual date changes) can neither expire nor extend them.

## Cooldown scopes

Cooldowns come in two scopes, and `cooldown.base`/`cooldown.max` drive both
through the same saturating curve (base doubled per consecutive failure,
capped at max):

- **Route scope** (`proxy_connect`, `socks_connect`): a route-level failure
  makes the route ineligible for **every** target until its cooldown lifts,
  because dial, greeting, auth-framing, and reply-I/O failures are
  target-independent — the route itself is broken.
- **Pair scope** (`connect_target`): an explicit refusal of one CONNECT
  makes only the **(route, target) pair** ineligible, leaving the route
  eligible for every other target. The pair's escalation streak is counted
  independently per target, so repeated refusals of one destination cap out
  at `cooldown.max` for that pair alone; a success through the pair clears
  its cooldown and resets its streak, and touches no other pair — and a
  verified rotation of the route clears all its pair cooldowns at once,
  because every tracked refusal was answered from the old egress IP
  ([manual rotation routes](rotation.md)).

Both scopes feed the all-cooling fallback: when every allowed route is cooling
for the request's target under either scope, the fallback hands out the route
that can serve **that target** again soonest — the later of its route and pair
deadlines decides. Pair tracking is bounded per route (1024 targets; expired
entries are reclaimed first, then the soonest-recovering pair is evicted), so a
flood of unique refused targets cannot grow memory without limit. Pair
cooldowns survive a reload exactly like other retained route state, and the
tracked targets are client-controlled strings that never appear in logs or
`/status` — only the summary counts do.

## What never mutates health

Target bytes are ordinary tunnel data. A byte sequence that resembles an HTTP
`407` is not SOCKS authentication data, does not rotate, and does not create
cooldown; once the tunnel is established, nothing the target sends alters
route health. Local inbound protocol errors
([inbound SOCKS5 behavior](inbound-socks5.md)) and everything after the tunnel
exists are `setup`: no health mutation, no retry. Rotation probe traffic
bypasses pool health entirely ([manual rotation routes](rotation.md)), and the
[warm pool](warm-pool.md) never writes route health either.
