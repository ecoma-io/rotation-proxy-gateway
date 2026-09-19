# rotation-proxy-gateway

`rotation-proxy-gateway` is a Go HTTP forward proxy that accepts stable
inbound HTTP proxy endpoints and routes traffic through a health-aware pool of
**SOCKS5-only** upstream routes. It supports ordinary absolute-form HTTP
requests and inbound `CONNECT` tunnels.

<p align="center">
  <a href="https://github.com/ecoma-io/rotation-proxy-gateway/actions/workflows/ci.yml"><img src="https://github.com/ecoma-io/rotation-proxy-gateway/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/ecoma-io/rotation-proxy-gateway/actions/workflows/analysis.yml"><img src="https://github.com/ecoma-io/rotation-proxy-gateway/actions/workflows/analysis.yml/badge.svg" alt="Analysis" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache 2.0" /></a>
</p>

> **Status:** This document is the normative behavior contract. In particular,
> never infer SOCKS route health from a destination HTTP response.

## Inbound endpoints

The process starts one admin listener and up to three proxy listeners:

| Endpoint | Default | Purpose |
|---|---:|---|
| Admin | `0.0.0.0:30120` | `/healthz` and `/status`; operator controls network exposure |
| Mixed proxy | `:30121` | Selects both v4- and v6-egress routes |
| IPv4 proxy | `:30122` | Selects only `kind: v4` routes |
| IPv6 proxy | `:30123` | Selects only `kind: v6` routes |

`kind` is the public egress IP family supplied by a proxy provider. It is not
the SOCKS endpoint address family and it does not impose an IPv4/IPv6 policy on
the client's target destination.

A single shared pool owns health state. Therefore, a dial cooldown or SOCKS
authentication block observed through the v4 listener is also observed by the
mixed listener when it considers that route. A listener never falls through to
a route of another kind. A v4-only or v6-only route pool is valid: mixed selects
the available family, and the enabled dedicated listener without matching routes
remains live but returns the ordinary no-route `502` until that family is added.

## Quick start

```bash
cp config.example.yaml config.yaml # add real static SOCKS routes
MIXED_LISTEN_ADDR=:30121 \
V4_LISTEN_ADDR=:30122 \
V6_LISTEN_ADDR=:30123 \
ADMIN_ADDR=0.0.0.0:30120 \
go run ./cmd/rotation-proxy-gateway

curl -x http://127.0.0.1:30121 https://example.com/
curl http://127.0.0.1:30120/status
```

`config.yaml` normally contains upstream credentials and is ignored by Git and
Docker build contexts. Do not commit it or bake it into an image.

## Configuration

### Bootstrap settings -- environment, restart required

These values create sockets or choose the polled file and are read only when
the process starts. Empty proxy listener addresses disable their listener, but
at least one proxy listener must remain enabled.

| Variable | Default | Meaning |
|---|---:|---|
| `CONFIG_FILE` | `config.yaml` | Runtime YAML file path |
| `ADMIN_ADDR` | `0.0.0.0:30120` | Always-on admin listener; network policy controls exposure |
| `MIXED_LISTEN_ADDR` | `:30121` | Mixed v4/v6 egress listener |
| `V4_LISTEN_ADDR` | `:30122` | v4-egress-only listener |
| `V6_LISTEN_ADDR` | `:30123` | v6-egress-only listener |
| `SHUTDOWN_GRACE` | `55s` | Total shared drain budget for graceful shutdown |

All enabled addresses must be valid, use a numeric port, and not overlap --
including wildcard binds on the same port. Docker Healthcheck uses only
`ADMIN_ADDR`; a bad runtime reload cannot make an otherwise-running service
unhealthy.

### Runtime YAML -- validated and hot-reloaded

See [`config.example.yaml`](config.example.yaml). The file is the complete
source for runtime behavior and static routes:

```yaml
log-level: info
max-retries: 3
cooldown:
  base: 15s
  max: 10m
dial-timeout: 10s
balance:
  v4: 7
  v6: 3
global:
  target-tls-insecure: false
  max-body-buffer: 67108864
proxies:
  auto:
    - proxy: socks5://username:password@provider.example:1080
      kind: v4
      weight: 3
    - proxy: socks5://username:password@[2001:db8::1]:1080
      kind: v6
  manual: []
```

`proxies.auto` is the source of static routes; `proxies.manual` routes
additionally carry a rotate schedule and provider API (see
["Manual rotation routes"](#manual-rotation-routes)). The accepted `proxy`
forms are:

```text
socks5://host:port
socks5://user:pass@host:port
host:port:user:pass
user:pass@host:port
```

Every route requires an explicit port. Bracket IPv6 literals. HTTP/HTTPS routes,
URL paths, queries, fragments, unknown active YAML fields, duplicate route
identities, and non-lowercase/missing `kind` are rejected. A duplicate remains
a duplicate even if it claims another kind. Credentials never appear in errors,
logs, or `/status`.

Every route accepts an optional selection `weight` (whole number, default 1, at
most 1000): picks distribute across eligible routes proportionally to their
weights, so `weight: 3` serves about three times the traffic of a `weight: 1`
peer. Equal weights — or no `weight` key at all — give true round-robin. The
key exists on both `proxies.auto` and `proxies.manual` routes and is not part
of route identity: a reload that only retunes weights keeps the route's health
state.

The optional `balance` block splits mixed-listener picks between the two egress
families by relative share — `balance: {v4: 7, v6: 3}` sends about 70% of mixed
traffic through `kind: v4` routes no matter how many routes each family has,
while route `weight` still distributes picks inside one family. Each share is a
whole number 1–1000; a family with no share only serves as standby when the
shared family has no live route, and a family whose routes are all cooling or
auth-blocked always defers to the other — availability beats the ratio. The
dedicated v4/v6 listeners ignore the block. Without it, each family's share
follows its routes' own weights, exactly as if the pool were flat. A reload
that changes the ratio applies to the retained routes and carries the split's
phase over.

`global.target-tls-insecure` and `global.max-body-buffer` are global settings;
per-route overrides are rejected. `target-tls-insecure` defaults to `false` and
should not be enabled for untrusted targets.

`proxies.auto` routes and `proxies.manual` routes share one pool and one
identity space; a duplicate across the two lists is rejected like any other.

## Manual rotation routes

`proxies.manual` routes are static SOCKS routes whose **public egress IP is
changed through a provider HTTP API** on a per-route schedule. The gateway
drives that schedule itself: it probes the route's current egress IP, calls the
provider's rotate endpoint, verifies the egress IP actually changed, and records
the outcome. Manual routes serve ordinary traffic like any other route between
rotations.

### Route configuration

```yaml
proxies:
  manual:
    - proxy: socks5://username:password@provider.example:1080
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
- `weight` (optional, whole number 1–1000, default 1): selection weight,
  identical to the `proxies.auto` route key. Higher-weight manual routes absorb
  proportionally more traffic between rotations.
- `api` (required): the provider call that requests a new egress IP.
  `url` is required (http or https). `method` defaults to `POST`. `timeout`
  defaults to `10s` and bounds one call. `headers` and `body` are sent verbatim.
  **Headers and body may carry provider credentials: they are never logged,
  never echoed in errors, and never exposed by `/status`.** The call is made
  directly from the gateway process and never through the route pool, so a
  failing provider API cannot affect route health.
- `kind` keeps its phase-1 meaning: the provider-backed public egress IP family.
  It does not restrict target address families, and no family is inferred from
  the SOCKS endpoint address.

### Rotation settings

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

| Setting | Default | Meaning |
|---|---:|---|
| `max-concurrent` | `1` | Rotation procedures running at once: a fixed count, or `"NN%"` of the manual routes (rounded up, at least 1, never more than the route count). Resolved fresh every scheduling cycle. |
| `drain-timeout` | `55s` | How long a procedure waits for the route's in-flight requests to finish before force-rotating. Expiry does not wait longer; requests already in flight may continue on the old egress IP. |
| `rotate-on-start` | `false` | Rotate every manual route at process start, under the same cap and staggering, instead of waiting one interval. |
| `ip-check-url` | Cloudflare trace | HTTPS URL whose response body contains an `ip=` line. **Must be `https`.** The probe always verifies TLS regardless of `target-tls-insecure`. |
| `ip-check-timeout` | `20s` | Total window for one verification: how long a procedure watches for a changed IP before giving up on that attempt. |
| `ip-check-interval` | `2s` | Pause between verification probes inside that window. |
| `retry-backoff-max` | `15m` | Ceiling of the same-IP retry backoff. |

`rotation.drain-timeout` and `SHUTDOWN_GRACE` are unrelated budgets. The drain
timeout bounds one route's pre-rotation quiesce; the shutdown grace bounds the
whole process's listener drain. They never interact: a rotation procedure never
extends shutdown, and shutdown never waits on a rotation.

### Procedure contract

Each attempt runs: **drain → baseline probe → rotate call → verify**.

1. **Drain.** The route stops receiving new picks immediately and stays
   ineligible for the whole procedure. The procedure waits for the route's
   in-flight requests to finish, bounded by `drain-timeout`; expiry proceeds
   anyway. Draining a route that serves no other purpose can make requests fail
   with the ordinary `no_route` `502` until the window ends.
2. **Baseline probe.** The gateway dials through the route (SOCKS, then TLS)
   to `ip-check-url` and reads the `ip=` line. Three attempts; if all fail the
   procedure continues with no known baseline (**unverified mode**), and later
   verification only requires an IP that does not collide with another manual
   route.
3. **Rotate call.** One call to the route's `api`. Transport errors, non-2xx
   statuses, and timeouts end the call; the procedure still probes once, because
   the provider may have rotated despite reporting failure. A `429` response
   with `Retry-After: N` raises the next attempt's wait to at least `N` seconds.
4. **Verify.** The gateway re-probes until `ip-check-timeout` elapses. The
   attempt **succeeds only if the reported IP differs from the baseline and is
   not the current IP of any other manual route** (a cross-route collision does
   not count). Success records the new IP as the route's baseline, clears dial
   cooldowns learned against the old IP, and never clears an authentication
   block — credentials did not rotate with the IP.

**An unchanged IP is not a failure of the route.** The route returns to serving
immediately in the `stale` state, and the gateway retries forever — the next
attempt waits one `rotate-interval`, doubling per consecutive unchanged result
(`interval`, `2×`, `4×`, …) with ±10% jitter, capped at `retry-backoff-max`, and
floored by any `Retry-After`. Stale routes are pushed to the back of the
weighted recency order so fresher routes absorb traffic first, but they keep
serving normally.

A route whose provider hands out non-sticky addresses cannot be rotated
reliably. At boot the gateway probes each manual route twice and logs a warning
when the two probes differ.

### States

`/status` reports each manual route's rotation view:

| State | Meaning |
|---|---|
| `idle` | Serving; last verified rotation observed a changed IP (or none has run yet). |
| `draining` | Mid-procedure: ineligible for picks, waiting for in-flight work. |
| `rotating` | Mid-procedure: baseline learned, rotate API call in progress. |
| `verifying` | Mid-procedure: watching for a changed egress IP. |
| `stale` | Serving; the last attempt(s) did not change the IP; next retry is scheduled. |

Each view additionally shows `lastIP` (the last verified egress IP — this is
operational data, not a credential), `lastRotationAt` (RFC 3339), `nextRetryIn`
(stale routes only), and `consecutiveSameIP`.

### Reload and shutdown interplay

Manual routes reload like everything else: new or changed entries are picked up
on the next one-second scheduling cycle, and unchanged identities keep their
rotation state. A route removed (or whose URL, kind, or origin changes) while
its procedure runs has that procedure abandoned at the next checkpoint; the
provider API is not called again for it and no outcome is recorded.

Shutdown cancels the rotation engine first, so every mid-flight procedure stops
immediately and leaves the route in its last serving state; rotations never
extend `SHUTDOWN_GRACE` and tunnels are never broken by shutdown sequencing
beyond the ordinary listener drain.

### Request-path interaction

Rotation procedures run outside the request path: probe traffic bypasses pool
health entirely and never creates cooldowns or failures. Requests picked before
a rotation began keep running (unless the drain timeout expired and the operator
accepts the old egress); requests arriving during a procedure select other
routes, or `502` with `no_route` when none exist.

### Reload behavior

The process polls the runtime YAML every second and reloads when the file's
content hash changes, so every way of updating the file behaves the same:
in-place edits, atomic replacements (editor save, `mv`, symlink swap), and any
bind-mount style. Hashing content instead of listening for filesystem events
deliberately trades instant delivery for universality; up to one second of
latency is irrelevant for configuration.

```yaml
# compose.yaml
volumes:
  - ./config.yaml:/app/config.yaml:ro
environment:
  CONFIG_FILE: /app/config.yaml
```

One case no in-process reader can observe: renaming a new file over the config
**behind a single-file bind mount**. The mount pins the file's inode, so a
host-side `mv`/editor-safe-save swaps in a new inode that the container path
never follows; the old content keeps serving until restart. With a single-file
mount, update the file in place, or mount its directory instead.

Each reload parses and validates a complete new configuration before changing
any serving state. A syntax error, partial write, invalid route, or invalid
runtime setting logs a sanitized warning and retains the last-known-good config
and pool. Validated configuration and its reconfigured pool snapshot publish as
one atomic generation: every request and CONNECT operation loads that generation
once, while in-flight operations finish on their original snapshot.

#### Measured mount behavior (Docker bind mounts)

Measured on Linux (2026-09), first against event-based watching (Viper 1.21 +
fsnotify), then against the current content-hash poller:

| Host update | Directory bind mount | Single-file bind mount |
|---|---|---|
| In-place write (`echo > file`) | reload fires | reload fires (poller only — inotify never sees it) |
| Atomic rename-over (editor save, `mv`) | reload fires | invisible (mount pins the old inode) |

The rename-over single-file blind spot is inherent to bind-mount semantics, not
to any watcher implementation: nothing inside the container can observe a new
inode spliced in on the host. Event-based watching had a second blind spot —
inotify parent-directory events follow the writing side's path hierarchy, so a
single-file in-place write produced no event at all. Polling by content was
adopted so the mount style stops mattering, and there is deliberately no
signal-based fallback: SIGHUP re-reads the same pinned inode and cannot fix
either blind spot.

The following settings apply to new client operations without restart:

- `log-level`
- `max-retries`
- `cooldown.base` and `cooldown.max` (new dial failures only)
- `dial-timeout`
- `global.target-tls-insecure`
- `global.max-body-buffer`
- `proxies.auto` and `proxies.manual`
- every `rotation.*` setting (the scheduler reads them per cycle; a procedure
  already running keeps its own `drain-timeout` and probe settings)

Unchanged URL+kind routes preserve their recency pass, cooldown,
authentication-block, rotation state (last verified IP, stale history), and
counters. A changed `weight` applies to the retained route without resetting
any of it. Changing userinfo, kind, or moving a route between `proxies.auto`
and `proxies.manual` creates a fresh route state.

## Failure and route-health contract

### Definitions

- **`proxy_connect`**: DNS resolution or TCP dialing of the configured SOCKS
  endpoint fails.
- **`auth_route`**: a connected SOCKS endpoint cannot authenticate the
  configured route.
- **`socks_connect`**: the SOCKS handshake with a connected endpoint fails
  before the target tunnel is established: greeting, method or authentication
  framing, CONNECT framing or reply, and bound-address reads. No client bytes
  have crossed the tunnel yet, so these are route failures, not request
  failures.
- **`setup`**: local request errors that behave the same on every route
  (unsupported scheme, oversized configured credentials, invalid target) and
  every error after the tunnel is established, including target TLS, writes,
  reads, malformed responses, cancellation, and established-tunnel failures.
- **`no_route`**: no eligible untried route remains.

| Outcome | Pool handling | Request handling |
|---|---|---|
| SOCKS endpoint DNS/TCP dial fails | Record `proxy_connect`, exponential cooldown | Retry a distinct eligible route; synthetic `502` only when none remains |
| SOCKS endpoint cannot authenticate | Auth-block the route; no dial cooldown | Retry a distinct eligible route; synthetic `502` only when none remains |
| SOCKS handshake fails before the tunnel is established | Record `socks_connect`, exponential cooldown | Retry a distinct eligible route; synthetic `502` only when none remains |
| Local request error (scheme, credentials, invalid target) or any error after the tunnel is established | No health mutation and no retry | Sanitized `502` |
| Target TLS, HTTP write/read, malformed response | No health mutation and no retry | `502` unless client cancelled |
| Valid target HTTP response, including `407`, `408`, `429`, `5xx` | Record success; no rotation/cooldown | Forward once |
| Client cancellation/disconnect | No health mutation and no retry | End operation |
| Established tunnel breaks | No health mutation | Close tunnel |

The pool serves the eligible route with the smallest weighted recency pass:
every pick, completed request, and stale return advances the route's pass by
one step inversely proportional to its `weight`, so picks distribute
proportionally to the configured weights and equal weights give true
round-robin. On the mixed listener, a configured `balance` block composes a
family clock above this order: the family whose clock is furthest behind
serves first — zero-share families only as standby — and the weighted order
then picks the route inside that family. A request never tries the same route
twice. Cooling routes are skipped when a usable eligible route exists; when
all eligible non-auth-blocked routes cool down, the one recovering soonest is
tried — weight- and family-blind, because soonest recovery is the only
criterion that matters there. Authentication blocks remain until the route
identity changes on reload.

A target HTTP `407` is ordinary target response data. It is not SOCKS
authentication data, does not rotate, and does not create cooldown.

## HTTP and CONNECT behavior

Clients send absolute-form HTTP requests. The forwarder opens one SOCKS5
`CONNECT` tunnel to the target for each ordinary request, writes an origin-form
request, and performs target TLS inside that tunnel for HTTPS. It removes
hop-by-hop headers, including `Connection`-listed headers and
`Proxy-Authorization`, in both directions.

Bodies up to `global.max-body-buffer` are replayable after an endpoint dial,
SOCKS handshake, or authentication fallback. Known-larger bodies stream
immediately; unknown-length bodies are probed up to the limit. Once streamed
bytes have been consumed, the body cannot safely be retried. Declared request
trailers retain chunked framing.

For CONNECT, the service returns `200 Connection Established` only after the
SOCKS target CONNECT succeeds, then relays bytes bidirectionally. Failures after
that point do not alter route health.

Relayed bytes are never inspected or buffered: streamed responses such as
server-sent events are flushed per chunk, and established tunnels have no
timeouts. An upstream that breaks the tunnel mid-stream resets the client
connection, so a truncated stream stays visibly truncated instead of reading as
a clean end.

## Admin and observability

```bash
curl http://127.0.0.1:30120/healthz # body: ok\n
curl http://127.0.0.1:30120/status
ADMIN_ADDR=127.0.0.1:30120 ./bin/rpgw healthcheck
./bin/rpgw version
```

`/status` keeps `version`, `uptime`, global `requests`, global `rotations`
(completed manual-route rotations that observed a changed egress IP), and
redacted `pool` state. It additionally reports safe per-listener counters —
`requests` and `failovers` (in-band route fallbacks, distinct from rotations) —
each route's `kind` and `origin`, each manual route's rotation view (see
"Manual rotation routes"), and the active `balance` family split when one is
configured. Route identities are always `host:port`, never
userinfo; rotate-API headers, bodies, and URLs never appear anywhere in the
output. Each route's `failures` and `lastDialError` cover endpoint dial and
SOCKS handshake failures.

Each request has a process-local `request_id`. Logs additionally include
`listener=mixed|v4|v6`, host-only `target` and `upstream`, retry attempts,
error category, and cooldown for endpoint dial and SOCKS handshake failures.
They never log full URLs, headers, bodies, userinfo, or the rotate-API
configuration.

Every established tunnel also logs a close record with its lifetime,
per-direction byte counts, and which side ended the stream first
(`close_reason`). Close records log at `debug`; a tunnel broken by an
upstream-side error logs at `warn`, making mid-stream provider drops
attributable.

## Docker

```bash
cp config.example.yaml config.yaml
# edit config.yaml with real routes
docker compose up -d --build
curl http://127.0.0.1:30120/status
```

Compose publishes ports `30120` (admin), `30121` (mixed), `30122` (v4), and
`30123` (v6) on all host interfaces. The admin process listener deliberately
binds all interfaces inside its network namespace; operators control exposure
through Docker port publishing, Docker networks, and firewall policy. The image
remains a static binary in `scratch` with CA certificates and no shell; its
healthcheck invokes the binary subcommand directly. Compose retains at most
three 10 MiB JSON log files.

## Migration from `proxies.txt`

For each old line, create one `proxies.auto` item and choose `kind` from your
provider's documented public egress family. There is no safe automatic family
detection from the SOCKS hostname/IP. `proxies.txt` is no longer loaded.

## Build and verification

The source supports Go 1.25 or newer. Docker builds with Go 1.27. The project
uses Viper for YAML loading and validation; hot reload is a self-contained
content-hash poller (see "Reload behavior").

```bash
gofmt -w .
go vet ./...
go test -race ./...
go build -ldflags "-X main.version=0.1.0-dev" -o bin/rpgw ./cmd/rotation-proxy-gateway
```

Graceful shutdown stops the rotation engine (mid-flight procedures abort at
their next checkpoint; no outcome is recorded), then drains every enabled proxy
listener and the admin listener against one shared budget, `SHUTDOWN_GRACE`
(default 55s). It is one deadline for the whole process, not a window per
listener, so even a fully busy worst case exits near the budget; an idle
process exits immediately. When the budget expires, the remaining listeners are
still closed, and hijacked CONNECT tunnels that `http.Server.Shutdown` does not
track are force-closed. Size the surrounding orchestrator above the budget --
for example `stop_grace_period: 60s` in compose -- so its kill timer never cuts
the drain short.

## Community

- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md) — the commands, the hooks,
  the commit and pull-request conventions, how a release happens.
- Code of conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Security: [SECURITY.md](SECURITY.md) — never a public issue for a
  vulnerability.
- License: [LICENSE](LICENSE) — Apache 2.0.
