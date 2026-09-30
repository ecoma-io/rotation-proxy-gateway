# rotation-proxy-gateway

Go HTTP forward proxy that routes `CONNECT` and absolute-form HTTP requests
through a health-aware pool of **SOCKS5-only** outbound routes. It runs three
inbound HTTP proxy listener views over one shared route-health pool:

- mixed egress (`30121` by default): v4 and v6 routes
- v4 egress (`30122` by default): `kind: v4` routes only
- v6 egress (`30123` by default): `kind: v6` routes only

The always-on admin listener defaults to `0.0.0.0:30120`; operators control
network exposure through Docker port publishing, network policy, and firewalls.
The authoritative behavior contract lives under [`docs/`](docs/);
[`docs/architecture.md`](docs/architecture.md) is the cross-cutting map of the
request path, generation publication, rotation, and warm pool; and
[`README.md`](README.md) is the entry point.

## Build and test

```bash
gofmt -w . && go vet ./... && go test -race ./...
go build -ldflags "-X main.version=0.1.0-dev" -o bin/rpgw ./cmd/rotation-proxy-gateway
```

The source supports Go ≥ 1.25; Docker builds with Go 1.27. Viper is used for
runtime YAML loading and validation; hot reload is a self-contained 1s
content-hash poller (`internal/config.Poller`). Style rules: source randomness from `crypto/rand` (the semgrep
security gate rejects every `math/rand` variant, v2 included) and use
`for range n` loops.

## Configure and run

Copy [`config.example.yaml`](config.example.yaml) to Git-ignored `config.yaml`,
then replace the placeholder `proxies.auto` SOCKS routes. The file may contain
credentials; never log, commit, or bake it into an image.

```bash
RPGW_CONFIG_FILE=config.yaml \
RPGW_ADMIN_ADDR=0.0.0.0:30120 \
RPGW_MIXED_LISTEN_ADDR=:30121 \
RPGW_V4_LISTEN_ADDR=:30122 \
RPGW_V6_LISTEN_ADDR=:30123 \
./bin/rpgw
```

Environment variables are bootstrap-only and require restart:

| Env                      |         Default | Meaning                                                 |
| ------------------------ | --------------: | ------------------------------------------------------- |
| `RPGW_CONFIG_FILE`       |   `config.yaml` | Runtime YAML path                                       |
| `RPGW_ADMIN_ADDR`        | `0.0.0.0:30120` | Admin (HTTP) listener; network policy controls exposure |
| `RPGW_MIXED_LISTEN_ADDR` |        `:30121` | Mixed v4/v6 egress HTTP proxy listener                  |
| `RPGW_V4_LISTEN_ADDR`    |        `:30122` | IPv4-egress-only HTTP proxy listener                    |
| `RPGW_V6_LISTEN_ADDR`    |        `:30123` | IPv6-egress-only HTTP proxy listener                    |
| `RPGW_SHUTDOWN_GRACE`    |           `55s` | Total shared drain budget for graceful shutdown         |
| `RPGW_ACCOUNT`           |         _unset_ | Require `Proxy-Authorization` on proxy listeners        |

Empty proxy listener addresses disable their listener, but at least one proxy
listener must remain enabled. All enabled addresses must be valid host:port
addresses and must not overlap (including wildcard binds on the same port).
Every bootstrap variable carries the `RPGW_` prefix; a set legacy unprefixed
name fails startup with an error naming its replacement, and
[`.env.example`](.env.example) lists the full set.

Runtime settings and active routes live only in `config.yaml`:
`log-level`, `max-retries`, `cooldown`, `dial-timeout`, `proxies.auto`,
`proxies.manual`, the `rotation` block, the optional `warm-pool` block, and
the optional `routing` block. The process polls the file each
second and reloads when its content hash changes, so in-place edits and atomic
replacements both reload under any mount style. A failed parse/validation
leaves the last-known-good pool and runtime settings serving. Do not add a
manual reload fallback (for example SIGHUP), and do not reintroduce
event-based watching: neither can fix the one blind spot, a rename-over a
single-file bind mount (the mount pins the old inode) — see
[`docs/configuration.md`](docs/configuration.md) "Reload behavior".
The removed HTTP era's `global:` block is rejected: a config containing
`target-tls-insecure` or `max-body-buffer` fails validation — the
last-known-good config keeps serving, and on first boot the process refuses
to start. Route proxy lines carry no scheme (`host:port`,
`user:pass@host:port`, `host:port:user:pass`): the endpoint protocol is
always SOCKS5, so a line containing `socks5://` — or any scheme — is
rejected the same way. The removed weighted-selection keys — a route
`weight` and a `balance` block — are rejected identically.

`kind: v4|v6` means the provider-backed **public egress IP family**. It does
not classify the SOCKS endpoint transport address and does not restrict target
address families. Do not infer kind by resolving a hostname.

## Behavior notes

Read [`docs/failure-and-health.md`](docs/failure-and-health.md) before
changing failure classification.

- The pool selects the usable **eligible** route with the smallest recency
  pass, first-seen order breaking ties — true round-robin over the eligible
  set. It is a single shared pool: cooldown, pair-scoped target-cooldown, and
  auth state are visible through both dedicated and mixed listeners. The
  optional routing block narrows selection to the target's candidate set
  (first-match-wins domain rules, `*.` label-boundary wildcards, domain targets
  only, `default-routes` or fail-closed `503`); the pool stays the sole
  authority on health and order, retries stay inside the candidate set, and
  routing never reads or writes health nor inspects tunnel bytes.
- Endpoint DNS/TCP failure is `proxy_connect`: cooldown then a distinct
  eligible fallback. SOCKS auth failure is `auth_route`, blocks the route, and
  may fall back, but never creates dial cooldown. A SOCKS handshake failure
  before the tunnel exists—greeting, method/auth framing, CONNECT framing or
  reply I/O, bound-address reads—is `socks_connect`: the same
  cooldown-and-fallback treatment as `proxy_connect`, because no client bytes
  have crossed the tunnel yet. A CONNECT the upstream itself refuses with a
  non-zero reply is `connect_target`: same cooldown-and-fallback treatment,
  but the cooldown is scoped to the (route, target) pair—same base→max curve,
  bounded per-route tracking (1024, expired-then-soonest eviction), summary
  counts only in `/status`—so one refused target cannot cool the route for
  other targets. Local inbound request errors and post-tunnel errors are
  `setup`; picking finds no eligible untried route is `no_route`, while
  spending the `max-retries` budget with eligible routes still untried is
  `retry_exhausted`.
- Errors after the SOCKS tunnel is established—including target reads/writes,
  malformed target content, cancellation, and broken tunnel—and local inbound
  request errors (malformed request target, origin-form on a proxy listener,
  absent or inconsistent authority, zero port, oversized configured
  credentials) do not alter health and are not retried.
- The optional `warm-pool` block (default off) keeps bounded half-established
  upstream connections — TCP + greeting + auth, never a target `CONNECT` —
  that requests borrow before cold-dialing; a miss falls through cold and
  never waits. The pool never writes route health (replenish pauses for
  rotating, auth-blocked, or cooling routes), stamps parked connections with
  the rotation epoch so a rotation closes the old generation, and keeps
  failure classes identical: a refused `CONNECT` through a borrow stays
  `connect_target` (pair-scoped); a dead borrowed transport discards its
  siblings with no health report. Everything is bounded (per-route min/max
  idle, global idle cap, fleet replenish concurrency plus an optional
  per-route in-flight cap `max-replenish-per-route` that keeps one provider's
  routes from taking the whole fleet, backoff, idle TTL), and
  reload-disable, route removal, and shutdown close parked connections.
  Enable it where upstream RTT is real — see the warm A/B benchmarks in
  `e2e/BENCH.md`.
- The kind filter applies to ordinary LRU selection and all-cooling fallback;
  v4/v6 listeners must never leak into the other kind. A pool containing only
  one family is valid: mixed uses it, while a dedicated listener without a
  matching route remains live and replies `503` on `no_route`.
- Inbound protocol is HTTP forward proxying. Exactly two request shapes are
  accepted: `CONNECT host:port HTTP/1.1` (authority-form target, `Host`
  optional and authoritative) and absolute-form `GET http://host/path
HTTP/1.1`. An origin-form target on a proxy listener is a request for a
  local resource that does not exist and gets `400`; a target with no path
  forwards as `/`; only `http` is proxied (`501` otherwise), a version other
  than 1.1 gets `505`, and an absolute-form method outside `GET`/`HEAD`/`POST`
  gets `405`. A malformed or absent authority gets `400`. An
  absolute-form request is rewritten to origin-form before forwarding — never
  forwarded unchanged. Malformed request lines get `400` without a tunnel.
  Domain targets are forwarded as names: DNS happens at the outbound route
  (socks5h), never in the gateway. Hop-by-hop headers, `Proxy-Authorization`,
  and every `x-ecoma-*` control header — named or not — are removed before
  forwarding; request bodies stream. A 30s read deadline bounds reading the
  request — including the whole retry chain of outbound attempts — and is
  cleared once the tunnel is established; established tunnels have no timeouts.
  One `CONNECT` tunnel is one client connection's payload; keep-alive/reuse is
  the client's choice.
  Without `RPGW_ACCOUNT`, no `Proxy-Authorization` is required and one that
  arrives anyway is consumed and stripped. With `RPGW_ACCOUNT=username:password`
  set, every request on every proxy listener must carry
  `Proxy-Authorization: Basic base64(username:password)`; a missing, malformed,
  non-`Basic`, or wrong-credential header gets `407` plus
  `Proxy-Authenticate: Basic realm="rotation-proxy-gateway"`. The comparison is
  constant-time, auth failures are pre-selection local errors that never
  advance `requests` nor touch route health, and a correct header is stripped
  before forwarding. The env var name and its `user:pass` value format are
  unchanged from the SOCKS5 era; only the wire form changed. Userinfo and the
  inbound account must never appear in logs, `/status`, errors, or responses.
- Two gateway-private `x-ecoma-*` control headers are read on ingress, stripped
  before forwarding, and absent from route identity. `x-ecoma-proxy-family`
  takes `v4`, `v6`, or `mixed` (absent = `mixed`): a request-scoped
  route-selection constraint that narrows eligible routes exactly as a
  listener's kind filter and the routing block do, composes with both by
  intersection, and never binds a socket, resolves a name, or changes the
  outbound SOCKS5 `CONNECT` target. A v4-only route can never serve a `v6`
  request on any listener — including when every route is cooling, because
  `PickFor` applies the same composed predicate to the all-cooling fallback.
  Two requests differing only in this header hit the same `pool.Proxy` objects.
  A value outside the closed set, an empty value, or a repeated header is
  refused with `400` before route selection, as a local `setup`/`bad_request`
  error that never advances `requests` nor touches route health — refusing
  rather than falling back to `mixed`, because a client that asked for IPv6
  egress and silently got IPv4 has no way to see it. `x-ecoma-request-id` is a
  client correlation id: resolved once before selection, bounded to 64 bytes
  inside `[A-Za-z0-9-_.:]`, replaced by a `r-`-prefixed id from `crypto/rand`
  when absent, repeated, over-long, or carrying anything else, and preserved
  across every retry of one chain. Both are specified in
  [`docs/inbound-http.md`](docs/inbound-http.md).
- Logs contain process-local `request_id` and `listener`; `target` and
  `upstream` are host-only. `request_id` stays the process-local ordinal,
  because it is what the per-listener `/status` `requests` figure reports;
  a client's `x-ecoma-request-id` travels beside it as `correlation_id`, and
  the two are never conflated. `debug` shows flow, `info` terminal successes,
  and `warn` fallback/terminal failures. Established tunnels log a close record
  (lifetime, per-direction byte counts, which side ended first) at `debug`; a
  tunnel broken by an upstream error logs at `warn` and resets the client
  connection.
- Reload preserves runtime pool state only for unchanged URL+kind. Changed URL
  userinfo or kind — or moving a route between `proxies.auto` and
  `proxies.manual` — creates a new route state. Validated configuration and its
  reconfigured pool snapshot publish as one atomic generation; in-flight
  operations finish on their original generation.
- Manual routes (`proxies.manual`) rotate their public egress IP through a
  provider HTTP API on a per-route schedule, driven by `internal/rotation`:
  drain → baseline probe → rotate call → verify (success requires a changed IP
  that collides with no other manual route). An unchanged IP never takes the
  route out of service: it serves in the `stale` state and retries forever with
  doubling, capped, jittered backoff. Probe and rotate traffic bypasses pool
  health entirely; rotate-API headers, bodies, and URLs must never reach logs,
  errors, or `/status`. `rotation.drain-timeout` (one route's pre-rotation
  quiesce) is unrelated to `RPGW_SHUTDOWN_GRACE` (whole-process listener drain).
- Shutdown runs in a fixed order: `/readyz` goes `503` while every listener is
  still accepting, then a 5s readiness head start (drawn from the grace, capped
  at `grace/2`, covering all listeners plus admin), then the rotation engine,
  then the warm pool, then every listen socket closed and all proxy listeners
  plus admin drained concurrently against one shared `RPGW_SHUTDOWN_GRACE`
  budget (default 55s; one deadline for the whole process, not a window per
  listener), then force-closed established tunnels. `/healthz` stays `200`
  throughout: it is liveness, and a probe that failed while the process is
  stopping correctly would invite the orchestrator to kill it mid-drain. Keep
  the surrounding orchestrator's kill timer above the budget
  (`stop_grace_period: 60s` in compose). A readiness signal is necessary but
  not sufficient for a zero-downtime rollout — that needs ≥2 replicas and a
  load balancer that honours it, which is deployment-side; see
  [`docs/deployment.md`](docs/deployment.md) "Zero-downtime rollout".

## Admin

```bash
curl http://127.0.0.1:30120/healthz # body "ok\n" — unconditional liveness
curl http://127.0.0.1:30120/readyz  # 200 "ok\n" while serving, 503 from the first drain instant
curl http://127.0.0.1:30120/status  # requests/failovers per listener, global rotations, safe pool state
RPGW_ADMIN_ADDR=127.0.0.1:30120 ./bin/rpgw healthcheck
./bin/rpgw version
```

`failovers` counts in-band route fallbacks (a listener metric); a listener's
`requests` counts valid proxy requests that reached route selection
(protocol rejects never advance it); `rotations` counts completed manual-route
rotations that observed a changed egress IP.

## Docker

```bash
docker build -t rpgw:dev --build-arg VERSION=0.1.0-dev .
docker run --rm rpgw:dev version
# Copy config.example.yaml to config.yaml and add routes first.
docker compose up -d --build
curl http://127.0.0.1:30120/status
```

`compose.yaml` publishes host 30120/30121/30122/30123 for the admin/mixed/v4/v6
listeners (admin is the status/health API; the proxy listeners are HTTP
forward proxies) on all host interfaces. It bind-mounts `config.yaml` read-only; hot
reload polls content, so in-place host edits apply without restart, while an
atomic replace across the single-file mount stays invisible (see
[`docs/configuration.md`](docs/configuration.md) "Reload behavior"). Compose defaults to bounded `json-file` logs and uses the
binary `healthcheck` subcommand (no shell in the scratch image).

## Layout

- `internal/config` — bootstrap environment, Viper YAML validation, route parsing (auto + manual), rotation settings, routing-block compilation, content-hash change poller
- `internal/pool` — LRU filtering, cooldown/auth state, in-flight work, rotation state, immutable generation snapshots (config + pool + routing policy as one unit)
- `internal/routing` — the compiled domain-routing policy: it resolves one inbound target to its candidate route set and never selects, never reads or writes health
- `internal/proxyserver` — inbound HTTP forward proxy: request parsing, `Proxy-Authorization`, the `x-ecoma-*` control headers (`x-ecoma-proxy-family` route constraint, `x-ecoma-request-id` correlation id), the protocol-agnostic route-selection and relay engine they feed, plus the admin mux
- `internal/socksdial` — the shared SOCKS5 dialer used by the proxy server and the rotation probes; `DialHalf` parks a half-handshake (TCP + greeting + auth) the warm pool completes later with `CompleteConnect`
- `internal/warmpool` — background pool of half-established upstream connections, bounded per route and process-wide, epoch-invalidated by rotation, borrowed on the serving path
- `internal/rotation` — manual-route rotation engine: scheduling under the concurrency cap, drain, probes, rotate calls, verification, backoff
- `cmd/rotation-proxy-gateway` — lifecycle, signals, watcher, admin endpoints
- `docs` — the behavior-contract pages (configuration, rotation, warm pool, failure and route health, inbound HTTP forward proxy, observability, deployment)
- `e2e` — black-box tests and benchmarks driving the real binary as a
  subprocess with SOCKS5/HTTP/trace/rotate-API simulators; `go test ./e2e/`
  (skip with `-short`), baselines in `e2e/BENCH.md`
