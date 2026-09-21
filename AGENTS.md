# rotation-proxy-gateway

Go SOCKS5 proxy (RFC 1928 inbound) that routes `CONNECT` requests through a
health-aware pool of **SOCKS5-only** outbound routes. It runs three inbound
SOCKS5 proxy listener views over one shared route-health pool:

- mixed egress (`30121` by default): v4 and v6 routes
- v4 egress (`30122` by default): `kind: v4` routes only
- v6 egress (`30123` by default): `kind: v6` routes only

The always-on admin listener defaults to `0.0.0.0:30120`; operators control
network exposure through Docker port publishing, network policy, and firewalls.
The authoritative behavior contract is [`README.md`](README.md).

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
CONFIG_FILE=config.yaml \
ADMIN_ADDR=0.0.0.0:30120 \
MIXED_LISTEN_ADDR=:30121 \
V4_LISTEN_ADDR=:30122 \
V6_LISTEN_ADDR=:30123 \
./bin/rpgw
```

Environment variables are bootstrap-only and require restart:

| Env                 |         Default | Meaning                                                 |
| ------------------- | --------------: | ------------------------------------------------------- |
| `CONFIG_FILE`       |   `config.yaml` | Runtime YAML path                                       |
| `ADMIN_ADDR`        | `0.0.0.0:30120` | Admin (HTTP) listener; network policy controls exposure |
| `MIXED_LISTEN_ADDR` |        `:30121` | Mixed v4/v6 egress SOCKS5 listener                      |
| `V4_LISTEN_ADDR`    |        `:30122` | IPv4-egress-only SOCKS5 listener                        |
| `V6_LISTEN_ADDR`    |        `:30123` | IPv6-egress-only SOCKS5 listener                        |
| `SHUTDOWN_GRACE`    |           `55s` | Total shared drain budget for graceful shutdown         |

Empty proxy listener addresses disable their listener, but at least one proxy
listener must remain enabled. All enabled addresses must be valid host:port
addresses and must not overlap (including wildcard binds on the same port).

Runtime settings and active routes live only in `config.yaml`:
`log-level`, `max-retries`, `cooldown`, `dial-timeout`, `proxies.auto`,
`proxies.manual`, the `rotation` block, and the optional
`warm-pool` block. The process polls the file each
second and reloads when its content hash changes, so in-place edits and atomic
replacements both reload under any mount style. A failed parse/validation
leaves the last-known-good pool and runtime settings serving. Do not add a
manual reload fallback (for example SIGHUP), and do not reintroduce
event-based watching: neither can fix the one blind spot, a rename-over a
single-file bind mount (the mount pins the old inode) — see README
"Reload behavior".
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

Read [`README.md`](README.md) before changing failure classification.

- The pool selects the usable **eligible** route with the smallest recency
  pass, first-seen order breaking ties — true round-robin over the eligible
  set. It is a single shared pool: cooldown, pair-scoped target-cooldown, and
  auth state are visible through both dedicated and mixed listeners.
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
  other targets. Local SOCKS request errors and post-tunnel errors are
  `setup`; exhausting eligible routes is `no_route`.
- Errors after the SOCKS tunnel is established—including target reads/writes,
  malformed target content, cancellation, and broken tunnel—and local inbound
  request errors (malformed target encoding, oversized configured
  credentials, invalid target) do not alter health and are not retried.
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
  matching route remains live and replies `05 01` (general failure) on
  `no_route`.
- Inbound protocol is SOCKS5 (RFC 1928). Only NO AUTHENTICATION REQUIRED is
  accepted; a client offering no `0x00` method gets `05 ff`. Only `CONNECT` is
  supported; `BIND` and `UDP ASSOCIATE` get `05 07`. Success replies `05 00`
  with a zero BND.ADDR/BND.PORT that clients must ignore. Malformed or
  truncated frames close without a reply. Domain targets are forwarded as
  names: DNS happens at the outbound route (socks5h), never in the gateway. A
  30s read deadline bounds the greeting/request exchange and is cleared once
  the tunnel is established; established tunnels have no timeouts. One client
  connection carries one tunnel; keep-alive/reuse is the client's choice.
  Userinfo must never appear in logs, `/status`, errors, or responses.
- Logs contain process-local `request_id` and `listener`; `target` and
  `upstream` are host-only. `debug` shows flow, `info` terminal successes, and
  `warn` fallback/terminal failures. Established tunnels log a close record
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
  quiesce) is unrelated to `SHUTDOWN_GRACE` (whole-process listener drain).
- Shutdown cancels the rotation engine first — procedures abort at their next
  checkpoint and never extend the budget — then drains all proxy listeners and
  admin against one shared `SHUTDOWN_GRACE` budget (default 55s; one deadline
  for the whole process, not a window per listener), then force-closes
  established tunnels. Keep the surrounding orchestrator's kill timer above the
  budget (`stop_grace_period: 60s` in compose).

## Admin

```bash
curl http://127.0.0.1:30120/healthz # body "ok\n"
curl http://127.0.0.1:30120/status  # requests/failovers per listener, global rotations, safe pool state
ADMIN_ADDR=127.0.0.1:30120 ./bin/rpgw healthcheck
./bin/rpgw version
```

`failovers` counts in-band route fallbacks (a listener metric); a listener's
`requests` counts valid `CONNECT` commands that reached route selection
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
listeners (admin is HTTP; the proxy listeners are SOCKS5) on all host
interfaces. It bind-mounts `config.yaml` read-only; hot
reload polls content, so in-place host edits apply without restart, while an
atomic replace across the single-file mount stays invisible (see README
"Reload behavior"). Compose defaults to bounded `json-file` logs and uses the
binary `healthcheck` subcommand (no shell in the scratch image).

## Layout

- `internal/config` — bootstrap environment, Viper YAML validation, route parsing (auto + manual), rotation settings, content-hash change poller
- `internal/pool` — LRU filtering, cooldown/auth state, in-flight work, rotation state, immutable generation snapshots
- `internal/proxyserver` — inbound SOCKS5 (RFC 1928) server plus the admin mux
- `internal/socksdial` — the shared SOCKS5 dialer used by the proxy server and the rotation probes; `DialHalf` parks a half-handshake (TCP + greeting + auth) the warm pool completes later with `CompleteConnect`
- `internal/warmpool` — background pool of half-established upstream connections, bounded per route and process-wide, epoch-invalidated by rotation, borrowed on the serving path
- `internal/rotation` — manual-route rotation engine: scheduling under the concurrency cap, drain, probes, rotate calls, verification, backoff
- `cmd/rotation-proxy-gateway` — lifecycle, signals, watcher, admin endpoints
- `e2e` — black-box tests and benchmarks driving the real binary as a
  subprocess with SOCKS5/HTTP/trace/rotate-API simulators; `go test ./e2e/`
  (skip with `-short`), baselines in `e2e/BENCH.md`
