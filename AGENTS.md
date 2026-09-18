# rotation-proxy-gateway

Go HTTP forward proxy that routes plain absolute-URI requests and inbound
`CONNECT` tunnels through a health-aware pool of **SOCKS5-only** routes. It
runs three inbound proxy listener views over one shared route-health pool:

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
content-hash poller (`internal/config.Poller`). Style rules: use
`math/rand/v2` (never `math/rand`) and `for range n` loops.

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

| Env | Default | Meaning |
|---|---:|---|
| `CONFIG_FILE` | `config.yaml` | Runtime YAML path |
| `ADMIN_ADDR` | `0.0.0.0:30120` | Admin listener; network policy controls exposure |
| `MIXED_LISTEN_ADDR` | `:30121` | Mixed v4/v6 egress listener |
| `V4_LISTEN_ADDR` | `:30122` | IPv4-egress-only listener |
| `V6_LISTEN_ADDR` | `:30123` | IPv6-egress-only listener |
| `SHUTDOWN_GRACE` | `55s` | Total shared drain budget for graceful shutdown |

Empty proxy listener addresses disable their listener, but at least one proxy
listener must remain enabled. All enabled addresses must be valid host:port
addresses and must not overlap (including wildcard binds on the same port).

Runtime settings and active routes live only in `config.yaml`:
`log-level`, `max-retries`, `cooldown`, `dial-timeout`, global TLS/body
settings, `proxies.auto`, `proxies.manual`, and the `rotation` block. The
process polls the file each second and
reloads when its content hash changes, so in-place edits and atomic
replacements both reload under any mount style. A failed parse/validation
leaves the last-known-good pool and runtime settings serving. Do not add a
manual reload fallback (for example SIGHUP), and do not reintroduce
event-based watching: neither can fix the one blind spot, a rename-over a
single-file bind mount (the mount pins the old inode) — see README
"Reload behavior".
Per-route `target-tls-insecure` and
`max-body-buffer` are not allowed: both are global settings.

`kind: v4|v6` means the provider-backed **public egress IP family**. It does
not classify the SOCKS endpoint transport address and does not restrict target
address families. Do not infer kind by resolving a hostname.

## Behavior notes

Read [`README.md`](README.md) before changing failure classification.

- The pool selects the usable **eligible** route least recently used by pick
  sequence. It is a single shared pool: cooldown/auth state is visible through
  both dedicated and mixed listeners.
- Endpoint DNS/TCP failure is `proxy_connect`: cooldown then a distinct
  eligible fallback. SOCKS auth failure is `auth_route`, blocks the route, and
  may fall back, but never creates dial cooldown. A SOCKS handshake failure
  before the tunnel exists—greeting, method/auth framing, CONNECT framing or
  reply, bound-address reads—is `socks_connect`: the same cooldown-and-fallback
  treatment as `proxy_connect`, because no client bytes have crossed the tunnel
  yet. Local request errors and post-tunnel errors are `setup`; exhausting
  eligible routes is `no_route`.
- Errors after the SOCKS tunnel is established—including target TLS, write/
  read, malformed response, cancellation, and broken tunnel—and local request
  errors (bad scheme, oversized configured credentials, invalid target) do not
  alter health and are not retried.
- Valid target responses, including `407`, `408`, `429`, and `5xx`, are
  forwarded once. A target `407` is ordinary data, not SOCKS authentication.
- The kind filter applies to ordinary LRU selection and all-cooling fallback;
  v4/v6 listeners must never leak into the other kind. A pool containing only
  one family is valid: mixed uses it, while a dedicated listener without a
  matching route remains live and returns the ordinary no-route `502`.
- Hop-by-hop headers and `Proxy-Authorization` are removed in both directions.
  Declared request trailers retain chunked framing. Userinfo must never appear
  in logs, `/status`, errors, or responses.
- Logs contain process-local `request_id` and `listener`; `target` and
  `upstream` are host-only. `debug` shows flow, `info` terminal successes, and
  `warn` fallback/terminal failures. Established tunnels log a close record
  (lifetime, per-direction byte counts, which side ended first) at `debug`; a
  tunnel broken by an upstream error logs at `warn` and resets the client
  connection. Streamed plain-HTTP responses flush per chunk.
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
  for the whole process, not a window per listener), then force-closes hijacked
  tunnels. Keep the surrounding orchestrator's kill timer above the budget
  (`stop_grace_period: 60s` in compose).

## Admin

```bash
curl http://127.0.0.1:30120/healthz # body "ok\n"
curl http://127.0.0.1:30120/status  # requests/failovers per listener, global rotations, safe pool state
ADMIN_ADDR=127.0.0.1:30120 ./bin/rpgw healthcheck
./bin/rpgw version
```

`failovers` counts in-band route fallbacks (a listener metric); `rotations`
counts completed manual-route rotations that observed a changed egress IP.

## Docker

```bash
docker build -t rpgw:dev --build-arg VERSION=0.1.0-dev .
docker run --rm rpgw:dev version
# Copy config.example.yaml to config.yaml and add routes first.
docker compose up -d --build
curl http://127.0.0.1:30120/status
```

`compose.yaml` publishes host 30120/30121/30122/30123 for the admin/mixed/v4/v6
listeners on all host interfaces. It bind-mounts `config.yaml` read-only; hot
reload polls content, so in-place host edits apply without restart, while an
atomic replace across the single-file mount stays invisible (see README
"Reload behavior"). Compose defaults to bounded `json-file` logs and uses the
binary `healthcheck` subcommand (no shell in the scratch image).

## Layout

- `internal/config` — bootstrap environment, Viper YAML validation, route parsing (auto + manual), rotation settings, content-hash change poller
- `internal/pool` — LRU filtering, cooldown/auth state, in-flight work, rotation state, immutable generation snapshots
- `internal/proxyserver` — inbound HTTP/CONNECT forwarding plus the admin mux
- `internal/socksdial` — the shared SOCKS5 dialer used by the forwarder and the rotation probes
- `internal/rotation` — manual-route rotation engine: scheduling under the concurrency cap, drain, probes, rotate calls, verification, backoff
- `cmd/rotation-proxy-gateway` — lifecycle, signals, watcher, admin endpoints
- `e2e` — black-box tests and benchmarks driving the real binary as a
  subprocess with SOCKS5/HTTP/trace/rotate-API simulators; `go test ./e2e/`
  (skip with `-short`), baselines in `e2e/BENCH.md`
