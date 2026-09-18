# proxy-auto-rotate-forwarder

Go HTTP forward proxy that routes plain absolute-URI requests and inbound
`CONNECT` tunnels through a health-aware pool of **SOCKS5-only** routes. It
runs three inbound proxy listener views over one shared route-health pool:

- mixed egress (`30121` by default): v4 and v6 routes
- v4 egress (`30122` by default): `kind: v4` routes only
- v6 egress (`30123` by default): `kind: v6` routes only

The always-on admin listener defaults to `127.0.0.1:30120`. The authoritative
behavior contract is [`README.md`](README.md).

## Build and test

```bash
gofmt -w . && go vet ./... && go test -race ./...
go build -ldflags "-X main.version=0.1.0-dev" -o bin/paf ./cmd/proxy-auto-rotate-forwarder
```

The toolchain pins Go ≥ 1.25; development used Go 1.26.4. Viper is used for
runtime YAML loading and fsnotify-backed watching. Style rules: use
`math/rand/v2` (never `math/rand`) and `for range n` loops.

## Configure and run

Copy [`config.example.yaml`](config.example.yaml) to Git-ignored `config.yaml`,
then replace the placeholder `proxies.auto` SOCKS routes. The file may contain
credentials; never log, commit, or bake it into an image.

```bash
CONFIG_FILE=config.yaml \
ADMIN_ADDR=127.0.0.1:30120 \
MIXED_LISTEN_ADDR=:30121 \
V4_LISTEN_ADDR=:30122 \
V6_LISTEN_ADDR=:30123 \
./bin/paf
```

Environment variables are bootstrap-only and require restart:

| Env | Default | Meaning |
|---|---:|---|
| `CONFIG_FILE` | `config.yaml` | Runtime YAML path |
| `ADMIN_ADDR` | `127.0.0.1:30120` | Private admin listener |
| `MIXED_LISTEN_ADDR` | `:30121` | Mixed v4/v6 egress listener |
| `V4_LISTEN_ADDR` | `:30122` | IPv4-egress-only listener |
| `V6_LISTEN_ADDR` | `:30123` | IPv6-egress-only listener |

Empty proxy listener addresses disable their listener, but at least one proxy
listener must remain enabled. All enabled addresses must be valid host:port
addresses and must not overlap (including wildcard binds on the same port).

Runtime settings and active static routes live only in `config.yaml`:
`log-level`, `max-retries`, `cooldown`, `dial-timeout`, global TLS/body
settings, and `proxies.auto`. Viper watches that file; `SIGHUP` is a manual
fallback. A failed parse/validation leaves the last-known-good pool and runtime
settings serving. `proxies.manual` is accepted but opaque and ignored until the
future API-rotation phase. Per-route `target-tls-insecure` and
`max-body-buffer` are not allowed: both are global settings.

`kind: v4|v6` means the provider-backed **public egress IP family**. It does
not classify the SOCKS endpoint transport address and does not restrict target
address families. Do not infer kind by resolving a hostname.

## Behavior notes

Read [`README.md`](README.md) before changing failure classification.

- The pool selects the usable **eligible** route least recently used by pick
  sequence. It is a single shared pool: cooldown/auth state is visible through
  both dedicated and mixed listeners.
- Endpoint DNS/TCP failure is `proxy_connect_error`: cooldown then a distinct
  eligible fallback. SOCKS auth failure blocks the route and may fall back, but
  never creates dial cooldown.
- Errors after endpoint TCP dial succeeds—including SOCKS target-connect,
  target TLS, write/read, malformed response, cancellation, and broken tunnel—
  do not alter health and are not retried.
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
  `warn` fallback/terminal failures.
- Reload preserves runtime pool state only for unchanged URL+kind. Changed URL
  userinfo or kind creates a new route state.
- Shutdown order: drain all proxy listeners (10s) → admin → hijacked tunnels.

## Admin

```bash
curl http://127.0.0.1:30120/healthz # body "ok"
curl http://127.0.0.1:30120/status  # global + per-listener counters, safe pool state
ADMIN_ADDR=127.0.0.1:30120 ./bin/paf healthcheck
./bin/paf version
```

## Docker

```bash
docker build -t paf:dev --build-arg VERSION=0.1.0-dev .
docker run --rm paf:dev version
# Copy config.example.yaml to config.yaml and add routes first.
docker compose up -d --build
curl http://127.0.0.1:30120/status
```

`compose.yaml` maps host 30121/30122/30123 to mixed/v4/v6 proxy listeners and
maps `127.0.0.1:30120` to admin. It mounts `config.yaml` read-only, defaults to
bounded `json-file` logs, and uses the binary `healthcheck` subcommand (no shell
in the scratch image).

## Layout

- `internal/config` — bootstrap environment, Viper YAML validation, route parsing
- `internal/pool` — LRU filtering, cooldown/auth state, live route reload
- `internal/proxyserver` — SOCKS5 dialing plus inbound HTTP/CONNECT forwarding
- `cmd/proxy-auto-rotate-forwarder` — lifecycle, signals, watcher, admin endpoints
