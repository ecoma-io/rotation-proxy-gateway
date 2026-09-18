# rotation-proxy-gateway

`rotation-proxy-gateway` is a Go HTTP forward proxy that accepts stable
inbound HTTP proxy endpoints and routes traffic through a health-aware pool of
**SOCKS5-only** upstream routes. It supports ordinary absolute-form HTTP
requests and inbound `CONNECT` tunnels.

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
cp config.example.yaml config/config.yaml # add real static SOCKS routes
MIXED_LISTEN_ADDR=:30121 \
V4_LISTEN_ADDR=:30122 \
V6_LISTEN_ADDR=:30123 \
ADMIN_ADDR=0.0.0.0:30120 \
go run ./cmd/rotation-proxy-gateway

curl -x http://127.0.0.1:30121 https://example.com/
curl http://127.0.0.1:30120/status
```

`config/config.yaml` normally contains upstream credentials and is ignored by Git and
Docker build contexts. Do not commit it or bake it into an image.

## Configuration

### Bootstrap settings -- environment, restart required

These values create sockets or choose the watched file and are read only when
the process starts. Empty proxy listener addresses disable their listener, but
at least one proxy listener must remain enabled.

| Variable | Default | Meaning |
|---|---:|---|
| `CONFIG_FILE` | `config.yaml` | Runtime YAML file path |
| `ADMIN_ADDR` | `0.0.0.0:30120` | Always-on admin listener; network policy controls exposure |
| `MIXED_LISTEN_ADDR` | `:30121` | Mixed v4/v6 egress listener |
| `V4_LISTEN_ADDR` | `:30122` | v4-egress-only listener |
| `V6_LISTEN_ADDR` | `:30123` | v6-egress-only listener |

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
global:
  target-tls-insecure: false
  max-body-buffer: 67108864
proxies:
  auto:
    - proxy: socks5://username:password@provider.example:1080
      kind: v4
    - proxy: socks5://username:password@[2001:db8::1]:1080
      kind: v6
  manual: []
```

`proxies.auto` is the phase-1 source of static routes. The accepted `proxy`
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

`global.target-tls-insecure` and `global.max-body-buffer` are global settings;
per-route overrides are rejected. `target-tls-insecure` defaults to `false` and
should not be enabled for untrusted targets.

`proxies.manual` is deliberately accepted but **ignored** in phase 1. No API
request is made, no manual route is selected, and its contents are never exposed
by logs or status. API-driven rotation is a future phase.

### Reload behavior

Viper watches the directory containing the runtime YAML file, so both in-place
edits and atomic replacements (editor save, `mv`, symlink swap) are detected and
applied after a short debounce.

In Docker, mount the config's **directory**, not the single file: a single-file
bind mount pins the file's inode, so replacing the file on the host is invisible
inside the container and no reload can observe it. With a directory bind mount,
host-side updates reach the watcher and hot-reload works.

```yaml
# compose.yaml
volumes:
  - ./config:/app/config:ro
environment:
  CONFIG_FILE: /app/config/config.yaml
```

Each reload parses and validates a complete new configuration before changing
any serving state. A syntax error, partial write, invalid route, or invalid
runtime setting logs a sanitized warning and retains the last-known-good config
and pool. Validated configuration and its reconfigured pool snapshot publish as
one atomic generation: every request and CONNECT operation loads that generation
once, while in-flight operations finish on their original snapshot.

#### Measured watcher behavior (Docker bind mounts)

Verified against Viper 1.21 + fsnotify with the production binary in an Alpine
container (2026-09): Viper watches the config file's **directory**, so any
create/rename inside that directory is observed. The results that shaped the
mount guidance:

| Host update | Directory bind mount | Single-file bind mount |
|---|---|---|
| Atomic rename-over (editor save, `mv`) | reload fires | invisible (mount pins the old inode) |
| In-place write (`echo > file`) | reload fires | no inotify event reaches the container |

The single-file in-place case fails because inotify parent-directory event
propagation follows the directory hierarchy of the *writing* side (the host
path), not the container's mountpoint. There is no signal-based workaround:
a reload triggered by signal re-reads the same pinned inode, and after a
rename-over the pinned inode is the old file. Directory mounting is the only
configuration that makes hot reload fully reliable, so the process deliberately
has no manual reload fallback.

One startup nuance: the watcher installs after the listeners start. An update
landing in that window is not seen as an event, but the next watch event (or a
restart, which reads the file at boot) converges the state.

The following settings apply to new client operations without restart:

- `log-level`
- `max-retries`
- `cooldown.base` and `cooldown.max` (new dial failures only)
- `dial-timeout`
- `global.target-tls-insecure`
- `global.max-body-buffer`
- `proxies.auto`

Unchanged URL+kind routes preserve their LRU, cooldown, authentication-block,
and counter state. Changing userinfo or kind creates a fresh route state.

## Failure and route-health contract

### Definitions

- **`proxy_connect`**: DNS resolution or TCP dialing of the configured SOCKS
  endpoint fails.
- **`auth_route`**: a connected SOCKS endpoint cannot authenticate the
  configured route.
- **`setup`**: every other error after the endpoint TCP dial succeeds, including
  SOCKS framing/target replies, TLS, writes, reads, malformed responses,
  cancellation, and established-tunnel failures.
- **`no_route`**: no eligible untried route remains.

| Outcome | Pool handling | Request handling |
|---|---|---|
| SOCKS endpoint DNS/TCP dial fails | Record `proxy_connect`, exponential cooldown | Retry a distinct eligible route; synthetic `502` only when none remains |
| SOCKS endpoint cannot authenticate | Auth-block the route; no dial cooldown | Retry a distinct eligible route; synthetic `502` only when none remains |
| SOCKS setup/target error after TCP dial | No health mutation and no retry | Sanitized `502` |
| Target TLS, HTTP write/read, malformed response | No health mutation and no retry | `502` unless client cancelled |
| Valid target HTTP response, including `407`, `408`, `429`, `5xx` | Record success; no rotation/cooldown | Forward once |
| Client cancellation/disconnect | No health mutation and no retry | End operation |
| Established tunnel breaks | No health mutation | Close tunnel |

The pool is least-recently-used by pick sequence (true round-robin). A request
never tries the same route twice. Cooling routes are skipped when a usable
eligible route exists; when all eligible non-auth-blocked routes cool down, the
one recovering soonest is tried. Authentication blocks remain until the route
identity changes on reload.

A target HTTP `407` is ordinary target response data. It is not SOCKS
authentication data, does not rotate, and does not create cooldown.

## HTTP and CONNECT behavior

Clients send absolute-form HTTP requests. The forwarder opens one SOCKS5
`CONNECT` tunnel to the target for each ordinary request, writes an origin-form
request, and performs target TLS inside that tunnel for HTTPS. It removes
hop-by-hop headers, including `Connection`-listed headers and
`Proxy-Authorization`, in both directions.

Bodies up to `global.max-body-buffer` are replayable after an endpoint dial or
SOCKS authentication fallback. Known-larger bodies stream immediately;
unknown-length bodies are probed up to the limit. Once streamed bytes have been
consumed, the body cannot safely be retried. Declared request trailers retain
chunked framing.

For CONNECT, the service returns `200 Connection Established` only after the
SOCKS target CONNECT succeeds, then relays bytes bidirectionally. Failures after
that point do not alter route health.

## Admin and observability

```bash
curl http://127.0.0.1:30120/healthz # body: ok\n
curl http://127.0.0.1:30120/status
ADMIN_ADDR=127.0.0.1:30120 ./bin/rpgw healthcheck
./bin/rpgw version
```

`/status` keeps `version`, `uptime`, global `requests`, global `rotations`, and
redacted `pool` state. It additionally reports safe per-listener counters and
each route's `kind`. Route identities are always `host:port`, never userinfo.

Each request has a process-local `request_id`. Logs additionally include
`listener=mixed|v4|v6`, host-only `target` and `upstream`, retry attempts,
error category, and cooldown only for endpoint dial errors. They never log full
URLs, headers, bodies, userinfo, or the ignored manual API configuration.

## Docker

```bash
cp config.example.yaml config/config.yaml
# edit config/config.yaml with real routes
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
uses Viper for YAML loading and file watching.

```bash
gofmt -w .
go vet ./...
go test -race ./...
go build -ldflags "-X main.version=0.1.0-dev" -o bin/rpgw ./cmd/rotation-proxy-gateway
```

Graceful shutdown gives each enabled proxy listener its own ten-second drain
window, then gives the admin listener a separate ten-second window, and finally
closes hijacked CONNECT tunnels that `http.Server.Shutdown` does not track.
