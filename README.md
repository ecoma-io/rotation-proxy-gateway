# proxy-auto-rotate-forwarder

`proxy-auto-rotate-forwarder` is a zero-dependency Go HTTP forward proxy. It
accepts one stable **inbound HTTP proxy** endpoint for clients and routes every
outbound connection through a pool of **SOCKS5** proxies.

It supports ordinary absolute-form HTTP requests and inbound `CONNECT` tunnels
on one listener. Its health model is deliberately narrow: it manages
reachability and authentication of configured SOCKS endpoints, not the
availability or correctness of destination servers.

> **Status:** This document is the normative behavior contract. The
> implementation and tests must conform to it. In particular, never infer SOCKS
> route health from a destination HTTP status.

## Quick start

```bash
cp proxies.example.txt proxies.txt # edit: your SOCKS5 routes
LISTEN_ADDR=:8080 ADMIN_ADDR=127.0.0.1:8081 \
  go run ./cmd/proxy-auto-rotate-forwarder

curl -x http://127.0.0.1:8080 https://example.com/
curl http://127.0.0.1:8081/status
```

## Architecture

```text
client
  |
  | absolute-form HTTP request or CONNECT target:port
  v
proxy-auto-rotate-forwarder
  |                 \
  |                  \-- admin listener: health and pool status
  v
selected SOCKS5 endpoint
  |
  | SOCKS5 CONNECT
  v
requested destination
```

The public listener defaults to `:8080`; the admin listener defaults to
`127.0.0.1:8081`. Keep the admin listener private: it exposes route health and
operational counters.

## Upstream SOCKS5 pool

`PROXIES_FILE` defaults to root-level `proxies.txt`. It contains one SOCKS5
route per line; blank lines and lines beginning with `#` are ignored. Copy the
tracked `proxies.example.txt` to create the Git-ignored live file.

Supported formats are:

```text
socks5://host:port
socks5://user:pass@host:port
host:port:user:pass
user:pass@host:port
```

The two bare forms default to SOCKS5. Explicit `http://` and `https://` entries
are rejected; outbound HTTP and HTTPS proxy protocols are not supported.

URL userinfo is used only for SOCKS authentication. Credentials are never shown
in logs or `/status`; route identities are reported as `host:port` only.

The pool uses stable least-recently-used selection by pick sequence (true
round-robin). A request never tries the same route twice. A route in dial
cooldown is skipped when another usable route is available; if all usable routes
are cooling down, the route recovering soonest is used rather than failing
immediately. An authentication-blocked route is not usable.

Sending `SIGHUP` reloads the pool file. A parsing error leaves the current pool
untouched. An unchanged URL preserves its runtime state; changing a URL,
including its userinfo, creates a new route with clean state.

## Failure and route-health contract

### Definitions

- **`proxy_connect_error`**: failure of DNS resolution or TCP dialing to the
  configured SOCKS endpoint. This includes connection refused, dial timeout,
  and host or network unreachable errors returned while dialing that endpoint.
- **`auth_route_error`**: a connected SOCKS endpoint cannot authenticate the
  configured route. This includes an endpoint requiring credentials when none
  are configured, accepting none of the offered methods, or rejecting RFC 1929
  username/password credentials.
- **Post-dial setup/target outcome**: every other error after the TCP dial has
  succeeded, including SOCKS framing errors, SOCKS target `CONNECT` replies,
  target TLS failures, request write/read failures, malformed target responses,
  client cancellation, and established-tunnel failures.

Only `proxy_connect_error` changes dial health and creates exponential cooldown.
`auth_route_error` is recorded separately and blocks that route without creating
dial cooldown. Neither category asserts that a destination server is healthy or
unhealthy.

### Outcome matrix

| Outcome | Pool handling | Request handling |
|---|---|---|
| SOCKS endpoint DNS/TCP dial fails | Record `proxy_connect_error`, increment dial-failure count, and apply exponential cooldown | Retry a distinct route; return synthetic `502` only when no usable route remains |
| SOCKS endpoint cannot authenticate the route | Record `auth_route_error`, block the route, and do not change dial cooldown | Retry a distinct route; return synthetic `502` only when no usable route remains |
| SOCKS protocol/setup error after endpoint TCP dial, including a non-success target `CONNECT` reply | No failure-health mutation and no retry | Sanitized synthetic `502` |
| Target TLS, HTTP write/read, or malformed-response error after SOCKS setup succeeds | No failure-health mutation and no retry | Synthetic `502` unless the client has cancelled |
| Valid target HTTP response, including `407`, `408`, `429`, and `5xx` | Record normal route success; no failure/cooldown mutation and no retry | Forward the response once |
| Client cancels/disconnects | No route-health mutation and no retry | End the request/connection |
| Tunnel breaks after `200 Connection Established` | No route-health mutation and no retry | Close the tunnel |

An authentication-blocked route stays blocked until a reload changes its exact
pool entry. This is intentional: unchanged credentials are not expected to
recover spontaneously. Changed credentials create a new route that can be tried
again.

### HTTP `407` is ordinary target data

There is no outbound HTTP proxy exchange in this project, so there is no
outbound HTTP-proxy `407` attribution problem. SOCKS authentication errors are
identified from the SOCKS protocol before a target HTTP request exists.

A `407 Proxy Authentication Required` received as a valid HTTP response from a
target or intermediary is ordinary response data. It is forwarded once, has no
SOCKS authentication meaning, does not rotate the pool, and does not create a
cooldown.

## HTTP and CONNECT behavior

### Ordinary HTTP requests

Clients send absolute-form requests, for example:

```http
GET http://example.com/path HTTP/1.1
Host: example.com
```

The forwarder establishes a SOCKS5 `CONNECT` tunnel to the request target, then
writes an origin-form HTTP request through that tunnel. For an `https://` target,
it performs target TLS inside the SOCKS tunnel before writing the request.

Every successful target response is forwarded once. A `407`, `408`, `429`, or
`5xx` response does not cause rotation or dial cooldown.

Request bodies up to `MAX_BODY_BUFFER` are replayable for an endpoint dial or
SOCKS authentication fallback. Larger bodies stream once; they cannot safely be
retried after the forwarder has begun consuming them.

Each ordinary request uses its own SOCKS tunnel rather than a reused HTTP
transport connection. This makes the boundary between endpoint TCP-dial errors
and all later errors explicit and reliable.

### `CONNECT` tunnels

For an inbound request such as:

```http
CONNECT api.example.com:443 HTTP/1.1
Host: api.example.com:443
```

The forwarder sends a SOCKS5 `CONNECT` command to the selected route and returns
`200 Connection Established` only after the SOCKS endpoint reports success.
After that point, bytes flow verbatim in both directions. A target refusal
reported by SOCKS becomes a sanitized `502`; it is not evidence that the SOCKS
endpoint itself is unreachable. A post-establishment reset or destination
failure never affects route health.

## Headers and privacy

Hop-by-hop headers are removed in both directions, including headers named by
`Connection`. `Proxy-Authorization` is never sent onward to destinations and is
never exposed in responses or logs.

## Configuration

Configuration is read from the process environment. Docker deployment values
and their operational comments live directly in `compose.yaml`.

| Variable | Default | Meaning |
|---|---:|---|
| `LISTEN_ADDR` | `:8080` | Inbound proxy listener for HTTP and `CONNECT` |
| `ADMIN_ADDR` | `127.0.0.1:8081` | Always-on admin listener; must differ from `LISTEN_ADDR` |
| `PROXIES_FILE` | `proxies.txt` | SOCKS5 pool file |
| `MAX_RETRIES` | `3` | Maximum distinct routes attempted after endpoint dial or SOCKS authentication failure |
| `COOLDOWN_BASE` | `15s` | First endpoint TCP-dial cooldown; doubles for consecutive dial failures |
| `COOLDOWN_MAX` | `10m` | Maximum endpoint TCP-dial cooldown |
| `CONNECT_TIMEOUT` | `10s` | Timeout for SOCKS endpoint dial and SOCKS setup |
| `TARGET_TLS_INSECURE` | `false` | Skip certificate verification for HTTPS targets reached through SOCKS; avoid in production |
| `MAX_BODY_BUFFER` | `64MiB` | Maximum request body buffered for dial/auth fallback replay |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error` |

## Admin and observability

```bash
curl http://127.0.0.1:8081/healthz # body: ok
curl http://127.0.0.1:8081/status  # version, uptime, requests, rotations, pool state
ADMIN_ADDR=127.0.0.1:8081 ./bin/paf healthcheck
./bin/paf version
```

`/status` reports redacted route identities and distinguishes TCP dial failures
from SOCKS authentication-route failures. A dial failure records its cooldown
and last safe error. An authentication-route failure is reported separately and
never extends dial cooldown. The `rotations` counter counts route changes, not a
proxy-health verdict by itself.

## Operations

Graceful shutdown proceeds in this order:

1. drain normal proxy requests for up to 10 seconds;
2. drain the admin listener;
3. close hijacked `CONNECT` tunnels, which Go's `http.Server.Shutdown` does not
   track automatically.

## Docker

```bash
docker build -t paf:dev --build-arg VERSION=0.1.0-dev .
docker run --rm paf:dev version

# Full stack. The pool file is mounted read-only.
docker compose up -d --build
curl http://127.0.0.1:8081/status
```

The Docker image is a static binary in `scratch` plus the CA bundle needed to
verify HTTPS targets. The container healthcheck invokes the binary's
`healthcheck` subcommand directly; there is no shell in the runtime image.
`compose.yaml` maps the proxy on host port `8080` and binds the admin port to
`127.0.0.1:8081` only.

## Non-goals

This project does not:

- support HTTP or HTTPS upstream proxy routes;
- determine whether an origin service is healthy;
- treat arbitrary HTTP `4xx`/`5xx` responses as proof that a SOCKS endpoint is
  unhealthy;
- retry destination or application failures across egress routes;
- provide weighted routing, domain policy routing, geo routing, or a remote
  control plane;
- intercept or decrypt inbound `CONNECT` tunnel traffic.

## Build and verification

Go 1.25 or newer is required.

```bash
gofmt -w .
go vet ./...
go test -race ./...
go build -ldflags "-X main.version=0.1.0-dev" -o bin/paf ./cmd/proxy-auto-rotate-forwarder
```

The test suite covers endpoint dial retry/cooldown, SOCKS authentication state,
target `407`/`408`/`429`/`5xx` pass-through without cooldown, SOCKS target
failure without cooldown, post-dial setup failures without retry, request-body
replay after a genuine endpoint dial failure, and `CONNECT` tunneling.

## Source layout

- `internal/config` — environment loading; SOCKS pool-file parsing.
- `internal/pool` — LRU selection, endpoint dial cooldowns, SOCKS
  authentication state, snapshots, and live reload.
- `internal/proxyserver` — SOCKS5 dialing plus inbound HTTP and `CONNECT`
  forwarding.
- `cmd/proxy-auto-rotate-forwarder` — process entrypoint, signals, and admin
  endpoints.
