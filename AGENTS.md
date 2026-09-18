# proxy-auto-rotate-forwarder

Zero-dependency Go HTTP forward proxy that rotates across a pool of upstream
proxies: plain absolute-URI requests and CONNECT tunneling on one listener,
auto-rotating on failure with exponential cooldown, an always-on admin
listener (health + status), and SIGHUP pool reload. Built for the private
homelab deployment layer described in the workspace `CLAUDE.md`.

## Build and test

```bash
gofmt -w . && go vet ./... && go test -race ./...
go build -ldflags "-X main.version=0.1.0-dev" -o bin/paf ./cmd/proxy-auto-rotate-forwarder
```

The toolchain pins Go ≥ 1.25 (`go.mod`); development used Go 1.26.4. Style
rules for this repo: `math/rand/v2` (never `math/rand`), `for range n` loops.

## Run

`configs/proxies.txt` (ignored by git) holds the pool, one URL per line,
`#` comments allowed. Supported schemes: `http`, `https` (TLS to the proxy
itself), `socks5` (RFC 1928/1929 auth). Userinfo in the URL is used for
upstream authentication and is never echoed in logs or `/status`.

```bash
LISTEN_ADDR=:8080 \
ADMIN_ADDR=127.0.0.1:8081 \
PROXIES_FILE=configs/proxies.txt \
./bin/paf
```

An optional `.env` in the working directory is read without overriding the
real environment. See `.env.example` for every knob:

|Env|Default|Meaning|
|---|---|---|
|`LISTEN_ADDR`|`:8080`|proxy listener (HTTP + CONNECT)|
|`ADMIN_ADDR`|`127.0.0.1:8081`|admin listener (always on; must differ from `LISTEN_ADDR`)|
|`PROXIES_FILE`|`configs/proxies.txt`|pool file|
|`MAX_RETRIES`|`3`|attempts across **distinct** proxies|
|`COOLDOWN_BASE`|`30s`|first-failure cooldown; doubles per consecutive failure, capped|
|`COOLDOWN_MAX`|`10m`|cooldown ceiling|
|`CONNECT_TIMEOUT`|`10s`|dial + upstream handshake timeout|
|`UPSTREAM_TLS_INSECURE`|`false`|skip upstream proxy cert verification|
|`MAX_BODY_BUFFER`|64MiB|request bodies replayed for rotation up to this size; larger bodies stream with no retry|
|`LOG_LEVEL`|`info`|`debug`/`info`/`warn`/`error`|

## Behavior notes

- The pool always selects the available proxy least recently used by pick sequence (true round-robin); it has no rotation-mode setting.
- Retry only on connection failure or target status 408/429/5xx. If every
  attempt hit a retryable status, the **last** response is passed through
  (a real 429 beats a synthetic 502); with no response at all the client gets
  502. 403/404 etc. are forwarded as-is without rotation.
- Hop-by-hop headers (incl. Connection-listed tokens and
  `Proxy-Authorization` on responses) are stripped in both directions.
- `SIGHUP` re-reads the pool file; on parse error the old pool keeps serving.
- Shutdown order: graceful proxy drain (10s) → admin drain → close hijacked
  tunnels (Go's `Shutdown` does not track those).

## Admin

```bash
curl http://127.0.0.1:8081/healthz   # body "ok"
curl http://127.0.0.1:8081/status   # JSON: version, uptime, requests, rotations, pool (per-proxy state)
ADMIN_ADDR=127.0.0.1:8081 ./bin/paf healthcheck # exit 0 = healthy (Docker HEALTHCHECK uses it)
./bin/paf version
```

## Docker
```bash
docker build -t paf:dev --build-arg VERSION=0.1.0-dev .
docker run --rm paf:dev version
# or full stack (mounts configs/proxies.txt read-only):
docker compose up -d --build && curl http://127.0.0.1:8081/status
```

`compose.yaml` maps host 8080 → proxy and 127.0.0.1:8081 → admin
(localhost-only); the pool file is mounted `:ro`, and the container
healthcheck calls the binary's own `healthcheck` subcommand (no shell in
the scratch image).

`Dockerfile` builds a static binary into a `scratch` image plus the CA
bundle; `HEALTHCHECK` works because `healthcheck` is a subcommand of the
entrypoint binary itself (no shell in the image).

## Layout

- `internal/config` — env + `.env` loading, pool file parser
- `internal/pool` — fixed LRU round-robin rotation, failure cooldowns, live `Reload`
- `internal/proxyserver` — upstream dialers (HTTP CONNECT, SOCKS5) and the
  forward proxy handler
- `cmd/proxy-auto-rotate-forwarder` — entrypoint, signals, admin endpoints
