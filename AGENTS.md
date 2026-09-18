# proxy-auto-rotate-forwarder

Zero-dependency Go HTTP forward proxy that routes plain absolute-URI requests
and inbound `CONNECT` tunnels through a pool of **SOCKS5-only** routes. It has
an always-on admin listener (health + status) and SIGHUP pool reload. The
authoritative behavior contract is [`README.md`](README.md). Built for the
private homelab deployment layer described in the workspace `CLAUDE.md`.

## Build and test

```bash
gofmt -w . && go vet ./... && go test -race ./...
go build -ldflags "-X main.version=0.1.0-dev" -o bin/paf ./cmd/proxy-auto-rotate-forwarder
```

The toolchain pins Go ≥ 1.25 (`go.mod`); development used Go 1.26.4. Style
rules for this repo: `math/rand/v2` (never `math/rand`), `for range n` loops.

## Run

`proxies.txt` at the project root (ignored by git) holds one SOCKS5 route per
line; `#` comments are allowed. Copy `proxies.example.txt` to create it.
Supported forms are:

```text
socks5://host:port
socks5://user:pass@host:port
host:port:user:pass
user:pass@host:port
```

Bare forms default to SOCKS5. Explicit `http://` and `https://` upstream routes
are rejected. Userinfo is used for SOCKS authentication and is never echoed in
logs or `/status`.

```bash
LISTEN_ADDR=:8080 \
ADMIN_ADDR=127.0.0.1:8081 \
PROXIES_FILE=proxies.txt \
./bin/paf
```

Configuration is supplied through the process environment. For the Docker
deployment, `compose.yaml` documents every supported variable beside its value.

|Env|Default|Meaning|
|---|---|---|
|`LISTEN_ADDR`|`:8080`|inbound proxy listener (HTTP + CONNECT)|
|`ADMIN_ADDR`|`127.0.0.1:8081`|admin listener (always on; must differ from `LISTEN_ADDR`)|
|`PROXIES_FILE`|`proxies.txt`|SOCKS5 pool file|
|`MAX_RETRIES`|`3`|attempts across **distinct** routes after endpoint TCP dial or SOCKS authentication failure|
|`COOLDOWN_BASE`|`15s`|first SOCKS endpoint **TCP dial** failure cooldown; doubles per consecutive dial failure, capped|
|`COOLDOWN_MAX`|`10m`|maximum SOCKS endpoint TCP dial cooldown|
|`CONNECT_TIMEOUT`|`10s`|timeout for SOCKS endpoint dial and setup|
|`TARGET_TLS_INSECURE`|`false`|skip HTTPS **target** certificate verification through SOCKS; never use casually|
|`MAX_BODY_BUFFER`|64MiB|request bodies replayed only for a dial/auth fallback; known-larger bodies stream immediately|
|`LOG_LEVEL`|`info`|application default; `debug` adds request-flow events, while `info`/`warn`/`error` filter progressively. Compose overrides this to `warn`.|

## Behavior notes

Read [`README.md`](README.md) before changing failure classification: it is the
normative behavior contract and outcome matrix.

- The pool always selects the usable route least recently used by pick sequence (true round-robin); it has no rotation-mode setting.
- Only SOCKS endpoint DNS/TCP dial failure is a `proxy_connect_error`: it causes a dial cooldown and retry through a distinct route.
- SOCKS authentication negotiation/rejection is a separate authentication-route failure. It blocks the route and may fall back to another route, but never causes TCP dial cooldown.
- A valid target HTTP response—including `407`, `408`, `429`, and `5xx`—is forwarded once without rotation. A target `407` is ordinary response data, not a SOCKS authentication signal.
- Errors after endpoint TCP dial succeeds—including SOCKS target-connect/protocol errors, target TLS, write/read, malformed response, client cancellation, and broken established tunnels—do not mutate route health and are not retried. SOCKS target-connect failure becomes a sanitized `502`.
- Hop-by-hop headers (including Connection-listed tokens and `Proxy-Authorization`) are stripped in both directions. Upstream URL credentials must never appear in logs, `/status`, or responses.
- Request logs carry a process-local `request_id` so a fallback sequence can be correlated. Log `target` and `upstream` values are host-only; never add full URLs, userinfo, headers, or bodies. `LOG_LEVEL=debug` shows request flow, while `info` records terminal successes and `warn` records fallback/terminal failures.
- `SIGHUP` re-reads the pool file; on parse error the old pool keeps serving. Unchanged URLs preserve runtime state; changing URL/userinfo creates a new route.
- Shutdown order: graceful proxy drain (10s) → admin drain → close hijacked tunnels (Go's `Shutdown` does not track those).

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
# or full stack (mounts root-level proxies.txt read-only):
docker compose up -d --build && curl http://127.0.0.1:8081/status
```

`compose.yaml` maps host 8080 → proxy and 127.0.0.1:8081 → admin
(localhost-only); the pool file is mounted `:ro`, application logging defaults
to `warn` in Compose, and Docker retains at most three 10 MiB `json-file` logs.
Set `LOG_LEVEL=info` or `debug` temporarily for detailed request tracing. The
container healthcheck calls the binary's own `healthcheck` subcommand (no shell
in the scratch image).

`Dockerfile` builds a static binary into a `scratch` image plus the CA bundle
for HTTPS target verification; `HEALTHCHECK` works because `healthcheck` is a
subcommand of the entrypoint binary itself (no shell in the image).

## Layout

- `internal/config` — environment loading, SOCKS pool file parser
- `internal/pool` — fixed LRU round-robin rotation, endpoint dial cooldowns, SOCKS auth state, live `Reload`
- `internal/proxyserver` — SOCKS5 dialing and inbound HTTP/CONNECT forwarding
- `cmd/proxy-auto-rotate-forwarder` — entrypoint, signals, admin endpoints
