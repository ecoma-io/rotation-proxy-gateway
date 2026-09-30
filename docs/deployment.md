# Deployment

Running the gateway for real: Docker, migrating inbound clients from the old
HTTP era, building and verifying from source, and sizing shutdown.

## Docker

```bash
cp config.example.yaml config.yaml
# edit config.yaml with real routes
docker compose up -d --build
curl http://127.0.0.1:30120/status
```

Compose publishes ports `30120` (admin, HTTP), `30121` (mixed SOCKS5),
`30122` (v4 SOCKS5), and `30123` (v6 SOCKS5) on all host interfaces. The admin
process listener deliberately binds all interfaces inside its network
namespace; operators control exposure through Docker port publishing, Docker
networks, and firewall policy. The image remains a static binary in `scratch`
with CA certificates and no shell; its healthcheck invokes the binary
subcommand directly. Compose retains at most three 10 MiB JSON log files.

Compose bind-mounts `config.yaml` read-only; hot reload polls content, so
in-place host edits apply without restart, while an atomic replace across the
single-file mount stays invisible — see
[reload behavior](configuration.md#reload-behavior).

## Migrating inbound clients to SOCKS5

The listener protocol changed from HTTP forward proxying to SOCKS5, so inbound
clients migrate:

- Switch each client's proxy URL to a SOCKS5 URL. With a curl-style client this
  is `curl --socks5-hostname 127.0.0.1:30121 https://example.com/`; in a
  browser or library, configure the SOCKS5 proxy (host `127.0.0.1`, port
  `30121`) with remote DNS — the gateway never resolves target names.
- Remove any `global:` block from `config.yaml`. The old
  `global.target-tls-insecure` and `global.max-body-buffer` keys are no longer
  accepted and the config fails validation otherwise (on first boot the process
  refuses to start).
- Authentication follows `RPGW_ACCOUNT`. Unset, only NO AUTHENTICATION is
  offered and a client configured to send SOCKS username/password must have
  that mode disabled. Set, every client must speak SOCKS username/password
  mode with the exact configured `username:password` (see
  [inbound SOCKS5 behavior](inbound-socks5.md#authentication)).
- Keep-alive is now client-owned: one client connection carries exactly one
  tunnel, and pooled clients reuse it across requests. HTTP clients over SOCKS
  typically do this automatically.

For each old `proxies.txt` line, create one `proxies.auto` item and choose
`kind` from your provider's documented public egress family. There is no safe
automatic family detection from the SOCKS hostname/IP. `proxies.txt` is no
longer loaded.

## Build and verification

The source supports Go 1.25 or newer. Docker builds with Go 1.27. The project
uses Viper for YAML loading and validation; hot reload is a self-contained
content-hash poller.

```bash
gofmt -w .
go vet ./...
go test -race ./...
go build -ldflags "-X main.version=0.1.0-dev" -o bin/rpgw ./cmd/rotation-proxy-gateway
```

The black-box E2E suite lives under `e2e/` and drives the real binary as a
subprocess against in-process simulators; `go test ./e2e/` runs it (skip with
`-short`), and [`e2e/BENCH.md`](../e2e/BENCH.md) documents the benchmarks.

## Shutdown sizing

Graceful shutdown runs in a fixed order, and the order is the contract:

1. **Stop advertising readiness.** `GET /readyz` goes `503` immediately, while
   every listener is still accepting. Nothing is closed yet.
2. **Hold for the readiness head start** — 5 seconds, drawn from the budget
   below rather than added to it, and capped at `RPGW_SHUTDOWN_GRACE / 2`. This
   is the window a load balancer needs: a probe scheduled before the signal
   still lands on a live socket, so it observes a `503` rather than a refused
   connection. It covers all three proxy listeners and the admin listener, not
   just admin — the caller-facing SOCKS5 listeners are the ones that actually
   get refused. A `500ms` interval plus a `500ms` timeout on the probe side is
   1s of worst-case notification, comfortably inside 5s; a `2s` interval plus
   `2s` timeout is 4s and still fits, but only just.
3. **Stop the rotation engine, then the warm pool**, in that order, inside the
   same budget. Rotations abort at their next checkpoint and no outcome is
   recorded. The warm pool is second on purpose: reversing the order would let
   parked warm sockets outlive the sessions they exist to accelerate.
4. **Close every listen socket**, then **drain all of them concurrently**,
   together with the admin listener, against one shared budget
   (`RPGW_SHUTDOWN_GRACE`, default `55s`).

Step 4 closes all sockets before draining any of them, which is a change in
failure profile worth knowing about. Draining one listener at a time used to
leave the not-yet-drained listeners accepting — and, because each listener only
refuses new sessions once _its own_ shutdown has begun, those listeners went on
admitting brand-new tunnels that the already-expired deadline then force-closed.
Now one long tunnel on **any** listener ends the accept phase for all of them.
That is the right shape for a draining gateway, but it is a change from "some
listeners still serve" to "none do, promptly".

The one shared budget is not a window per listener: even a fully busy worst case
exits near the budget, and an idle process exits as soon as the head start is
over. When it expires, the remaining sessions' client connections — including
established tunnels, which no HTTP server shutdown tracks — are force-closed,
and a bounded tail of about one second lets them unwind on their closed sockets.
Because the drains now run concurrently, that tail is paid once, not once per
proxy listener in sequence. The worst case with the default 55s grace is
therefore roughly 56s. Size the surrounding orchestrator above the budget — for
example `stop_grace_period: 60s` in compose — so its kill timer never cuts the
drain short.

**`stop_grace_period` is not a lever for availability.** It bounds how long the
outgoing container keeps running, and while it drains its SOCKS5 listeners are
closed, so a single-replica deployment has nowhere to send new connections for
exactly that long. Making it larger makes the incident worse. What closes the
window is the topology below; the grace should be sized to the real drain-time
distribution, measured rather than guessed.

## Zero-downtime rollout

The process can now _report_ that it is going away, and it can be drained
without half its listeners serving while the others are already dead. Neither of
those closes the new-connection window on its own. This is the part that does,
and it is not in this repository:

**Run at least two replicas and replace them start-new-then-stop-old.**

Until that is true, a rollout drops every new connection for the duration of the
outgoing container's drain. A readiness signal makes the error message better
("no healthy upstream" instead of "connection refused") — it does not make the
outage shorter. With two or more replicas behind a load balancer that honours
`/readyz`, the balancer has somewhere else to send traffic and the rollout
becomes invisible to clients.

If you are fronted by Traefik, the TCP services need a health check. Traefik v3.6
added health checking for TCP load balancers (it was HTTP-only before), and the
deployed proxy runs v3.7, so the labels below apply. Unlike the HTTP health
check there is no `path` and no status code: `TCPServerHealthCheck` is a
connect check with optional payload exchange, so it verifies the socket, not the
`/readyz` body. `/readyz` still has to be probed by something — the binary's own
`healthcheck` subcommand, a container probe, or an HTTP-scoped router — and it
is what tells Traefik to stop sending traffic. The TCP health check and
`/readyz` are complementary, not substitutes:

```yaml
labels:
  # A draining instance must leave Traefik's rotation before its sockets go
  # away. Defaults are 30s interval / 5s timeout, both too slow for a 5s
  # head start; 2s + 1s keeps the worst case inside it.
  traefik.tcp.services.proxy-mixed.loadbalancer.healthcheck.interval: 2s
  traefik.tcp.services.proxy-mixed.loadbalancer.healthcheck.timeout: 1s
  traefik.tcp.services.proxy-v4.loadbalancer.healthcheck.interval: 2s
  traefik.tcp.services.proxy-v4.loadbalancer.healthcheck.timeout: 1s
  traefik.tcp.services.proxy-v6.loadbalancer.healthcheck.interval: 2s
  traefik.tcp.services.proxy-v6.loadbalancer.healthcheck.timeout: 1s
  traefik.tcp.services.proxy-admin.loadbalancer.healthcheck.interval: 2s
  traefik.tcp.services.proxy-admin.loadbalancer.healthcheck.timeout: 1s
```

A separate, HTTP-style health check — `healthcheck.path`, `healthcheck.scheme`,
`healthcheck.status` — does **not** exist for a TCP load balancer in any Traefik
release. Only the `port` / `send` / `expect` / `interval` / `unhealthyInterval` /
`timeout` keys are read, and a status code is never consulted. So there is no
Traefik label that will make it poll `/readyz`; the labels above make Traefik
notice a closed socket, and something else has to read the body. Verify with
Traefik's API (`/api/rawdata`) that the health check you configured is actually
attached to the service — a misspelled label is silently ignored and the server
stays in the rotation forever.

**Do not rely on connection-refused to evict a draining instance.** That is the
failure mode this design exists to eliminate: an instance whose port is refused
is a server Traefik still believes in until the check says otherwise, and until
then every new connection is an outage.
