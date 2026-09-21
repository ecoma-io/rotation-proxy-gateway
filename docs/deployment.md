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

Graceful shutdown stops the rotation engine (mid-flight procedures abort at
their next checkpoint; no outcome is recorded), then closes every enabled
proxy listener socket and drains each listener's active SOCKS sessions plus
the admin listener against one shared budget, `RPGW_SHUTDOWN_GRACE` (default
55s). It is one deadline for the whole process, not a window per listener, so
even a fully busy worst case exits near the budget; an idle process exits
immediately.

When the budget expires, the remaining listeners are still closed, and their
tracked client connections — including established tunnels, which no HTTP
server shutdown tracks — are force-closed; a bounded tail (about one second
per proxy listener) lets the sessions unwind on their closed sockets. The
worst case with the default 55s grace is roughly 58s. Size the surrounding
orchestrator above the budget — for example `stop_grace_period: 60s` in
compose — so its kill timer never cuts the drain short.
