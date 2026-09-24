# rotation-proxy-gateway

`rotation-proxy-gateway` is a Go SOCKS5 proxy that accepts stable inbound
SOCKS5 (RFC 1928) endpoints and routes connections through a health-aware pool
of **SOCKS5-only** upstream routes. It runs three inbound proxy listeners —
one mixed egress family, one IPv4-only, one IPv6-only — over a single shared
route-health pool. An optional routing block scopes any domain target to a
candidate set of named routes; the pool stays the sole authority on health,
cooldowns, and selection order.

<p align="center">
  <a href="https://github.com/ecoma-io/rotation-proxy-gateway/actions/workflows/ci.yml"><img src="https://github.com/ecoma-io/rotation-proxy-gateway/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/ecoma-io/rotation-proxy-gateway/actions/workflows/analysis.yml"><img src="https://github.com/ecoma-io/rotation-proxy-gateway/actions/workflows/analysis.yml/badge.svg" alt="Analysis" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache 2.0" /></a>
</p>

> **Status:** The authoritative behavior contract lives under
> [`docs/`](docs/); this README is the entry point. In particular, never infer
> SOCKS route health from a destination HTTP response — see
> [Failure and route health](docs/failure-and-health.md).

## Inbound endpoints

The process starts one admin listener and up to three proxy listeners:

| Endpoint     |         Default | Protocol | Purpose                                                      |
| ------------ | --------------: | -------- | ------------------------------------------------------------ |
| Admin        | `0.0.0.0:30120` | HTTP     | `/healthz` and `/status`; operator controls network exposure |
| Mixed SOCKS5 |        `:30121` | SOCKS5   | Selects both v4- and v6-egress routes                        |
| IPv4 SOCKS5  |        `:30122` | SOCKS5   | Selects only `kind: v4` routes                               |
| IPv6 SOCKS5  |        `:30123` | SOCKS5   | Selects only `kind: v6` routes                               |

`kind` is the public egress IP family supplied by a proxy provider. It is not
the SOCKS endpoint address family and it does not impose an IPv4/IPv6 policy on
the client's target destination.

A single shared pool owns health state. Therefore, a dial cooldown or SOCKS
authentication block observed through the v4 listener is also observed by the
mixed listener when it considers that route. A listener never falls through to
a route of another kind. A v4-only or v6-only route pool is valid: mixed selects
the available family, and the enabled dedicated listener without matching routes
remains live but replies with the ordinary no-route SOCKS general-failure
(`05 01`) until that family is added.

Domain-based request routing is optional and configured in the runtime YAML:
rules map domain patterns (exact or `*.`-prefixed) to candidate route sets,
first match wins, and unmatched targets resolve to `default-routes` or fail
closed with `05 01`. Only domain targets match rules — IP targets and the
wire bytes are never rewritten — and routing never overrides health: the pool
still decides which candidate serves. See
[configuration](docs/configuration.md#request-routing-routing-block) and
[failure and route health](docs/failure-and-health.md#routing-and-selection).

## Quick start

```bash
cp config.example.yaml config.yaml # add real static SOCKS routes
RPGW_MIXED_LISTEN_ADDR=:30121 \
RPGW_V4_LISTEN_ADDR=:30122 \
RPGW_V6_LISTEN_ADDR=:30123 \
RPGW_ADMIN_ADDR=0.0.0.0:30120 \
go run ./cmd/rotation-proxy-gateway

curl --socks5-hostname 127.0.0.1:30121 https://example.com/
curl http://127.0.0.1:30120/status
```

`config.yaml` normally contains upstream credentials and is ignored by Git and
Docker build contexts. Do not commit it or bake it into an image. Every
bootstrap variable carries the `RPGW_` prefix;
[`.env.example`](.env.example) lists them all with their defaults — copy it to
`.env` (Git-ignored) and either export it before a bare-metal run
(`set -a; . ./.env; set +a`) or pass `--env-file .env` to `docker run`.

## Documentation

- [Configuration](docs/configuration.md) — bootstrap environment variables
  (`RPGW_*`), the runtime YAML (routes and their ids, cooldown, rotation, warm
  pool, the domain-routing block) and its validation rules, and hot-reload
  behavior including the bind-mount table.
- [Manual rotation routes](docs/rotation.md) — provider-API routes that rotate
  their public egress IP: the procedure contract (drain → baseline probe →
  rotate call → verify), states, backoff, and reload/shutdown interplay.
- [Warm upstream pool](docs/warm-pool.md) — the optional bounded pool of
  half-established upstream connections: bounds, borrowing, and rotation
  isolation.
- [Failure and route health](docs/failure-and-health.md) — the failure
  classification contract (`proxy_connect`, `auth_route`, `socks_connect`,
  `connect_target`, `setup`, `no_route`, `retry_exhausted`), round-robin
  selection, and the two cooldown scopes.
- [Inbound SOCKS5 behavior](docs/inbound-socks5.md) — RFC 1928/1929
  authentication, commands, target-address transparency, replies, the
  handshake deadline, and keep-alive ownership.
- [Observability](docs/observability.md) — the admin listener, the `/status`
  JSON contract, and the logging and redaction contract.
- [Deployment](docs/deployment.md) — Docker and compose, migrating inbound
  clients to SOCKS5, build and verification, and shutdown sizing.

Benchmarks live in [`e2e/BENCH.md`](e2e/BENCH.md): end-to-end, HA, and
warm-pool A/B scenarios, with the workflow for trustworthy before/after
comparisons.

## Community

- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md) — the commands, the hooks,
  the commit and pull-request conventions, how a release happens.
- Code of conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Security: [SECURITY.md](SECURITY.md) — never a public issue for a
  vulnerability.
- License: [LICENSE](LICENSE) — Apache 2.0.
