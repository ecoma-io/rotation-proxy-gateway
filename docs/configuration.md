# Configuration

Configuration has two layers. **Bootstrap** values create sockets or choose
the polled file, are read from `RPGW_`-prefixed environment variables exactly
once at process start, and require a restart. **Runtime** settings and routes
live in a YAML file that is validated and hot-reloaded every second.

## Bootstrap environment (restart only)

| Variable                 |         Default | Meaning                                                        |
| ------------------------ | --------------: | -------------------------------------------------------------- |
| `RPGW_CONFIG_FILE`       |   `config.yaml` | Runtime YAML file path                                         |
| `RPGW_ADMIN_ADDR`        | `0.0.0.0:30120` | Always-on admin listener; network policy controls exposure     |
| `RPGW_MIXED_LISTEN_ADDR` |        `:30121` | Mixed v4/v6 egress listener                                    |
| `RPGW_V4_LISTEN_ADDR`    |        `:30122` | v4-egress-only listener                                        |
| `RPGW_V6_LISTEN_ADDR`    |        `:30123` | v6-egress-only listener                                        |
| `RPGW_SHUTDOWN_GRACE`    |           `55s` | Total shared drain budget for graceful shutdown                |
| `RPGW_ACCOUNT`           |         _unset_ | `username:password` — require RFC 1929 auth on proxy listeners |

[`.env.example`](../.env.example) lists them all with their defaults — copy it
to `.env` (Git-ignored) and either export it before a bare-metal run
(`set -a; . ./.env; set +a`) or pass `--env-file .env` to `docker run`.

An explicitly empty proxy listener address disables that listener, but at least
one proxy listener must remain enabled. All enabled addresses must be valid
host:port addresses, use a numeric port, and not overlap — including wildcard
binds on the same port (ports compare numerically, so `:080` and `:80` collide).
Docker Healthcheck uses only `RPGW_ADMIN_ADDR`; a bad runtime reload cannot
make an otherwise-running service unhealthy.

### `RPGW_ACCOUNT`

When set, it must read `username:password`: split at the first colon (the
password may itself contain colons), a username of 1-255 bytes and a password
of 0-255 bytes — the RFC 1929 field limits. An empty value is the same as
unset. Any other shape — no colon, an empty username, an oversized field —
fails startup instead of silently serving without authentication. The inbound
authentication behavior it switches on is documented in
[Inbound SOCKS5 behavior](inbound-socks5.md#authentication).

### Retired unprefixed names

The unprefixed names these variables replaced (`CONFIG_FILE`, `ADMIN_ADDR`,
`MIXED_LISTEN_ADDR`, `V4_LISTEN_ADDR`, `V6_LISTEN_ADDR`, `SHUTDOWN_GRACE`) are
retired: setting any of them — to any value, including empty — fails startup
with an error naming its `RPGW_` replacement, the same reject-don't-ignore
treatment as removed config keys, so an upgraded deployment cannot silently
boot on default listeners and the default config path.

## Runtime YAML

See [`config.example.yaml`](../config.example.yaml). The file is the complete
source for runtime behavior and static routes:

```yaml
log-level: info
max-retries: 3
cooldown:
  base: 15s
  max: 10m
dial-timeout: 10s
proxies:
  auto:
    - proxy: username:password@provider.example:1080
      kind: v4
    - proxy: username:password@[2001:db8::1]:1080
      kind: v6
  manual: []
```

The scalar settings are **required** — there are no defaults for them, and an
absent or invalid value fails validation (on reload the last-known-good config
keeps serving; on first boot the process refuses to start):

| Key             | Rule                                                              |
| --------------- | ----------------------------------------------------------------- |
| `log-level`     | One of `debug`, `info`, `warn`, `error`                           |
| `max-retries`   | Whole number ≥ 1 (a fractional value is rejected, not truncated)  |
| `cooldown.base` | Positive Go duration; must not exceed `cooldown.max`              |
| `cooldown.max`  | Positive Go duration                                              |
| `dial-timeout`  | Positive Go duration; bounds endpoint TCP dialing and SOCKS setup |
| `proxies`       | At least one route across `proxies.auto` and `proxies.manual`     |

The `rotation` and `warm-pool` blocks are optional and fully defaulted — see
[Manual rotation routes](rotation.md) and [Warm upstream pool](warm-pool.md).

`max-retries` is the total number of distinct eligible routes one request may
attempt (the first try included), not a number of extra retries.

### Route lines

`proxies.auto` is the source of static routes; `proxies.manual` routes
additionally carry a rotate schedule and provider API. The accepted `proxy`
forms are:

```text
host:port
user:pass@host:port
host:port:user:pass
```

Every route requires an explicit port and a `kind` of exactly `v4` or `v6`.
Bracket IPv6 literals. The route line carries no scheme: the endpoint protocol
is not configurable — every route is a SOCKS5 endpoint — and a line containing
`socks5://`, `socks5h://`, or any other scheme is rejected.

`kind: v4|v6` is the provider-backed **public egress IP family**. It does not
classify the SOCKS endpoint transport address and does not restrict target
address families. Do not infer kind by resolving a hostname.

`proxies.auto` routes and `proxies.manual` routes share one pool and one
identity space; a duplicate across the two lists is rejected like any other,
and a duplicate remains a duplicate even if it claims another kind — route
identity is the endpoint URL alone.

Credentials never appear in errors, logs, or `/status`
([observability](observability.md)).

### Route IDs

Every route may carry an `id` — the operator-facing label that
[routing rules](#request-routing-routing-block) refer to and `/status` shows:

```yaml
proxies:
  auto:
    - id: egress-a
      proxy: username:password@provider.example:1080
      kind: v4
```

An id is 1–128 characters of letters, digits, hyphens, and underscores. That
grammar is also the log-safety guarantee: ids appear in configuration errors,
`/status`, and debug logs, so nothing that reads as another field or carries
whitespace is admitted. Ids must be unique across `proxies.auto` and
`proxies.manual` combined — two routes answering to one label could be picked
twice per request and would make every rule that names the label ambiguous.

An id is a routing label, not the route's identity. Route identity stays
canonical URL+kind+origin: renaming an id keeps the route's health state
(cooldowns, counters, rotation history) exactly as any other
identity-preserving reload does, and `/status` shows the new label from the
moment the reload publishes. Ids are optional while no `routing` block exists;
once one does, every serving route must carry an id — an unnamed route could
never appear in a rule, and silently letting it serve outside every rule would
narrow the pool behind the operator's back.

### Request routing (`routing` block)

The optional `routing` block scopes which routes each inbound CONNECT target
may use. Without it (the default), every listener selects from the whole pool
exactly as the rest of this document describes. With it, each target resolves
to a **candidate set**, and the pool — still the sole authority on health,
cooldown, order, and kind filtering — picks among exactly those candidates:

```yaml
routing:
  rules:
    - match:
        domains:
          - api.openai.com
          - "*.openai.com"
      routes:
        - egress-a
        - egress-b
  default-routes:
    - rotating-a
```

- **First match wins.** Rules are evaluated in order against the target's
  hostname; the first rule whose patterns match decides the candidate set.
  Later rules never merge into an earlier match.
- **Only domain targets match.** A CONNECT sent as ATYP=DOMAIN (`0x03`) is
  matched against the rules; IPv4 and IPv6 targets carry no hostname, so they
  always resolve to `default-routes`. The gateway never reverse-resolves an
  address to a name: routing follows what the client actually sent, not what
  DNS would say.
- **Matching is normalized and label-bound.** Names compare case-insensitively
  with one trailing DNS dot ignored — `API.OpenAI.com.` matches
  `api.openai.com`. A pattern is either a hostname or `*.` followed by a
  hostname; `*.openai.com` matches `api.openai.com` and `a.b.openai.com`, never
  `openai.com` itself (that is what the exact pattern is for) and never
  `evilopenai.com` (the dot is the label boundary). The wire target is never
  rewritten: whatever bytes arrive travel to the outbound CONNECT untouched.
- **Unmatched targets resolve to `default-routes`.** Omit the key and an
  unmatched target has no candidates at all: it receives the ordinary `05 01`
  general failure and nothing else in the pool is contacted. An explicit empty
  `default-routes: []` is rejected — omit the key for the same, documented
  result.
- **The block is deliberate.** A null `routing:` key means the block is absent
  (unrestricted). A present-but-empty `routing: {}` is the configured kill
  switch: every target fails closed unless a future rule admits it. Removing
  the block restores unrestricted selection on the next reload.

Validation is at load time, in one pass with the rest of the config: a rule
with no domains or no routes, an unknown pattern form (anything beyond exact
or a leading `*.`), a route id a rule or `default-routes` names but no route
carries, or a route left unnamed are all rejected. A rejected routing block
rejects the whole configuration, so on reload the last-known-good policy keeps
serving, exactly like any other invalid change.

The routing policy rides the same atomic generation as the pool and its
routes: a reload that changes rules and routes together publishes both as one
unit, and in-flight requests finish on the generation they started with.
Renaming a route's id is a routing change, not a health change — but note the
one transient: an in-flight request on the old generation may find a just-
renamed route absent from its candidate set and fail closed (`05 01`), never
open.

### Rejected configuration

Unknown active YAML fields are rejected (strict decoding), which is what makes
the removed keys fail loudly rather than be ignored:

- The removed HTTP era's `global:` block: a config containing
  `target-tls-insecure` or `max-body-buffer` fails validation.
- The removed weighted-selection keys: a route `weight` key and a `balance`
  block fail validation identically.
- HTTP/HTTPS routes, URL paths, queries, fragments, and unknown fields on a
  route entry.

## Reload behavior

The process polls the runtime YAML every second and reloads when the file's
content hash changes, so every way of updating the file behaves the same:
in-place edits, atomic replacements (editor save, `mv`, symlink swap), and any
bind-mount style. Hashing content instead of listening for filesystem events
deliberately trades instant delivery for universality; up to one second of
latency is irrelevant for configuration.

```yaml
# compose.yaml
volumes:
  - ./config.yaml:/app/config.yaml:ro
environment:
  RPGW_CONFIG_FILE: /app/config.yaml
```

One case no in-process reader can observe: renaming a new file over the config
**behind a single-file bind mount**. The mount pins the file's inode, so a
host-side `mv`/editor-safe-save swaps in a new inode that the container path
never follows; the old content keeps serving until restart. With a single-file
mount, update the file in place, or mount its directory instead.

Each reload parses and validates a complete new configuration before changing
any serving state. A syntax error, partial write, invalid route, or invalid
runtime setting logs a sanitized warning and retains the last-known-good config
and pool. Validated configuration and its reconfigured pool snapshot publish as
one atomic generation: every request and CONNECT operation loads that generation
once, while in-flight operations finish on their original snapshot.

There is deliberately no signal-based fallback. SIGHUP is caught and ignored:
it is neither a reload trigger nor a stop signal. The gateway logs one line on
first receipt and keeps serving — SIGHUP never reloads anything and never
drains or kills the process. A SIGHUP-based reload would also re-read the same
pinned inode and cannot fix the bind-mount blind spot, so it would only add a
second, more surprising reload path. `SIGTERM` and `SIGINT` remain the
graceful-stop signals (see [deployment](deployment.md)).

### Measured mount behavior (Docker bind mounts)

Measured on Linux (2026-09), first against event-based watching (Viper 1.21 +
fsnotify), then against the current content-hash poller:

| Host update                            | Directory bind mount | Single-file bind mount                             |
| -------------------------------------- | -------------------- | -------------------------------------------------- |
| In-place write (`echo > file`)         | reload fires         | reload fires (poller only — inotify never sees it) |
| Atomic rename-over (editor save, `mv`) | reload fires         | invisible (mount pins the old inode)               |

The rename-over single-file blind spot is inherent to bind-mount semantics, not
to any watcher implementation: nothing inside the container can observe a new
inode spliced in on the host. Event-based watching had a second blind spot —
inotify parent-directory events follow the writing side's path hierarchy, so a
single-file in-place write produced no event at all. Polling by content was
adopted so the mount style stops mattering.

### What a reload applies

The following settings apply to new client operations without restart:

- `log-level`
- `max-retries`
- `cooldown.base` and `cooldown.max` (new dial failures only)
- `dial-timeout`
- `proxies.auto` and `proxies.manual`, their `id` labels included
- the whole `routing` block (rules, `default-routes`, presence and absence)
- every `rotation.*` setting (the scheduler reads them per cycle; a procedure
  already running keeps its own `drain-timeout` and probe settings)
- every `warm-pool.*` setting (disabling the pool closes its parked
  connections; changed bounds apply to future replenishment)

### What a reload preserves

Routes whose canonical URL, kind, and origin are unchanged keep their runtime
state: recency pass, cooldown, pair-scoped target cooldowns,
authentication-block, rotation state (last verified IP, stale history), and
counters. Changing the URL (including its userinfo) or `kind` — or moving a
route between `proxies.auto` and `proxies.manual` — creates a fresh route
state. Renaming a route's `id` preserves all of it: the id is a routing label,
not the route's identity. See
[failure and route health](failure-and-health.md) for what that state is.
