# Inbound HTTP forward-proxy behavior

Each proxy listener is an HTTP forward proxy. The client states the target;
the gateway never learns it from configuration. This is the replacement for the
SOCKS5 ingress documented in the previous release and is the only ingress —
there is no compatibility listener, flag, or fallback port.

Two request shapes are accepted, and nothing else.

## CONNECT

    CONNECT api.example.com:443 HTTP/1.1
    Host: api.example.com:443

On success the gateway answers `HTTP/1.1 200 Connection established` with a
`Content-Length: 0` body and then relays bytes in both directions
transparently until either side ends. The `Host` header is optional; the
authority-form request target is authoritative, and a `Host` that disagrees
with it is a malformed request.

This is the shape `curl -x`, `https_proxy`, and any TLS client library use for
an `https://` target.

## Absolute-form

    GET http://api.example.com/path?q=1 HTTP/1.1
    Host: api.example.com

The target is the request-target's authority, not the `Host` header. The
gateway routes by that authority and then forwards the request **origin-form**:

    GET /path?q=1 HTTP/1.1
    Host: api.example.com

An absolute-form request target is never forwarded unchanged. A target with no
path (`GET http://api.example.com HTTP/1.1`) forwards as `GET / HTTP/1.1`.
Only the `http` scheme is proxied; `https` in an absolute-form target is
answered `501 Not Implemented`, and clients wanting TLS use `CONNECT`. The
method is relayed verbatim; only `GET`, `HEAD`, and `POST` have defined
forward-proxy semantics here, so any other method is answered
`405 Method Not Allowed` before a route is selected.

A default port is implied when the authority omits one — `http://example.com`
is `example.com:80`. An explicit port must be a real port number; zero is
rejected.

**Origin-form requests are not a proxy request.** `GET /path HTTP/1.1` sent to a
proxy listener is a request for a _local_ resource that does not exist, and is
answered `400`. This is the line between a forward proxy and a reverse proxy:
the gateway has no notion of "the origin", so a request that does not name one
cannot be served.

## Target addresses

DNS for a domain target happens at the outbound route, never in the gateway —
a hostname arriving on ingress leaves as the same hostname in the SOCKS5
`CONNECT` address type `0x03`. An IPv4 or IPv6 literal target keeps its
address family (`0x01` / `0x04`). The gateway never resolves a hostname to
decide a target's type, and never re-classifies a target from its string.

When a [routing block](configuration.md#request-routing-routing-block) is
configured, only a domain target can match a rule; the match reads the
hostname case-insensitively with one trailing DNS dot ignored. IPv4 and IPv6
targets skip the rules and resolve to `default-routes`; an unmatched target
with no default routes fails closed. See
[routing and selection](failure-and-health.md#routing-and-selection).

## Authentication

Authentication follows `RPGW_ACCOUNT` (see
[configuration](configuration.md#rpgw_account)) and is presented as HTTP
`Proxy-Authorization: Basic base64(username:password)`, the standard HTTP
forward-proxy credential. It is required on **every** request — `CONNECT` and
absolute-form alike — when `RPGW_ACCOUNT` is set.

- **Unset (the default):** no `Proxy-Authorization` is required. One that
  arrives anyway is consumed and stripped, never forwarded upstream.
- **Set:** a missing, malformed, non-`Basic`, or wrong-credential header is
  answered `407 Proxy Authentication Required` with
  `Proxy-Authenticate: Basic realm="rotation-proxy-gateway"`. A correct header
  is accepted and then stripped before forwarding.

Credentials are compared in constant time. Neither the configured account nor
anything a client presents ever appears in logs, errors, `/status`, or
responses. Authentication happens before route selection: a rejected
credential is a local inbound error — it never advances the listener
`requests` counter, never touches route health, and is never retried against
another route.

`Proxy-Authorization` is hop-by-hop for a proxied request: the gateway
terminates it. Forwarding it would hand a proxy credential to the target
server.

## Status codes

| Condition                                                                                                            | Status                              |
| -------------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| Tunnel established (`CONNECT`)                                                                                       | `200 Connection established`        |
| Tunnel established (absolute-form)                                                                                   | the origin's own status             |
| Upstream dial, handshake, auth, or target refused (`proxy_connect`, `socks_connect`, `auth_route`, `connect_target`) | `502 Bad Gateway`                   |
| No eligible route, or retry budget spent with routes left (`no_route`, `retry_exhausted`)                            | `503 Service Unavailable`           |
| Inbound handshake deadline expired before the next attempt                                                           | `502 Bad Gateway`                   |
| Malformed request: bad request line, origin-form without proxy role, absent or inconsistent authority, zero port     | `400 Bad Request`                   |
| `x-ecoma-proxy-family` outside the closed set, empty, or repeated                                                    | `400 Bad Request`                   |
| Unsupported scheme in an absolute-form target                                                                        | `501 Not Implemented`               |
| Absolute-form request whose method is not `GET`, `HEAD`, or `POST`                                                   | `405 Method Not Allowed`            |
| HTTP version other than 1.1                                                                                          | `505 HTTP Version Not Supported`    |
| Missing or wrong `Proxy-Authorization` while `RPGW_ACCOUNT` is set                                                   | `407 Proxy Authentication Required` |

A fallback in progress does not produce a status: the client sees only the
terminal outcome of its attempt chain. The `error_kind` values the process logs
are unchanged by this migration and are listed in
[failure and route health](failure-and-health.md).

## Control headers

Two headers in the gateway-private `x-ecoma-` namespace are read on ingress.
Both are stripped before forwarding, and neither is part of route identity. The
namespace as a whole is gateway-private: an `x-ecoma-` header the gateway has
never heard of is dropped just the same, and no `x-ecoma-` header ever reaches
an upstream, whatever it carries.

### `x-ecoma-proxy-family`

Constrains which **egress IP family** may carry one request. Values are the
closed set `v4`, `v6`, and `mixed`; an absent header is exactly `mixed`, and
the two are the same request.

    CONNECT api.example.com:443 HTTP/1.1
    Host: api.example.com:443
    X-Ecoma-Proxy-Family: v6

This is a request-scoped **route-selection constraint, not a socket binding**.
It narrows the eligible route set the same way a listener's own egress-kind
filter and the routing block do, and it composes with both **by intersection**:
the effective eligible set is whatever all three agree on. So on the mixed
listener, a `v6` request is served by a `kind: v6` route; on the dedicated v4
listener, a `v6` request has no candidate at all, because the listener's filter
excludes every route a v6 request could have wanted. A v4-only route can never
serve a `v6` request, on any listener, under any combination of the two.

What it does **not** do: it does not resolve a name, does not change the target's
address family, and does not change the address or address type that leaves in
the outbound SOCKS5 `CONNECT`. A domain target stays a domain target. The
header chooses the route; the route chooses the connection.

**Route identity is untouched.** The header never enters the canonical route
key, so two requests for one target that differ only in this header hit the
same `pool.Proxy` objects and share their health, their cooldown, and their
cooldown counters. A family-scoped request is not a new route and does not
fork route state.

**An invalid value is refused with `400 Bad Request`**, before route selection,
on the same footing as a malformed authority. It is a local pre-selection
reject: it never advances the listener `requests` counter, never touches route
health, and is never retried. The cases the grammar draws:

| Header state                                              | Result               |
| --------------------------------------------------------- | -------------------- |
| absent, or exactly one occurrence of `mixed`/`v4`/`v6`    | accepted             |
| a value outside the closed set (`V4`, `ipv4`, `any`, `4`) | `400 Bad Request`    |
| an empty value (`X-Ecoma-Proxy-Family:`)                  | `400 Bad Request`    |
| more than one occurrence, even with the same value        | `400 Bad Request`    |
| interior whitespace (`v 4`), upper case, a quoted value   | `400 Bad Request`    |
| leading or trailing whitespace (`" v4"`, `"v4 "`)         | accepted — see below |

Leading and trailing whitespace is not a spelling at all: HTTP strips optional
field-value whitespace (RFC 9110 §5.5) before the value reaches the gateway, so
`" v4 "` is byte-for-byte the same request as `v4`.

Refusing rather than falling back to `mixed` is a deliberate choice. A client
that asked for IPv6 egress and silently received IPv4 would have no way to see
it — an invisible correctness failure on the one property this gateway exists to
provide. An empty value is refused for the same reason: reading it as absent
would make "present but meaningless" indistinguishable from "never asked",
which is precisely the silent fallback being refused. A repeated header is
refused because the gateway cannot know which of the two constraints was meant,
and choosing one would let an intermediary pick the client's egress family.

A family constraint that leaves no eligible route is `no_route` — the ordinary
`503 Service Unavailable`, not a protocol error. An empty candidate set and a
refused value are different failures with different statuses.

### `x-ecoma-request-id`

An optional client-supplied correlation id. It appears as `correlation_id` on
the log records of the request it was resolved for, so a client can find its own
request among the gateway's.

    CONNECT api.example.com:443 HTTP/1.1
    Host: api.example.com:443
    X-Ecoma-Request-Id: 01J8Z9RQ4M7N2K3P4T5V6W7X8Y

**One request, one id.** It is resolved once, before route selection, and the
same value is carried by every record of that request's attempt chain — however
many routes the chain tried, the failure record and the eventual success record
share the id.

An id is echoed only when it is **exactly one occurrence**, at most **64 bytes**,
and every byte inside `[A-Za-z0-9-_.:]`. Anything else — absent, repeated,
over-long, quoted, whitespace-bearing, or carrying a control character or an
ANSI sequence — is **replaced by a freshly generated id**, not refused. A
serviceable request is not failed over a diagnostic header the client loses
nothing by dropping.

A generated id is marked with a leading `r-` and is otherwise the same shape as
an accepted one: same alphabet, bounded length, no quoting, one line. An
operator distinguishes a client-vouched id from a minted one by the prefix,
never by having to unpick the value.

**`correlation_id` is a companion field, not a replacement.** The
`request_id` field stays the process-local ordinal, and it must: that counter
is what the per-listener `requests` figure in `/status` reports, and its
documented meaning is _valid requests that reached route selection_. Overwriting
it with a client-controlled string would destroy that metric. The two travel
together, so an operator can always join a client's id to the gateway's own
ordinal. See [observability](observability.md).

## Header handling

- Hop-by-hop headers (RFC 7230 §6.1) are removed before forwarding. This is the
  standard library's behavior, not a second list maintained here.
- `Proxy-Authorization` is removed, per the authentication section above.
- Every `x-ecoma-*` header is removed before forwarding, whatever it carries.
  These are internal control headers; none of them may ever reach an upstream.
- Request bodies are streamed, never buffered. There is no body size limit
  configured at the gateway, and none is needed for a forward proxy that
  streams.

## Handshake deadline

A 30-second read deadline bounds reading the client's request — the whole
retry chain of outbound attempts included, since a retry dials again under the
same window. The success reply gets a fresh window, and the deadline is cleared
once the tunnel is established. Established tunnels have no timeouts.

## Keep-alive and tunnel ownership

An absolute-form request consumes exactly one tunnel: the gateway does not
reuse an upstream connection across requests of its own, so a client's
keep-alive does not extend an upstream connection's life. The gateway never
buffers or inspects relayed bytes and never terminates a client's tunnel
early; an upstream that breaks the tunnel mid-stream closes the client
connection, so a truncated stream stays visibly truncated instead of reading
as a clean end.

For `CONNECT`, one tunnel is one client connection's payload and lives until
either side closes. A client that pools connections obtains one tunnel per
pooled connection; tunnel scoping is the client's choice.
