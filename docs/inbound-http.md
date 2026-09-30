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
answered `501 Not Implemented`, and clients wanting TLS use `CONNECT`.

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
| Unsupported scheme in an absolute-form target                                                                        | `501 Not Implemented`               |
| HTTP version other than 1.1                                                                                          | `505 HTTP Version Not Supported`    |
| Missing or wrong `Proxy-Authorization` while `RPGW_ACCOUNT` is set                                                   | `407 Proxy Authentication Required` |

A fallback in progress does not produce a status: the client sees only the
terminal outcome of its attempt chain. The `error_kind` values the process logs
are unchanged by this migration and are listed in
[failure and route health](failure-and-health.md).

## Header handling

- Hop-by-hop headers (RFC 7230 §6.1) are removed before forwarding. This is the
  standard library's behavior, not a second list maintained here.
- `Proxy-Authorization` is removed, per the authentication section above.
- Every `x-ecoma-*` header is removed before forwarding. These are internal
  control headers; none of them, valid or not, may ever reach an upstream.
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
