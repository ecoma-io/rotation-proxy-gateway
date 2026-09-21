# Inbound SOCKS5 behavior

Each proxy listener is a SOCKS5 server (RFC 1928). Clients connect and complete
a version-negotiation greeting, then issue exactly one `CONNECT` request per
connection.

## Authentication

Authentication follows `RPGW_ACCOUNT` (see
[configuration](configuration.md#rpgw_account)):

- **Unset (the default):** only NO AUTHENTICATION REQUIRED (`0x00`) is
  accepted. A client whose greeting offers no `0x00` method receives `05 ff`
  and the connection is closed.
- **Set to `username:password`:** every proxy listener requires
  username/password authentication (RFC 1929). Method negotiation selects
  `0x02` when the client offers it; a greeting without `0x02` -- including
  one offering only `0x00` -- receives `05 ff` and the connection is closed.
  The RFC 1929 exchange must present the exact configured username and
  password; anything else receives the failure reply (`01 ff`) and the
  connection is closed. A malformed auth frame closes without a reply.

Credentials are compared in constant time. Neither the configured account nor
anything a client presents ever appears in logs, errors, or `/status`.
Authentication happens before route selection: a failed authentication is a
local inbound error -- it never advances the listener `requests` metric,
never touches route health, and is never retried against another route.

## Commands

`CONNECT` is the only supported command. `BIND` and `UDP ASSOCIATE` are
answered with `05 07` (command not supported) and the connection is closed.

## Target addresses

IPv4 (`0x01`), domain name (`0x03`), and IPv6 (`0x04`) target address types
are all supported, and the gateway preserves the inbound request's address
type to the egress CONNECT: an IPv4 target leaves as an IPv4 target, an IPv6
target as IPv6, and a domain as the untouched hostname. The gateway never
re-classifies a target by inspecting its string and never resolves target
names itself — DNS resolution happens at the outbound SOCKS route.

This is what makes the gateway transparent for both client conventions that
the `socks5://` and `socks5h://` URL schemes name. They are not two protocols:
both send plain RFC 1928 SOCKS5, and the only wire difference is the CONNECT
frame's address type. A `socks5` client resolves the target itself and sends
ATYP `0x01`/`0x04`; a `socks5h` client sends the name as ATYP `0x03` and lets
the far end resolve. Either way, whatever address type arrives on ingress is
exactly what the selected outbound route receives.

## Replies

- Success: `05 00` with a zero BND.ADDR/BND.PORT. Clients must ignore the
  bound address; the gateway does not bind a local relay endpoint.
- No eligible route remains (`no_route`), the retry budget spent while
  eligible routes remained (`retry_exhausted`), and local setup errors: `05 01`
  (general failure), followed by a close.
- Unsupported command: `05 07`, followed by a close.
- Malformed or truncated frames — bad version, bad reserved byte, unknown
  ATYP, zero target port, implausible lengths — close the connection with no
  reply at all.

## Handshake deadline

A 30-second read deadline bounds the greeting, the RFC 1929 exchange when
`RPGW_ACCOUNT` is set, and the CONNECT request — the whole retry chain of
outbound attempts included. The success reply gets a fresh window, and the
deadline is cleared once the tunnel is established. Established tunnels have
no timeouts.

## Keep-alive

One client connection carries one `CONNECT`, i.e. one tunnel. Clients that
pool connections — for example HTTP clients speaking SOCKS5 — obtain one
tunnel per pooled connection and may reuse it across requests; tunnel scoping
is the client's choice. The gateway never buffers or inspects relayed bytes
and never terminates the client's tunnel; an upstream that breaks the tunnel
mid-stream closes the client connection, so a truncated stream stays visibly
truncated instead of reading as a clean end.
