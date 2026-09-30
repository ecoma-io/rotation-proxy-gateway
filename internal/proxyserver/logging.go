package proxyserver

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/sanitize"
)

const maxLogErrorLength = 512

const (
	errorKindProxyConnect   = "proxy_connect"
	errorKindAuthRoute      = "auth_route"
	errorKindSocksConnect   = "socks_connect"
	errorKindConnectTarget  = "connect_target"
	errorKindSetup          = "setup"
	errorKindNoRoute        = "no_route"
	errorKindRetryExhausted = "retry_exhausted"
)

// Error-kind HTTP status mapping is intentionally adjacent to the stable log
// vocabulary rather than folded into logErrorKind: logs describe the precise
// event that occurred, while a client can receive one status only after every
// allowed fallback has ended. `setup` is split at ingress: malformed client HTTP
// is rejected before route selection as 400; a selected-route local setup error
// is ours and therefore 502. A rejected HTTP version is 505 before selection.
//
//   error_kind                                             terminal status
//   proxy_connect, socks_connect, auth_route, connect_target 502 Bad Gateway
//   no_route, retry_exhausted                                503 Service Unavailable
//   setup (gateway-side after valid selection)               502 Bad Gateway
//   setup (malformed client frame before selection)           400 Bad Request
//   http_version_not_supported                               505 HTTP Version Not Supported
//
// The table is a public wire contract; do not change logErrorKind values to
// smuggle a response distinction into observability.

// upstreamLogValue returns the redacted route identity used in logs. URL.Host
// excludes URL userinfo; never replace this with URL.String.
func upstreamLogValue(p *pool.Proxy) string {
	if p == nil || p.URL == nil {
		return "none"
	}
	return cleanLogValue(p.URL.Host)
}

// targetLogValue keeps only an inbound HTTP target's normalized host:port.
// The outbound hop remains SOCKS5H, but the target came from HTTP authority
// syntax and this boundary must stay oblivious to either protocol's framing.
func targetLogValue(target string) string {
	host, port, err := net.SplitHostPort(target)
	if err != nil || !validPortNumber(port) {
		// SplitHostPort "succeeds" on any colon (e.g. a userinfo-shaped
		// "user:pass@host" target with no real port); only a numeric port
		// proves the split is real. Anything else falls back to the
		// userinfo-stripping path, the only credential defense on
		// scheme-less targets.
		return cleanLogValue(dropUserinfo(target))
	}
	return cleanLogValue(net.JoinHostPort(dropUserinfo(host), port))
}

func validPortNumber(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}

func dropUserinfo(value string) string {
	if at := strings.LastIndexByte(value, '@'); at >= 0 {
		return value[at+1:]
	}
	return value
}

func logDuration(duration time.Duration) string {
	return duration.Truncate(time.Millisecond).String()
}

func logErrorKind(err error) string {
	switch {
	case isProxyDialError(err):
		return errorKindProxyConnect
	case isProxyAuthError(err):
		return errorKindAuthRoute
	case isConnectTargetError(err):
		return errorKindConnectTarget
	case isSocksHandshakeError(err):
		return errorKindSocksConnect
	default:
		return errorKindSetup
	}
}

// logErrorValue returns bounded diagnostic context via the shared sanitizer.
// Auth reasons are sanitized (never raw): a future dependency or caller must
// not be able to disclose route credentials through the reason string.
// Request headers and bodies never reach this function.
func logErrorValue(err error) string {
	if err == nil {
		return ""
	}

	var authErr *ProxyAuthError
	if errors.As(err, &authErr) {
		return sanitize.Sanitize(authErrorSafeText(authErr))
	}
	return sanitize.ErrorString(err)
}

// authErrorSafeText maps internal SOCKS auth reasons to fixed safe strings.
// The three reasons below are the only ProxyAuthError values constructed by
// dialSocks5; anything else (e.g. a future wrapped error carrying secrets)
// falls back to a fixed label so raw text is never logged.
func authErrorSafeText(err *ProxyAuthError) string {
	switch err.Reason {
	case "endpoint requires credentials but none are configured":
		return "endpoint requires credentials but none are configured"
	case "endpoint rejected credentials":
		return "endpoint rejected credentials"
	case "endpoint accepted no offered authentication method":
		return "endpoint accepted no offered authentication method"
	default:
		return "SOCKS authentication failed"
	}
}

// cleanLogValue keeps the historical host-only log helper on the shared
// sanitizer. maxLogErrorLength is retained for the existing test bound.
func cleanLogValue(value string) string {
	return sanitize.Sanitize(value)
}

// maxInboundRequestIDLength bounds an accepted client correlation id. It is
// deliberately far below both the 1 MiB inbound header bound and the
// sanitizer's 512-rune cap: a correlation id is a short opaque token, and a
// tighter bound is what keeps an untrusted value from becoming an unbounded,
// repeatedly written log field. A value past the bound is not an error — it is
// replaced by a generated id, because the request is still perfectly
// serviceable and only the client's own token was mismeasured.
const maxInboundRequestIDLength = 64

// requestIDAlphabet is the grammar an accepted client id must match: one
// printable, unquoted token. The restriction is not cosmetic. zerolog escapes
// control characters and quotes in a string field, so a hostile id cannot forge
// a log line — but it can still make one unreadable, and a correlation id that
// needs a log reader to unpick is worth nothing. Accepting only a token-shaped
// word keeps every line greppable and leaves no reader guessing whether a
// field was quoted by the encoder or by the client. The empty value is outside
// the grammar: `for range 0` never runs, so an empty id is not a token.
const requestIDAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:"

// requestIDPrefix marks a gateway-minted id, so an operator can tell a
// correlation the client vouched for from one this process invented. A client
// may use the prefix itself; that is its own choice and harmless. The generated
// form is otherwise the same shape as an accepted one — same length class, same
// alphabet, no quoting — so a log reader distinguishes them by the prefix, never
// by the form.
const requestIDPrefix = "r"

// generatedRequestIDBytes is the entropy behind a generated id: 128 bits
// rendered base32 without padding, 26 characters, case-insensitive in a log.
const generatedRequestIDBytes = 16

// requestIDGenDegraded is the marker in an id minted while the CSPRNG is
// unavailable. It names the degradation instead of hiding it: an operator
// correlating a degraded window should be able to see it. The counter that
// follows keeps those ids unique per process, so correlation still works —
// which is the id's entire purpose — even when the entropy source is broken.
const requestIDGenDegraded = "nogorand"

// degradedRequestIDs counts ids minted while the CSPRNG is broken, so even the
// degraded ids stay unique within one process.
var degradedRequestIDs atomic.Uint64

// resolveRequestID returns the correlation id one request's log lines carry.
// It is resolved once per request, before route selection, and the same value
// is threaded through that request's whole attempt chain — one request, one id,
// however many routes were tried. Resolving it here rather than inside the
// chain is what makes that true by construction: no retry path can re-resolve
// or re-mint it.
//
// A client id is accepted only when it is exactly one occurrence, at or under
// the size bound, and inside the token grammar. Anything else — absent,
// repeated, over-long, quoted, whitespace-bearing, or carrying a control
// character or an ANSI sequence — is replaced by a freshly generated id rather
// than refused. Refusing would fail a serviceable request over a diagnostic
// header the client loses nothing by dropping; accepting an unsanitized value
// would put an untrusted string into every log line of its chain. Minting
// instead keeps the field bounded and single-line by construction, and the
// client still gets correlation whenever its id was actually safe to echo.
//
// This is deliberately not the value of the `request_id` counter. That counter
// must keep counting valid requests that reached route selection — it is what
// the per-listener /status `requests` figure is — so it cannot take a
// client-controlled string without destroying the metric's meaning. The two
// travel together on the session logger instead: `request_id` is the
// process-local ordinal, `correlation_id` is the client's token or its minted
// replacement.
func resolveRequestID(header http.Header) string {
	values := header.Values(headerRequestID)
	if len(values) != 1 {
		return generateRequestID()
	}
	supplied := values[0]
	if len(supplied) == 0 || len(supplied) > maxInboundRequestIDLength || !isRequestIDToken(supplied) {
		return generateRequestID()
	}
	return supplied
}

// isRequestIDToken reports whether every byte is inside the token alphabet.
// Byte-wise is correct because the bound is a byte bound: a multi-byte rune is
// accepted only when each of its bytes is a plain ASCII character, so a partial
// match of one rune's bytes can never look complete.
func isRequestIDToken(value string) bool {
	for i := range len(value) {
		if strings.IndexByte(requestIDAlphabet, value[i]) < 0 {
			return false
		}
	}
	return true
}

// generateRequestID mints a correlation id for a request that supplied none
// this process is willing to echo. crypto/rand is the sole entropy source; the
// semgrep security gate rejects every math/rand variant, v2 included.
func generateRequestID() string {
	var raw [generatedRequestIDBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return requestIDPrefix + "-" + requestIDGenDegraded + "-" + strconv.FormatUint(degradedRequestIDs.Add(1), 10)
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:])
	return requestIDPrefix + "-" + encoded
}
