package proxyserver

import (
	"errors"
	"net"
	"strconv"
	"strings"
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
