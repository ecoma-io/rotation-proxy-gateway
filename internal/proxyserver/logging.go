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
	errorKindProxyConnect  = "proxy_connect"
	errorKindAuthRoute     = "auth_route"
	errorKindSocksConnect  = "socks_connect"
	errorKindConnectTarget = "connect_target"
	errorKindSetup         = "setup"
	errorKindNoRoute       = "no_route"
)

// upstreamLogValue returns the redacted route identity used in logs. URL.Host
// excludes URL userinfo; never replace this with URL.String.
func upstreamLogValue(p *pool.Proxy) string {
	if p == nil || p.URL == nil {
		return "none"
	}
	return cleanLogValue(p.URL.Host)
}

// socksTargetLogValue keeps only a SOCKS target's normalized host:port.
func socksTargetLogValue(target string) string {
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

// socksRejectLogValue bounds and sanitizes a protocol-reject reason. Reject
// errors are constructed locally from framing bytes; the sanitizer is the
// single defense keeping any odd byte sequence out of logs.
func socksRejectLogValue(err error) string {
	if err == nil {
		return ""
	}
	return sanitize.ErrorString(err)
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
