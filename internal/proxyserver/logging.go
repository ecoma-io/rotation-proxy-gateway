package proxyserver

import (
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"proxy-auto-rotate-forwarder/internal/pool"
	"proxy-auto-rotate-forwarder/internal/sanitize"
)

const maxLogErrorLength = 512

const (
	errorKindProxyConnect = "proxy_connect"
	errorKindAuthRoute    = "auth_route"
	errorKindSetup        = "setup"
	errorKindNoRoute      = "no_route"
)

// upstreamLogValue returns the redacted route identity used in logs. URL.Host
// excludes URL userinfo; never replace this with URL.String.
func upstreamLogValue(p *pool.Proxy) string {
	if p == nil || p.URL == nil {
		return "none"
	}
	return cleanLogValue(p.URL.Host)
}

// httpTargetLogValue returns only the HTTP target host or host:port. It
// deliberately excludes URL userinfo, paths, queries, and fragments.
func httpTargetLogValue(u *url.URL) string {
	if u == nil || u.Hostname() == "" {
		return "unknown"
	}
	if port := u.Port(); port != "" {
		return cleanLogValue(net.JoinHostPort(u.Hostname(), port))
	}
	return cleanLogValue(u.Hostname())
}

// tunnelTargetLogValue keeps only a CONNECT target's normalized host:port.
func tunnelTargetLogValue(target string) string {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return cleanLogValue(dropUserinfo(target))
	}
	return cleanLogValue(net.JoinHostPort(dropUserinfo(host), port))
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

func bodyLogMode(streamMode bool) string {
	if streamMode {
		return "streamed"
	}
	return "replayable"
}

func logErrorKind(err error) string {
	switch {
	case isProxyDialError(err):
		return errorKindProxyConnect
	case isProxyAuthError(err):
		return errorKindAuthRoute
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

// redactURLUserinfo is retained as a thin wrapper over the shared sanitizer
// so any external callers keep working.
func redactURLUserinfo(value string) string {
	return sanitize.Sanitize(value)
}
