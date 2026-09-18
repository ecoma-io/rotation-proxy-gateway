package proxyserver

import (
	"errors"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"proxy-auto-rotate-forwarder/internal/pool"
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

// logErrorValue returns bounded diagnostic context. It redacts URL userinfo so
// an error wrapped by a future dependency cannot accidentally disclose route
// credentials. Request headers and bodies never reach this function.
func logErrorValue(err error) string {
	if err == nil {
		return ""
	}

	var authErr *ProxyAuthError
	if errors.As(err, &authErr) {
		return cleanLogValue(authErr.Reason)
	}
	return cleanLogValue(redactURLUserinfo(err.Error()))
}

func cleanLogValue(value string) string {
	value = strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t':
			return ' '
		default:
			return r
		}
	}, value)
	if utf8.RuneCountInString(value) <= maxLogErrorLength {
		return value
	}
	return string([]rune(value)[:maxLogErrorLength]) + "…"
}

// redactURLUserinfo removes the userinfo portion from URLs embedded in error
// text. It operates on diagnostic text only; route identifiers always come
// from URL.Host before this point.
func redactURLUserinfo(value string) string {
	for searchFrom := 0; ; {
		schemeAt := strings.Index(value[searchFrom:], "://")
		if schemeAt < 0 {
			return value
		}
		schemeAt += searchFrom
		userinfoStart := schemeAt + len("://")
		remainder := value[userinfoStart:]
		at := strings.IndexByte(remainder, '@')
		if at < 0 {
			return value
		}
		at += userinfoStart
		if delimiter := strings.IndexAny(value[userinfoStart:at], "/?#\\\"'"); delimiter >= 0 {
			searchFrom = at + 1
			continue
		}
		value = value[:userinfoStart] + "[redacted]@" + value[at+1:]
		searchFrom = userinfoStart + len("[redacted]@")
	}
}
