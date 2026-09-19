// Package config validates bootstrap settings and parses runtime SOCKS routes.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

func envStr(key string, dst *string) {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		*dst = v
	}
}

// envAddr permits an explicit empty value so a bootstrap proxy listener can be
// disabled, unlike envStr where empty means unset.
func envAddr(key string, dst *string) {
	if v, ok := os.LookupEnv(key); ok {
		*dst = v
	}
}

var validSchemes = map[string]bool{"socks5": true}

// parseProxyLine accepts a socks5:// URL or either bare SOCKS5 form:
// "host:port:user:pass" or "user:pass@host:port". Bracketed IPv6 hosts are
// supported in all forms. Callers validate explicit ports and disallow URL
// paths, queries, and fragments after parsing.
func parseProxyLine(line string) (*url.URL, error) {
	if strings.Contains(line, "://") {
		u, err := url.Parse(line)
		if err != nil {
			return nil, errors.New("invalid proxy URL")
		}
		u.Scheme = strings.ToLower(u.Scheme)
		return u, nil
	}
	if strings.Contains(line, "@") {
		// Bare "user:pass@host:port" defaults to SOCKS5.
		u, err := url.Parse("socks5://" + line)
		if err != nil {
			return nil, errors.New("invalid proxy URL")
		}
		if u.Hostname() == "" {
			return nil, errors.New("proxy host is required")
		}
		if u.Port() == "" {
			return nil, errors.New("proxy port is required (want host:port)")
		}
		if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return nil, errors.New("proxy URL path, query, and fragment are not supported")
		}
		if err := checkPort(u.Port()); err != nil {
			return nil, err
		}
		return u, nil
	}
	// Bare "host:port:user:pass" defaults to SOCKS5. The host may be a
	// bracketed IPv6 literal such as "[2001:db8::1]:1080:user:pass".
	host, port, user, pass, ok := splitHostPortCreds(line)
	if !ok {
		return nil, errors.New("invalid proxy format (want socks5://..., host:port:user:pass, or user:pass@host:port)")
	}
	if err := checkPort(port); err != nil {
		return nil, err
	}
	return &url.URL{
		Scheme: "socks5",
		User:   url.UserPassword(user, pass),
		Host:   net.JoinHostPort(host, port),
	}, nil
}

// splitHostPortCreds splits bare "host:port:user:pass", accepting a bracketed
// IPv6 host. It reports false for any malformed shape.
func splitHostPortCreds(line string) (host, port, user, pass string, ok bool) {
	rest := line
	if strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "]")
		if end < 0 {
			return "", "", "", "", false
		}
		host = rest[1:end]
		rest = rest[end+1:]
		if !strings.HasPrefix(rest, ":") || host == "" {
			return "", "", "", "", false
		}
		rest = rest[1:]
	} else {
		var found bool
		host, rest, found = strings.Cut(rest, ":")
		if !found || host == "" || strings.Contains(host, ":") {
			return "", "", "", "", false
		}
	}
	port, rest, ok = strings.Cut(rest, ":")
	if !ok || port == "" || rest == "" {
		return "", "", "", "", false
	}
	user, pass, ok = strings.Cut(rest, ":")
	if !ok || user == "" || pass == "" || strings.Contains(pass, ":") {
		return "", "", "", "", false
	}
	return host, port, user, pass, true
}

// CanonicalRouteID identifies a configured route for duplicate detection and
// reload state preservation. It preserves credentials so distinct credentials
// remain distinct, while normalizing scheme and host case (including IPv6) so
// equivalent spellings collapse to one identity.
func CanonicalRouteID(u *url.URL) string {
	var creds string
	if u.User != nil {
		// Re-encode rather than concatenate the decoded user and password:
		// the raw form keeps separator characters escaped ("%3A", "%40"),
		// so a no-password username "u:v" can never collapse onto the
		// username/password pair "u"/"v" (or any similar pair) the way a
		// plain user + ":" + password concatenation does.
		creds = u.User.String()
	}
	return strings.ToLower(u.Scheme) + "://" + creds + "@" + strings.ToLower(u.Hostname()) + ":" + u.Port()
}

// checkPort validates a proxy port is numeric and in range without including a
// potentially credential-bearing pool entry in the error.
func checkPort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid proxy port %q", port)
	}
	return nil
}
