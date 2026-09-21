// Package config validates bootstrap settings and parses runtime SOCKS routes.
package config

import (
	"errors"
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

// parseProxyLine accepts one of the three bare SOCKS5 forms: "host:port"
// without credentials, "host:port:user:pass", or "user:pass@host:port". The
// endpoint protocol is not configurable — every route is a SOCKS5 endpoint —
// so route lines carry no scheme, and anything containing "://" is rejected.
// The parsed URL carries the implicit socks5 scheme for the rest of the
// process. Bracketed IPv6 hosts are supported in all forms. Callers validate
// explicit ports and disallow URL paths, queries, and fragments after
// parsing.
func parseProxyLine(line string) (*url.URL, error) {
	if strings.Contains(line, "://") {
		return nil, errors.New("route proxy lines carry no scheme: the endpoint protocol is always SOCKS5 (forms: host:port, user:pass@host:port, host:port:user:pass)")
	}
	if strings.Contains(line, "@") {
		// "user:pass@host:port". Both credentials are required: a username
		// without a password (or an empty pair) is not one of the documented
		// forms, and an empty-but-present pair would dial without auth while
		// holding a route identity distinct from the bare host:port form.
		u, err := url.Parse("socks5://" + line)
		if err != nil {
			return nil, errors.New("invalid proxy URL")
		}
		if u.User == nil || u.User.Username() == "" {
			return nil, errors.New("proxy credentials must be user:pass@host:port")
		}
		if pass, ok := u.User.Password(); !ok || pass == "" {
			return nil, errors.New("proxy credentials must be user:pass@host:port")
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
	// "host:port" or "host:port:user:pass". The host may be a bracketed IPv6
	// literal such as "[2001:db8::1]:1080:user:pass".
	host, port, user, pass, ok := splitHostPortCreds(line)
	if !ok {
		return nil, errors.New("invalid proxy format (want host:port, user:pass@host:port, or host:port:user:pass)")
	}
	// The bare branches never run url.Parse, so screen the host characters
	// here: whitespace or URL separators would otherwise load as a route that
	// can only ever fail to dial.
	if strings.ContainsAny(host, " \t/?#%\\") {
		return nil, errors.New("invalid proxy format (want host:port, user:pass@host:port, or host:port:user:pass)")
	}
	if err := checkPort(port); err != nil {
		return nil, err
	}
	u := &url.URL{
		Scheme: "socks5",
		Host:   net.JoinHostPort(host, port),
	}
	if user != "" {
		u.User = url.UserPassword(user, pass)
	}
	return u, nil
}

// splitHostPortCreds splits bare "host:port" or "host:port:user:pass",
// accepting a bracketed IPv6 host. An absent credential pair returns empty
// user and pass. It reports false for any malformed shape.
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
	port, creds, hasCreds := strings.Cut(rest, ":")
	if port == "" {
		return "", "", "", "", false
	}
	if !hasCreds {
		// "host:port" — a route without credentials.
		return host, port, "", "", true
	}
	user, pass, ok = strings.Cut(creds, ":")
	if !ok || user == "" || pass == "" || strings.Contains(pass, ":") {
		return "", "", "", "", false
	}
	return host, port, user, pass, true
}

// CanonicalRouteID identifies a configured route for duplicate detection and
// reload state preservation. It preserves credentials so distinct credentials
// remain distinct, while normalizing scheme, host case (including IPv6), and
// the port's decimal form so equivalent spellings collapse to one identity.
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
	return strings.ToLower(u.Scheme) + "://" + creds + "@" + strings.ToLower(u.Hostname()) + ":" + normalizePort(u.Port())
}

// normalizePort canonicalizes a port to its decimal form, so "0080" and "80"
// are one identity. An unparseable port is returned unchanged; validated
// routes never reach that path.
func normalizePort(port string) string {
	if n, err := strconv.Atoi(port); err == nil {
		return strconv.Itoa(n)
	}
	return port
}

// checkPort validates a proxy port is numeric and in range without including a
// potentially credential-bearing pool entry in the error.
func checkPort(port string) error {
	// Static on purpose: the offending text sits in the credential position
	// of a mistyped bare line ("host:password"), so quoting it would leak
	// into boot and reload-reject logs. The route index in the wrapped error
	// names the line to fix.
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("invalid proxy port (want 1-65535)")
	}
	return nil
}
