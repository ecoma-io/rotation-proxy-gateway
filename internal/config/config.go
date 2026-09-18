// Package config loads runtime configuration from environment variables and
// parses the upstream proxy pool file. Empty environment values are treated as
// unset.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultListenAddr     = ":8080"
	DefaultAdminAddr      = "127.0.0.1:8081"
	DefaultProxiesFile    = "proxies.txt"
	DefaultMaxRetries     = 3
	DefaultCooldownBase   = 15 * time.Second
	DefaultCooldownMax    = 10 * time.Minute
	DefaultConnectTimeout = 10 * time.Second
	DefaultMaxBodyBuffer  = 64 << 20 // 64 MiB
)

// Config is the full runtime configuration.
type Config struct {
	ListenAddr        string
	AdminAddr         string // admin listener (health, status); always on
	ProxiesFile       string
	MaxRetries        int
	CooldownBase      time.Duration
	CooldownMax       time.Duration
	ConnectTimeout    time.Duration
	TargetTLSInsecure bool
	MaxBodyBuffer     int64
	LogLevel          string
}

// Load applies defaults, then overrides them from the process environment.
// Malformed values produce errors.
func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:        DefaultListenAddr,
		AdminAddr:         DefaultAdminAddr,
		ProxiesFile:       DefaultProxiesFile,
		MaxRetries:        DefaultMaxRetries,
		CooldownBase:      DefaultCooldownBase,
		CooldownMax:       DefaultCooldownMax,
		ConnectTimeout:    DefaultConnectTimeout,
		TargetTLSInsecure: false,
		MaxBodyBuffer:     DefaultMaxBodyBuffer,
		LogLevel:          "info",
	}

	var errs []error
	envStr("LISTEN_ADDR", &cfg.ListenAddr)
	envStr("ADMIN_ADDR", &cfg.AdminAddr)
	envStr("PROXIES_FILE", &cfg.ProxiesFile)
	envStr("LOG_LEVEL", &cfg.LogLevel)
	errs = append(errs,
		envInt("MAX_RETRIES", &cfg.MaxRetries),
		envDuration("COOLDOWN_BASE", &cfg.CooldownBase),
		envDuration("COOLDOWN_MAX", &cfg.CooldownMax),
		envDuration("CONNECT_TIMEOUT", &cfg.ConnectTimeout),
		envInt64("MAX_BODY_BUFFER", &cfg.MaxBodyBuffer),
		envBool("TARGET_TLS_INSECURE", &cfg.TargetTLSInsecure),
	)
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	var errs []error
	if c.MaxRetries < 1 {
		errs = append(errs, fmt.Errorf("MAX_RETRIES must be >= 1, got %d", c.MaxRetries))
	}
	if c.CooldownBase <= 0 {
		errs = append(errs, fmt.Errorf("COOLDOWN_BASE must be positive, got %s", c.CooldownBase))
	}
	if c.CooldownMax <= 0 {
		errs = append(errs, fmt.Errorf("COOLDOWN_MAX must be positive, got %s", c.CooldownMax))
	}
	if c.CooldownBase > 0 && c.CooldownMax > 0 && c.CooldownBase > c.CooldownMax {
		errs = append(errs, fmt.Errorf("COOLDOWN_BASE %s must not exceed COOLDOWN_MAX %s", c.CooldownBase, c.CooldownMax))
	}
	if c.ConnectTimeout <= 0 {
		errs = append(errs, fmt.Errorf("CONNECT_TIMEOUT must be positive, got %s", c.ConnectTimeout))
	}
	if c.MaxBodyBuffer < 0 {
		errs = append(errs, fmt.Errorf("MAX_BODY_BUFFER must be >= 0, got %d", c.MaxBodyBuffer))
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("LOG_LEVEL must be one of debug, info, warn, error, got %q", c.LogLevel))
	}
	if c.AdminAddr == c.ListenAddr {
		errs = append(errs, fmt.Errorf("ADMIN_ADDR %q must differ from LISTEN_ADDR %q", c.AdminAddr, c.ListenAddr))
	}
	return errors.Join(errs...)
}

func envStr(key string, dst *string) {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		*dst = v
	}
}

// envAddr permits an explicit empty value so a bootstrap proxy listener can be
// disabled, unlike the legacy envStr convention where empty means unset.
func envAddr(key string, dst *string) {
	if v, ok := os.LookupEnv(key); ok {
		*dst = v
	}
}

func envInt(key string, dst *int) error {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	*dst = n
	return nil
}

func envInt64(key string, dst *int64) error {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	*dst = n
	return nil
}

func envDuration(key string, dst *time.Duration) error {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	*dst = d
	return nil
}

func envBool(key string, dst *bool) error {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	*dst = b
	return nil
}

var validSchemes = map[string]bool{"socks5": true}

// ParseProxies reads the SOCKS5 pool file: one upstream per line, blank lines
// and #-comments ignored. Each line is a socks5:// URL or either bare form
// "host:port:user:pass" / "user:pass@host:port", both interpreted as SOCKS5.
// Every route must carry an explicit port, must not carry a URL path, query,
// or fragment, and must be unique by canonical route identity (scheme,
// lowercase host, port, and credentials). It returns an error if any line is
// invalid or if the file yields no proxies.
func ParseProxies(path string) ([]*url.URL, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var (
		entries []*url.URL
		errs    []error
		seen    = make(map[string]int)
	)
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, err := parseProxyLine(line)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s line %d: %w", path, lineNo, err))
		case !validSchemes[u.Scheme]:
			errs = append(errs, fmt.Errorf("%s line %d: unsupported scheme %q (want socks5://..., host:port:user:pass, or user:pass@host:port)", path, lineNo, u.Scheme))
		case u.Hostname() == "":
			errs = append(errs, fmt.Errorf("%s line %d: missing host", path, lineNo))
		case u.Port() == "":
			errs = append(errs, fmt.Errorf("%s line %d: missing port (want host:port)", path, lineNo))
		case u.Path != "" || u.RawQuery != "" || u.Fragment != "":
			errs = append(errs, fmt.Errorf("%s line %d: proxy URL path, query, and fragment are not supported", path, lineNo))
		default:
			if err := checkPort(u.Port()); err != nil {
				errs = append(errs, fmt.Errorf("%s line %d: %w", path, lineNo, err))
				continue
			}
			id := canonicalRouteID(u)
			if first, dup := seen[id]; dup {
				errs = append(errs, fmt.Errorf("%s line %d: duplicate proxy route (first on line %d)", path, lineNo, first))
				continue
			}
			seen[id] = lineNo
			entries = append(entries, u)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%s: no proxies found", path)
	}
	return entries, nil
}

// parseProxyLine accepts a socks5:// URL or either bare SOCKS5 form:
// "host:port:user:pass" or "user:pass@host:port". Bracketed IPv6 hosts are
// supported in all forms. Explicit ports and empty URL path/query/fragment are
// enforced by ParseProxies; here bare "user:pass@host:port" callers get an
// early missing-port error so the failure is attributed to the right line.
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

// canonicalRouteID identifies a configured route for duplicate detection. It
// preserves credentials so distinct credentials remain distinct, while
// normalizing scheme case and host case (including IPv6) so equivalent spellings
// collapse to one identity.
func canonicalRouteID(u *url.URL) string {
	var creds string
	if u.User != nil {
		if pw, has := u.User.Password(); has {
			creds = u.User.Username() + ":" + pw
		} else {
			creds = u.User.Username()
		}
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
