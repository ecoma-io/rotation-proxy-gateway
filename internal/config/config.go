// Package config loads runtime configuration from environment variables
// (with an optional .env file for local runs) and parses the upstream proxy
// pool file. Empty environment values are treated as unset.
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

// RotateMode selects how the pool walks its entries.
type RotateMode string

const (
	RoundRobin RotateMode = "round-robin"
	Random     RotateMode = "random"
)

const (
	DefaultListenAddr     = ":8080"
	DefaultAdminAddr      = "127.0.0.1:8081"
	DefaultProxiesFile    = "configs/proxies.txt"
	DefaultMaxRetries     = 3
	DefaultCooldownBase   = 15 * time.Second
	DefaultCooldownMax    = 10 * time.Minute
	DefaultConnectTimeout = 10 * time.Second
	DefaultMaxBodyBuffer  = 64 << 20 // 64 MiB
)

// Config is the full runtime configuration.
type Config struct {
	ListenAddr          string
	AdminAddr           string // admin listener (health, status); always on
	ProxiesFile         string
	Mode                RotateMode
	MaxRetries          int
	CooldownBase        time.Duration
	CooldownMax         time.Duration
	ConnectTimeout      time.Duration
	UpstreamTLSInsecure bool
	MaxBodyBuffer       int64
	LogLevel            string
}

// Load applies defaults, reads the optional .env from the working directory,
// then overrides from the environment. Malformed values produce errors.
func Load() (*Config, error) {
	_ = loadDotEnv(".env")

	cfg := &Config{
		ListenAddr:          DefaultListenAddr,
		AdminAddr:           DefaultAdminAddr,
		ProxiesFile:         DefaultProxiesFile,
		Mode:                RoundRobin,
		MaxRetries:          DefaultMaxRetries,
		CooldownBase:        DefaultCooldownBase,
		CooldownMax:         DefaultCooldownMax,
		ConnectTimeout:      DefaultConnectTimeout,
		UpstreamTLSInsecure: false,
		MaxBodyBuffer:       DefaultMaxBodyBuffer,
		LogLevel:            "info",
	}

	var errs []error
	envStr("LISTEN_ADDR", &cfg.ListenAddr)
	envStr("ADMIN_ADDR", &cfg.AdminAddr)
	envStr("PROXIES_FILE", &cfg.ProxiesFile)
	envStr("LOG_LEVEL", &cfg.LogLevel)
	if v, ok := os.LookupEnv("ROTATE_MODE"); ok && v != "" {
		cfg.Mode = RotateMode(v)
	}
	errs = append(errs,
		envInt("MAX_RETRIES", &cfg.MaxRetries),
		envDuration("COOLDOWN_BASE", &cfg.CooldownBase),
		envDuration("COOLDOWN_MAX", &cfg.CooldownMax),
		envDuration("CONNECT_TIMEOUT", &cfg.ConnectTimeout),
		envInt64("MAX_BODY_BUFFER", &cfg.MaxBodyBuffer),
		envBool("UPSTREAM_TLS_INSECURE", &cfg.UpstreamTLSInsecure),
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
	switch c.Mode {
	case RoundRobin, Random:
	default:
		errs = append(errs, fmt.Errorf("ROTATE_MODE must be %q or %q, got %q", RoundRobin, Random, c.Mode))
	}
	if c.MaxRetries < 1 {
		errs = append(errs, fmt.Errorf("MAX_RETRIES must be >= 1, got %d", c.MaxRetries))
	}
	if c.CooldownBase <= 0 {
		errs = append(errs, fmt.Errorf("COOLDOWN_BASE must be positive, got %s", c.CooldownBase))
	}
	if c.CooldownMax <= 0 {
		errs = append(errs, fmt.Errorf("COOLDOWN_MAX must be positive, got %s", c.CooldownMax))
	}
	if c.ConnectTimeout <= 0 {
		errs = append(errs, fmt.Errorf("CONNECT_TIMEOUT must be positive, got %s", c.ConnectTimeout))
	}
	if c.MaxBodyBuffer < 0 {
		errs = append(errs, fmt.Errorf("MAX_BODY_BUFFER must be >= 0, got %d", c.MaxBodyBuffer))
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

// loadDotEnv reads KEY=VALUE lines into the environment without overriding
// variables that are already set. Missing file is not an error.
func loadDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" {
			continue
		}
		if _, exists := os.LookupEnv(k); !exists {
			_ = os.Setenv(k, v)
		}
	}
	return sc.Err()
}

var validSchemes = map[string]bool{"http": true, "https": true, "socks5": true}

// ParseProxies reads the pool file: one upstream proxy per line, blank lines
// and #-comments ignored. Each line is either a full proxy URL
// ("http://user:pass@host:port", "socks5://host:port") or the legacy bare
// form "host:port:user:pass" (treated as HTTP). It returns an error if any
// line is invalid or if the file yields no proxies.
func ParseProxies(path string) ([]*url.URL, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var (
		entries []*url.URL
		errs    []error
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
			errs = append(errs, fmt.Errorf("%s line %d: unsupported scheme %q (want http, https or socks5)", path, lineNo, u.Scheme))
		case u.Hostname() == "":
			errs = append(errs, fmt.Errorf("%s line %d: missing host", path, lineNo))
		default:
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

// parseProxyLine accepts a full proxy URL ("http://user:pass@host:port") or
// either legacy bare form: "host:port:user:pass" or "user:pass@host:port"
// (both treated as HTTP with Basic auth).
func parseProxyLine(line string) (*url.URL, error) {
	if strings.Contains(line, "://") {
		return url.Parse(line)
	}
	if strings.Contains(line, "@") {
		// Legacy "user:pass@host:port" (no scheme) — treat as HTTP.
		u, err := url.Parse("http://" + line)
		if err != nil {
			return nil, fmt.Errorf("bad proxy %q: %w", line, err)
		}
		if u.Hostname() == "" {
			return nil, fmt.Errorf("bad proxy %q: missing host", line)
		}
		if err := checkPort(u.Port(), line); err != nil {
			return nil, err
		}
		return u, nil
	}
	// Legacy "host:port:user:pass" (no scheme) — treat as HTTP.
	host, rest, ok := strings.Cut(line, ":")
	if !ok || host == "" {
		return nil, fmt.Errorf("bad proxy %q (want scheme://..., host:port:user:pass or user:pass@host:port)", line)
	}
	port, creds, ok := strings.Cut(rest, ":")
	if !ok || port == "" || creds == "" {
		return nil, fmt.Errorf("bad proxy %q (want scheme://..., host:port:user:pass or user:pass@host:port)", line)
	}
	user, pass, ok := strings.Cut(creds, ":")
	if !ok || user == "" || pass == "" || strings.Contains(pass, ":") {
		return nil, fmt.Errorf("bad proxy %q (want scheme://..., host:port:user:pass or user:pass@host:port)", line)
	}
	if err := checkPort(port, line); err != nil {
		return nil, err
	}
	return &url.URL{
		Scheme: "http",
		User:   url.UserPassword(user, pass),
		Host:   net.JoinHostPort(host, port),
	}, nil
}

// checkPort validates a proxy port is numeric and in range.
func checkPort(port, line string) error {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("bad proxy %q: invalid port %q", line, port)
	}
	return nil
}
