package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	DefaultConfigFile       = "config.yaml"
	DefaultRuntimeAdminAddr = "0.0.0.0:30120"
	DefaultMixedListenAddr  = ":30121"
	DefaultV4ListenAddr     = ":30122"
	DefaultV6ListenAddr     = ":30123"
	// DefaultShutdownGrace is one shared drain budget for the whole process:
	// every enabled proxy listener plus the admin listener. 55s fits under a
	// 60s docker stop_grace_period and a 90s systemd TimeoutStopSec.
	DefaultShutdownGrace = 55 * time.Second
)

// EgressKind is the public IP family supplied by an upstream proxy provider.
// It does not describe the SOCKS endpoint's network address or the target
// address family requested by a client.
type EgressKind string

const (
	EgressV4 EgressKind = "v4"
	EgressV6 EgressKind = "v6"
)

// RouteSpec is one validated static SOCKS route from the runtime config.
type RouteSpec struct {
	URL  *url.URL
	Kind EgressKind
}

// BootstrapConfig contains process-level settings. They are intentionally read
// only when the process starts because changing a listening socket or watched
// file in place would require a coordinated server restart.
type BootstrapConfig struct {
	ConfigFile      string
	AdminAddr       string
	MixedListenAddr string
	V4ListenAddr    string
	V6ListenAddr    string
	// ShutdownGrace bounds the entire graceful drain: one shared deadline for
	// all listeners, not a per-listener window.
	ShutdownGrace time.Duration
}

// RuntimeConfig is the immutable set of values used by new client operations.
// Callers must replace the entire value on reload rather than mutate it.
type RuntimeConfig struct {
	MaxRetries        int
	CooldownBase      time.Duration
	CooldownMax       time.Duration
	DialTimeout       time.Duration
	TargetTLSInsecure bool
	MaxBodyBuffer     int64
	LogLevel          string
	Routes            []RouteSpec
}

type fileConfig struct {
	LogLevel    string             `mapstructure:"log-level"`
	MaxRetries  int                `mapstructure:"max-retries"`
	Cooldown    cooldownFileConfig `mapstructure:"cooldown"`
	DialTimeout string             `mapstructure:"dial-timeout"`
	Global      globalFileConfig   `mapstructure:"global"`
	Proxies     proxiesFileConfig  `mapstructure:"proxies"`
}

type cooldownFileConfig struct {
	Base string `mapstructure:"base"`
	Max  string `mapstructure:"max"`
}

type globalFileConfig struct {
	TargetTLSInsecure bool  `mapstructure:"target-tls-insecure"`
	MaxBodyBuffer     int64 `mapstructure:"max-body-buffer"`
}

type proxiesFileConfig struct {
	Auto   []autoProxyFileConfig `mapstructure:"auto"`
	Manual any                   `mapstructure:"manual"`
}

type autoProxyFileConfig struct {
	Proxy string `mapstructure:"proxy"`
	Kind  string `mapstructure:"kind"`
}

// LoadBootstrap applies bootstrap defaults and explicit environment overrides.
// An explicit empty proxy listener address disables that listener; other empty
// bootstrap values retain their defaults.
func LoadBootstrap() (*BootstrapConfig, error) {
	cfg := &BootstrapConfig{
		ConfigFile:      DefaultConfigFile,
		AdminAddr:       DefaultRuntimeAdminAddr,
		MixedListenAddr: DefaultMixedListenAddr,
		V4ListenAddr:    DefaultV4ListenAddr,
		V6ListenAddr:    DefaultV6ListenAddr,
		ShutdownGrace:   DefaultShutdownGrace,
	}
	envStr("CONFIG_FILE", &cfg.ConfigFile)
	envStr("ADMIN_ADDR", &cfg.AdminAddr)
	envAddr("MIXED_LISTEN_ADDR", &cfg.MixedListenAddr)
	envAddr("V4_LISTEN_ADDR", &cfg.V4ListenAddr)
	envAddr("V6_LISTEN_ADDR", &cfg.V6ListenAddr)
	// Parsed inline rather than through a helper so a malformed value fails
	// fast instead of silently falling back to the default.
	if raw, ok := os.LookupEnv("SHUTDOWN_GRACE"); ok && raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return nil, fmt.Errorf("SHUTDOWN_GRACE %q must be a Go duration", raw)
		}
		cfg.ShutdownGrace = d
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *BootstrapConfig) validate() error {
	var errs []error
	if strings.TrimSpace(c.ConfigFile) == "" {
		errs = append(errs, errors.New("CONFIG_FILE must not be empty"))
	}
	if c.ShutdownGrace <= 0 {
		errs = append(errs, fmt.Errorf("SHUTDOWN_GRACE must be positive, got %s", c.ShutdownGrace))
	}
	if c.MixedListenAddr == "" && c.V4ListenAddr == "" && c.V6ListenAddr == "" {
		errs = append(errs, errors.New("at least one proxy listener must be enabled"))
	}

	listeners := []struct {
		name string
		addr string
	}{
		{"ADMIN_ADDR", c.AdminAddr},
		{"MIXED_LISTEN_ADDR", c.MixedListenAddr},
		{"V4_LISTEN_ADDR", c.V4ListenAddr},
		{"V6_LISTEN_ADDR", c.V6ListenAddr},
	}
	for i, listener := range listeners {
		if listener.addr == "" && listener.name != "ADMIN_ADDR" {
			continue
		}
		if err := validateListenAddr(listener.name, listener.addr); err != nil {
			errs = append(errs, err)
			continue
		}
		for _, other := range listeners[:i] {
			if other.addr == "" && other.name != "ADMIN_ADDR" {
				continue
			}
			if listenersOverlap(listener.addr, other.addr) {
				errs = append(errs, fmt.Errorf("%s %q must not overlap %s %q", listener.name, listener.addr, other.name, other.addr))
			}
		}
	}
	return errors.Join(errs...)
}

func validateListenAddr(name, addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s %q must be a host:port address", name, addr)
	}
	if err := checkPort(port); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return nil
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if !validListenerHostname(host) {
		return fmt.Errorf("%s %q has an invalid host", name, addr)
	}
	return nil
}

func validListenerHostname(host string) bool {
	if len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func listenersOverlap(left, right string) bool {
	leftHost, leftPort, leftErr := net.SplitHostPort(left)
	rightHost, rightPort, rightErr := net.SplitHostPort(right)
	if leftErr != nil || rightErr != nil || leftPort != rightPort {
		return false
	}
	if isWildcardHost(leftHost) || isWildcardHost(rightHost) {
		return true
	}
	return strings.EqualFold(leftHost, rightHost)
}

func isWildcardHost(host string) bool {
	return host == "" || host == "0.0.0.0" || host == "::"
}

// LoadRuntime reads and strictly validates the YAML runtime config at path.
// It creates an isolated Viper instance for every load so test and reload state
// cannot leak through Viper's package-global configuration.
func LoadRuntime(path string, bootstrap *BootstrapConfig) (*RuntimeConfig, error) {
	v, err := newViper(path)
	if err != nil {
		return nil, err
	}
	var raw fileConfig
	if err := v.UnmarshalExact(&raw); err != nil {
		return nil, fmt.Errorf("decode runtime config: %w", err)
	}
	cfg, err := runtimeFromFile(raw)
	if err != nil {
		return nil, err
	}
	if bootstrap != nil {
		if err := validateRouteEligibility(cfg.Routes, bootstrap); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

func newViper(path string) (*viper.Viper, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	if err := v.ReadInConfig(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("runtime config %q not found; copy config.example.yaml to config.yaml and configure CONFIG_FILE if needed", path)
		}
		return nil, fmt.Errorf("read runtime config: %w", err)
	}
	return v, nil
}

func runtimeFromFile(raw fileConfig) (*RuntimeConfig, error) {
	var errs []error
	base, err := parseRuntimeDuration("cooldown.base", raw.Cooldown.Base)
	if err != nil {
		errs = append(errs, err)
	}
	max, err := parseRuntimeDuration("cooldown.max", raw.Cooldown.Max)
	if err != nil {
		errs = append(errs, err)
	}
	dialTimeout, err := parseRuntimeDuration("dial-timeout", raw.DialTimeout)
	if err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	cfg := &RuntimeConfig{
		MaxRetries:        raw.MaxRetries,
		CooldownBase:      base,
		CooldownMax:       max,
		DialTimeout:       dialTimeout,
		TargetTLSInsecure: raw.Global.TargetTLSInsecure,
		MaxBodyBuffer:     raw.Global.MaxBodyBuffer,
		LogLevel:          raw.LogLevel,
	}
	for i, route := range raw.Proxies.Auto {
		spec, err := parseRouteSpec(route)
		if err != nil {
			return nil, fmt.Errorf("proxies.auto[%d]: %w", i, err)
		}
		cfg.Routes = append(cfg.Routes, spec)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func parseRuntimeDuration(name, value string) (time.Duration, error) {
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a Go duration", name)
	}
	return d, nil
}

func parseRouteSpec(raw autoProxyFileConfig) (RouteSpec, error) {
	kind := EgressKind(raw.Kind)
	if kind != EgressV4 && kind != EgressV6 {
		return RouteSpec{}, fmt.Errorf("kind must be exactly v4 or v6")
	}
	u, err := parseProxyLine(raw.Proxy)
	if err != nil {
		return RouteSpec{}, err
	}
	if err := validateProxyURL(u); err != nil {
		return RouteSpec{}, err
	}
	return RouteSpec{URL: u, Kind: kind}, nil
}

func validateProxyURL(u *url.URL) error {
	switch {
	case !validSchemes[u.Scheme]:
		return fmt.Errorf("unsupported scheme %q (want socks5)", u.Scheme)
	case u.Hostname() == "":
		return errors.New("missing host")
	case u.Port() == "":
		return errors.New("missing port (want host:port)")
	case u.Path != "" || u.RawQuery != "" || u.Fragment != "":
		return errors.New("proxy URL path, query, and fragment are not supported")
	}
	return checkPort(u.Port())
}

func (c *RuntimeConfig) validate() error {
	var errs []error
	if c.MaxRetries < 1 {
		errs = append(errs, fmt.Errorf("max-retries must be >= 1, got %d", c.MaxRetries))
	}
	if c.CooldownBase <= 0 {
		errs = append(errs, fmt.Errorf("cooldown.base must be positive, got %s", c.CooldownBase))
	}
	if c.CooldownMax <= 0 {
		errs = append(errs, fmt.Errorf("cooldown.max must be positive, got %s", c.CooldownMax))
	}
	if c.CooldownBase > 0 && c.CooldownMax > 0 && c.CooldownBase > c.CooldownMax {
		errs = append(errs, fmt.Errorf("cooldown.base %s must not exceed cooldown.max %s", c.CooldownBase, c.CooldownMax))
	}
	if c.DialTimeout <= 0 {
		errs = append(errs, fmt.Errorf("dial-timeout must be positive, got %s", c.DialTimeout))
	}
	if c.MaxBodyBuffer < 0 {
		errs = append(errs, fmt.Errorf("global.max-body-buffer must be >= 0, got %d", c.MaxBodyBuffer))
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("log-level must be one of debug, info, warn, error, got %q", c.LogLevel))
	}
	if len(c.Routes) == 0 {
		errs = append(errs, errors.New("proxies.auto must contain at least one route"))
	}
	seen := make(map[string]struct{}, len(c.Routes))
	for _, route := range c.Routes {
		id := CanonicalRouteID(route.URL)
		if _, duplicate := seen[id]; duplicate {
			errs = append(errs, errors.New("proxies.auto contains a duplicate route"))
		}
		seen[id] = struct{}{}
	}
	return errors.Join(errs...)
}

// validateRouteEligibility retains the mixed-listener invariant. Dedicated
// listeners intentionally may have no matching route: they remain available and
// return the standard no-route 502 without crossing into the other kind.
func validateRouteEligibility(routes []RouteSpec, bootstrap *BootstrapConfig) error {
	if bootstrap.MixedListenAddr != "" && len(routes) == 0 {
		return errors.New("mixed listener requires at least one route")
	}
	return nil
}
