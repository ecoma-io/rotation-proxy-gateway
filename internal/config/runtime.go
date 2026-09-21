package config

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
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

	// Route selection weight defaults and bounds. Weight shapes how often a
	// route is picked relative to its peers; 1 makes every route equal.
	DefaultRouteWeight = 1
	MaxRouteWeight     = 1000

	// MaxBalanceShare bounds one egress family's share in the balance block.
	// Shares are relative, so only their ratio matters; the magnitude bound
	// matches MaxRouteWeight so the family clock keeps the same stride
	// resolution as a route weight at the extreme.
	MaxBalanceShare = 1000

	// Rotation defaults. These bound how manual routes rotate their egress IP
	// through their provider API; every one is overridable in the rotation
	// block of the runtime YAML.
	DefaultDrainTimeout     = 55 * time.Second
	DefaultIPCheckURL       = "https://www.cloudflare.com/cdn-cgi/trace"
	DefaultIPCheckTimeout   = 20 * time.Second
	DefaultIPCheckInterval  = 2 * time.Second
	DefaultRetryBackoffMax  = 15 * time.Minute
	DefaultRotateAPITimeout = 10 * time.Second

	// Warm-pool defaults. The pool keeps half-established upstream
	// connections (TCP + greeting + auth, no CONNECT) ready in the
	// background; every bound is deliberately conservative, and the feature
	// is off unless warm-pool.enabled says otherwise.
	DefaultWarmMinIdlePerProxy         = 1
	DefaultWarmMaxIdlePerProxy         = 2
	DefaultWarmMaxTotalIdle            = 64
	DefaultWarmMaxReplenishConcurrency = 2
	DefaultWarmIdleTTL                 = 45 * time.Second
)

// EgressKind is the public IP family supplied by an upstream proxy provider.
// It does not describe the SOCKS endpoint's network address or the target
// address family requested by a client.
type EgressKind string

const (
	EgressV4 EgressKind = "v4"
	EgressV6 EgressKind = "v6"
)

// RouteOrigin records whether a route came from proxies.auto (static) or
// proxies.manual (API-rotated). Both origins serve client traffic through the
// same shared pool; the origin only drives rotation bookkeeping.
type RouteOrigin string

const (
	RouteOriginAuto   RouteOrigin = "auto"
	RouteOriginManual RouteOrigin = "manual"
)

// RouteSpec is one validated static SOCKS route from the runtime config.
// Weight is the route's selection weight in [DefaultRouteWeight, MaxRouteWeight]:
// a route is picked proportionally to its weight against its eligible peers.
// It is deliberately not part of the route identity — a reload that only
// retunes weights keeps the route's health state.
type RouteSpec struct {
	URL    *url.URL
	Kind   EgressKind
	Origin RouteOrigin
	Weight int
}

// ManualRouteSpec is one validated API-rotated SOCKS route. Besides the SOCKS
// endpoint it carries the provider rotation cadence and the HTTP call that
// swaps the route's public egress IP.
type ManualRouteSpec struct {
	RouteSpec
	RotateInterval time.Duration
	API            RotateAPI
}

// KindBalance sets how the mixed listener splits picks between the two egress
// families: the values are relative shares, so V4=7, V6=3 sends about 70% of
// mixed traffic through v4 routes no matter how many routes each family has.
// Route weight still distributes picks inside one family. A family with no
// share only serves as standby when the shared family has no live route; a
// family with no live route always defers to the other, so availability beats
// the ratio. The dedicated v4/v6 listeners are unaffected: their kind filter
// leaves a single family. The zero value disables the split, keeping the flat
// weighted pool where each family's share follows its routes' own weights.
type KindBalance struct {
	V4 int
	V6 int
}

// RotateAPI describes the provider HTTP request that rotates a manual route's
// egress IP. Headers and body may carry provider credentials: they are never
// logged, never returned in errors, and never exposed by /status.
type RotateAPI struct {
	URL     *url.URL
	Method  string
	Headers map[string]string
	Body    string
	Timeout time.Duration
}

// RotationSettings holds the global knobs for manual-route rotation.
// MaxConcurrentFixed and MaxConcurrentPercent are mutually exclusive; resolve
// the effective cap per cycle with ResolveMaxConcurrent so reloads that change
// the manual route count take effect without restart.
type RotationSettings struct {
	MaxConcurrentFixed   *int
	MaxConcurrentPercent *int
	DrainTimeout         time.Duration
	RotateOnStart        bool
	IPCheckURL           string
	IPCheckTimeout       time.Duration
	IPCheckInterval      time.Duration
	RetryBackoffMax      time.Duration
}

// ResolveMaxConcurrent returns the effective rotation concurrency for n manual
// routes: fixed counts pass through, percents round up, the result is at least
// 1 and at most n. It returns 0 when there is nothing to rotate.
func (r RotationSettings) ResolveMaxConcurrent(n int) int {
	if n <= 0 {
		return 0
	}
	limit := 1
	switch {
	case r.MaxConcurrentFixed != nil:
		limit = *r.MaxConcurrentFixed
	case r.MaxConcurrentPercent != nil:
		limit = (n**r.MaxConcurrentPercent + 99) / 100
	}
	if limit < 1 {
		limit = 1
	}
	if limit > n {
		limit = n
	}
	return limit
}

// WarmPoolSettings bounds the background pool of half-established upstream
// connections: TCP dialed, SOCKS5 greeting and auth negotiated, CONNECT not
// sent — a parked connection is reusable for any target. Requests never wait
// on the pool; it only ever swaps a cold dial for a ready half connection.
type WarmPoolSettings struct {
	Enabled                 bool
	MinIdlePerProxy         int
	MaxIdlePerProxy         int
	MaxTotalIdle            int
	MaxReplenishConcurrency int
	IdleTTL                 time.Duration
}

// AllRoutes returns every serving route, auto first. The pool and the rotation
// engine both key state by canonical URL+kind, so ordering only affects
// duplicate reporting and new-entry construction.
func (c *RuntimeConfig) AllRoutes() []RouteSpec {
	all := make([]RouteSpec, 0, len(c.Routes)+len(c.ManualRoutes))
	all = append(all, c.Routes...)
	for _, manual := range c.ManualRoutes {
		all = append(all, manual.RouteSpec)
	}
	return all
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
	MaxRetries   int
	CooldownBase time.Duration
	CooldownMax  time.Duration
	DialTimeout  time.Duration
	LogLevel     string
	Routes       []RouteSpec
	ManualRoutes []ManualRouteSpec
	Rotation     RotationSettings
	Balance      KindBalance
	WarmPool     WarmPoolSettings
}

type fileConfig struct {
	LogLevel    string             `mapstructure:"log-level"`
	MaxRetries  any                `mapstructure:"max-retries"`
	Cooldown    cooldownFileConfig `mapstructure:"cooldown"`
	DialTimeout string             `mapstructure:"dial-timeout"`
	Rotation    rotationFileConfig `mapstructure:"rotation"`
	Proxies     proxiesFileConfig  `mapstructure:"proxies"`
	Balance     balanceFileConfig  `mapstructure:"balance"`
	WarmPool    warmPoolFileConfig `mapstructure:"warm-pool"`
}

// balanceFileConfig keeps the shares as `any` so viper's weak typing cannot
// silently truncate a mistyped share the way it would turn 2.5 into 2.
type balanceFileConfig struct {
	V4 any `mapstructure:"v4"`
	V6 any `mapstructure:"v6"`
}

type cooldownFileConfig struct {
	Base string `mapstructure:"base"`
	Max  string `mapstructure:"max"`
}

type rotationFileConfig struct {
	MaxConcurrent   any    `mapstructure:"max-concurrent"`
	DrainTimeout    string `mapstructure:"drain-timeout"`
	RotateOnStart   *bool  `mapstructure:"rotate-on-start"`
	IPCheckURL      string `mapstructure:"ip-check-url"`
	IPCheckTimeout  string `mapstructure:"ip-check-timeout"`
	IPCheckInterval string `mapstructure:"ip-check-interval"`
	RetryBackoffMax string `mapstructure:"retry-backoff-max"`
}

// warmPoolFileConfig keeps the counts as `any` so viper's weak typing cannot
// silently truncate a mistyped bound (2.5 → 2), the same anti-coercion rule
// as max-retries and route weights.
type warmPoolFileConfig struct {
	Enabled                 *bool  `mapstructure:"enabled"`
	MinIdlePerProxy         any    `mapstructure:"min-idle-per-proxy"`
	MaxIdlePerProxy         any    `mapstructure:"max-idle-per-proxy"`
	MaxTotalIdle            any    `mapstructure:"max-total-idle"`
	MaxReplenishConcurrency any    `mapstructure:"max-replenish-concurrency"`
	IdleTTL                 string `mapstructure:"idle-ttl"`
}

type proxiesFileConfig struct {
	Auto   []autoProxyFileConfig   `mapstructure:"auto"`
	Manual []manualProxyFileConfig `mapstructure:"manual"`
}

type autoProxyFileConfig struct {
	Proxy  string `mapstructure:"proxy"`
	Kind   string `mapstructure:"kind"`
	Weight any    `mapstructure:"weight"`
}

type manualProxyFileConfig struct {
	Proxy          string        `mapstructure:"proxy"`
	Kind           string        `mapstructure:"kind"`
	Weight         any           `mapstructure:"weight"`
	RotateInterval string        `mapstructure:"rotate-interval"`
	API            apiFileConfig `mapstructure:"api"`
}

type apiFileConfig struct {
	URL     string            `mapstructure:"url"`
	Method  string            `mapstructure:"method"`
	Headers map[string]string `mapstructure:"headers"`
	Body    string            `mapstructure:"body"`
	Timeout string            `mapstructure:"timeout"`
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
	if leftErr != nil || rightErr != nil {
		return false
	}
	// Ports compare numerically: validation admits leading-zero spellings
	// ("080"), which must still collide with ":80" — otherwise the bind
	// discovers the overlap after validation called the addresses distinct.
	leftN, leftErr := strconv.Atoi(leftPort)
	rightN, rightErr := strconv.Atoi(rightPort)
	if leftErr != nil || rightErr != nil || leftN != rightN {
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
func LoadRuntime(path string) (*RuntimeConfig, error) {
	v, err := newViper(path)
	if err != nil {
		return nil, err
	}
	var raw fileConfig
	if err := v.UnmarshalExact(&raw); err != nil {
		return nil, fmt.Errorf("decode runtime config: %w", err)
	}
	return runtimeFromFile(raw)
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
	maxRetries, err := parseMaxRetries(raw.MaxRetries)
	if err != nil {
		errs = append(errs, err)
	}
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

	rotation, err := parseRotationSettings(raw.Rotation)
	if err != nil {
		return nil, err
	}
	balance, err := parseBalance(raw.Balance)
	if err != nil {
		return nil, err
	}
	warmPool, err := parseWarmPoolSettings(raw.WarmPool)
	if err != nil {
		return nil, err
	}

	cfg := &RuntimeConfig{
		MaxRetries:   maxRetries,
		CooldownBase: base,
		CooldownMax:  max,
		DialTimeout:  dialTimeout,
		LogLevel:     raw.LogLevel,
		Rotation:     rotation,
		Balance:      balance,
		WarmPool:     warmPool,
	}
	for i, route := range raw.Proxies.Auto {
		spec, err := parseRouteSpec(route)
		if err != nil {
			return nil, fmt.Errorf("proxies.auto[%d]: %w", i, err)
		}
		cfg.Routes = append(cfg.Routes, spec)
	}
	for i, route := range raw.Proxies.Manual {
		spec, err := parseManualRouteSpec(route)
		if err != nil {
			return nil, fmt.Errorf("proxies.manual[%d]: %w", i, err)
		}
		cfg.ManualRoutes = append(cfg.ManualRoutes, spec)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// parseRotationSettings applies defaults, then validates the overrides. Values
// that fail duration parsing are reported without echoing the raw input, which
// may be a typo of a secret in a shared config file.
func parseRotationSettings(raw rotationFileConfig) (RotationSettings, error) {
	settings := RotationSettings{
		DrainTimeout:    DefaultDrainTimeout,
		IPCheckURL:      DefaultIPCheckURL,
		IPCheckTimeout:  DefaultIPCheckTimeout,
		IPCheckInterval: DefaultIPCheckInterval,
		RetryBackoffMax: DefaultRetryBackoffMax,
	}
	fixed, percent, err := parseMaxConcurrent(raw.MaxConcurrent)
	if err != nil {
		return settings, err
	}
	settings.MaxConcurrentFixed, settings.MaxConcurrentPercent = fixed, percent
	if raw.RotateOnStart != nil {
		settings.RotateOnStart = *raw.RotateOnStart
	}
	if raw.DrainTimeout != "" {
		d, err := parseRuntimeDuration("rotation.drain-timeout", raw.DrainTimeout)
		if err != nil {
			return settings, err
		}
		settings.DrainTimeout = d
	}
	if raw.IPCheckTimeout != "" {
		d, err := parseRuntimeDuration("rotation.ip-check-timeout", raw.IPCheckTimeout)
		if err != nil {
			return settings, err
		}
		settings.IPCheckTimeout = d
	}
	if raw.IPCheckInterval != "" {
		d, err := parseRuntimeDuration("rotation.ip-check-interval", raw.IPCheckInterval)
		if err != nil {
			return settings, err
		}
		settings.IPCheckInterval = d
	}
	if raw.RetryBackoffMax != "" {
		d, err := parseRuntimeDuration("rotation.retry-backoff-max", raw.RetryBackoffMax)
		if err != nil {
			return settings, err
		}
		settings.RetryBackoffMax = d
	}
	if raw.IPCheckURL != "" {
		settings.IPCheckURL = raw.IPCheckURL
	}
	if err := settings.validate(); err != nil {
		return settings, err
	}
	return settings, nil
}

func (r RotationSettings) validate() error {
	var errs []error
	u, err := url.Parse(r.IPCheckURL)
	switch {
	case err != nil || !u.IsAbs():
		errs = append(errs, errors.New("rotation.ip-check-url must be an absolute URL"))
	case u.Scheme != "https":
		// The verification answer must resist tampering by the very network
		// path under test, so plaintext check endpoints are rejected outright.
		errs = append(errs, errors.New("rotation.ip-check-url must use https"))
	}
	if r.DrainTimeout <= 0 {
		errs = append(errs, fmt.Errorf("rotation.drain-timeout must be positive, got %s", r.DrainTimeout))
	}
	if r.IPCheckTimeout <= 0 {
		errs = append(errs, fmt.Errorf("rotation.ip-check-timeout must be positive, got %s", r.IPCheckTimeout))
	}
	if r.IPCheckInterval <= 0 {
		errs = append(errs, fmt.Errorf("rotation.ip-check-interval must be positive, got %s", r.IPCheckInterval))
	}
	if r.IPCheckInterval > r.IPCheckTimeout {
		errs = append(errs, fmt.Errorf("rotation.ip-check-interval %s must not exceed rotation.ip-check-timeout %s", r.IPCheckInterval, r.IPCheckTimeout))
	}
	if r.RetryBackoffMax <= 0 {
		errs = append(errs, fmt.Errorf("rotation.retry-backoff-max must be positive, got %s", r.RetryBackoffMax))
	}
	return errors.Join(errs...)
}

// parseWarmPoolSettings applies defaults, then validates the overrides —
// including when the pool is disabled, so a bad bound is reported now rather
// than silently shipping to the day the pool is switched on.
func parseWarmPoolSettings(raw warmPoolFileConfig) (WarmPoolSettings, error) {
	settings := WarmPoolSettings{
		MinIdlePerProxy:         DefaultWarmMinIdlePerProxy,
		MaxIdlePerProxy:         DefaultWarmMaxIdlePerProxy,
		MaxTotalIdle:            DefaultWarmMaxTotalIdle,
		MaxReplenishConcurrency: DefaultWarmMaxReplenishConcurrency,
		IdleTTL:                 DefaultWarmIdleTTL,
	}
	if raw.Enabled != nil {
		settings.Enabled = *raw.Enabled
	}
	var errs []error
	if n, ok, err := parseWarmCount("warm-pool.min-idle-per-proxy", raw.MinIdlePerProxy); err != nil {
		errs = append(errs, err)
	} else if ok {
		settings.MinIdlePerProxy = n
	}
	if n, ok, err := parseWarmCount("warm-pool.max-idle-per-proxy", raw.MaxIdlePerProxy); err != nil {
		errs = append(errs, err)
	} else if ok {
		settings.MaxIdlePerProxy = n
	}
	if n, ok, err := parseWarmCount("warm-pool.max-total-idle", raw.MaxTotalIdle); err != nil {
		errs = append(errs, err)
	} else if ok {
		settings.MaxTotalIdle = n
	}
	if n, ok, err := parseWarmCount("warm-pool.max-replenish-concurrency", raw.MaxReplenishConcurrency); err != nil {
		errs = append(errs, err)
	} else if ok {
		settings.MaxReplenishConcurrency = n
	}
	if raw.IdleTTL != "" {
		d, err := parseRuntimeDuration("warm-pool.idle-ttl", raw.IdleTTL)
		if err != nil {
			errs = append(errs, err)
		} else {
			settings.IdleTTL = d
		}
	}
	if err := settings.validate(); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return WarmPoolSettings{}, err
	}
	return settings, nil
}

func (w WarmPoolSettings) validate() error {
	var errs []error
	if w.MinIdlePerProxy < 0 {
		errs = append(errs, fmt.Errorf("warm-pool.min-idle-per-proxy must be >= 0, got %d", w.MinIdlePerProxy))
	}
	if w.MaxIdlePerProxy < 1 {
		errs = append(errs, fmt.Errorf("warm-pool.max-idle-per-proxy must be >= 1, got %d", w.MaxIdlePerProxy))
	}
	if w.MaxTotalIdle < 1 {
		errs = append(errs, fmt.Errorf("warm-pool.max-total-idle must be >= 1, got %d", w.MaxTotalIdle))
	}
	if w.MaxReplenishConcurrency < 1 {
		errs = append(errs, fmt.Errorf("warm-pool.max-replenish-concurrency must be >= 1, got %d", w.MaxReplenishConcurrency))
	}
	if w.IdleTTL <= 0 {
		errs = append(errs, fmt.Errorf("warm-pool.idle-ttl must be positive, got %s", w.IdleTTL))
	}
	if w.MinIdlePerProxy > w.MaxIdlePerProxy {
		errs = append(errs, fmt.Errorf("warm-pool.min-idle-per-proxy %d must not exceed warm-pool.max-idle-per-proxy %d", w.MinIdlePerProxy, w.MaxIdlePerProxy))
	}
	if w.MaxTotalIdle < w.MaxIdlePerProxy {
		errs = append(errs, fmt.Errorf("warm-pool.max-total-idle %d must be at least warm-pool.max-idle-per-proxy %d", w.MaxTotalIdle, w.MaxIdlePerProxy))
	}
	return errors.Join(errs...)
}

// parseWarmCount accepts an absent value (ok false, the default applies) or a
// whole YAML integer, refusing the fractional forms viper's weak typing would
// truncate.
func parseWarmCount(name string, raw any) (n int, ok bool, err error) {
	if raw == nil {
		return 0, false, nil
	}
	n, ok = raw.(int)
	if !ok {
		return 0, false, fmt.Errorf("%s must be a whole number", name)
	}
	return n, true, nil
}

// parseMaxConcurrent accepts a fixed count (1) or a percent of the manual pool
// ("25%"). Exactly one representation is returned.
func parseMaxConcurrent(raw any) (*int, *int, error) {
	switch v := raw.(type) {
	case nil:
		fixed := 1
		return &fixed, nil, nil
	case int:
		if v < 1 {
			return nil, nil, fmt.Errorf("rotation.max-concurrent must be >= 1, got %d", v)
		}
		return &v, nil, nil
	case string:
		digits, found := strings.CutSuffix(strings.TrimSpace(v), "%")
		if !found {
			return nil, nil, errors.New("rotation.max-concurrent must be a count or a percent such as 25%")
		}
		n, err := strconv.Atoi(strings.TrimSpace(digits))
		if err != nil || n < 1 || n > 100 {
			return nil, nil, errors.New("rotation.max-concurrent percent must be a whole number between 1 and 100")
		}
		return nil, &n, nil
	default:
		return nil, nil, errors.New("rotation.max-concurrent must be a count or a percent such as 25%")
	}
}

// parseMaxRetries requires a whole YAML integer: viper's weak typing would
// otherwise truncate 2.5 to 2 and quietly change the retry budget, the same
// anti-coercion rule as parseRouteWeight. An absent value falls through to the
// range check, which reports it.
func parseMaxRetries(raw any) (int, error) {
	if raw == nil {
		return 0, nil
	}
	n, ok := raw.(int)
	if !ok {
		return 0, errors.New("max-retries must be a whole number >= 1")
	}
	return n, nil
}

func parseRuntimeDuration(name, value string) (time.Duration, error) {
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a Go duration", name)
	}
	return d, nil
}

func parseRouteSpec(raw autoProxyFileConfig) (RouteSpec, error) {
	spec, err := parseKindedProxy(raw.Proxy, raw.Kind)
	if err != nil {
		return RouteSpec{}, err
	}
	spec.Origin = RouteOriginAuto
	if spec.Weight, err = parseRouteWeight(raw.Weight); err != nil {
		return RouteSpec{}, err
	}
	return spec, nil
}

// parseRouteWeight applies the default weight, then validates the override.
// Only whole YAML integers are accepted: viper's weak typing would otherwise
// silently truncate 2.5 to 2 and turn a config typo into a quiet share change.
func parseRouteWeight(raw any) (int, error) {
	if raw == nil {
		return DefaultRouteWeight, nil
	}
	n, ok := raw.(int)
	if !ok {
		return 0, fmt.Errorf("weight must be a whole number between %d and %d", DefaultRouteWeight, MaxRouteWeight)
	}
	if n < DefaultRouteWeight || n > MaxRouteWeight {
		return 0, fmt.Errorf("weight must be between %d and %d, got %d", DefaultRouteWeight, MaxRouteWeight, n)
	}
	return n, nil
}

// parseBalance validates the balance block shares. An absent or empty block
// disables the family split, so only present keys are checked: each must be a
// whole YAML integer in [1, MaxBalanceShare] — same anti-weak-typing rule as
// route weight. Shares are relative; any positive pair is a valid ratio.
func parseBalance(raw balanceFileConfig) (KindBalance, error) {
	balance := KindBalance{}
	var err error
	if balance.V4, err = parseBalanceShare("balance.v4", raw.V4); err != nil {
		return balance, err
	}
	if balance.V6, err = parseBalanceShare("balance.v6", raw.V6); err != nil {
		return balance, err
	}
	return balance, nil
}

func parseBalanceShare(name string, raw any) (int, error) {
	if raw == nil {
		return 0, nil
	}
	n, ok := raw.(int)
	if !ok {
		return 0, fmt.Errorf("%s must be a whole number between 1 and %d", name, MaxBalanceShare)
	}
	if n < 1 || n > MaxBalanceShare {
		return 0, fmt.Errorf("%s must be between 1 and %d, got %d", name, MaxBalanceShare, n)
	}
	return n, nil
}

// parseManualRouteSpec validates one manual entry: the same SOCKS endpoint
// rules as auto routes plus a mandatory rotation cadence and rotate API.
func parseManualRouteSpec(raw manualProxyFileConfig) (ManualRouteSpec, error) {
	spec, err := parseKindedProxy(raw.Proxy, raw.Kind)
	if err != nil {
		return ManualRouteSpec{}, err
	}
	manual := ManualRouteSpec{RouteSpec: spec}
	manual.Origin = RouteOriginManual
	if manual.Weight, err = parseRouteWeight(raw.Weight); err != nil {
		return ManualRouteSpec{}, err
	}
	if raw.RotateInterval == "" {
		return ManualRouteSpec{}, errors.New("rotate-interval is required (Go duration, e.g. 90s)")
	}
	interval, err := parseRuntimeDuration("rotate-interval", raw.RotateInterval)
	if err != nil {
		return ManualRouteSpec{}, err
	}
	if interval <= 0 {
		return ManualRouteSpec{}, fmt.Errorf("rotate-interval must be positive, got %s", interval)
	}
	manual.RotateInterval = interval
	api, err := parseRotateAPI(raw.API)
	if err != nil {
		return ManualRouteSpec{}, err
	}
	manual.API = api
	return manual, nil
}

// parseRotateAPI validates the provider rotate call. Error messages name the
// offending field but never quote url/headers/body values: those routinely
// carry provider tokens.
func parseRotateAPI(raw apiFileConfig) (RotateAPI, error) {
	if raw.URL == "" {
		return RotateAPI{}, errors.New("api.url is required")
	}
	u, err := url.Parse(raw.URL)
	if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") {
		return RotateAPI{}, errors.New("api.url must be an absolute http or https URL")
	}
	method := http.MethodPost
	if raw.Method != "" {
		method = strings.ToUpper(raw.Method)
		if !validHTTPMethod(method) {
			return RotateAPI{}, errors.New("api.method must be a valid HTTP method token")
		}
	}
	timeout := DefaultRotateAPITimeout
	if raw.Timeout != "" {
		timeout, err = parseRuntimeDuration("api.timeout", raw.Timeout)
		if err != nil {
			return RotateAPI{}, err
		}
		if timeout <= 0 {
			return RotateAPI{}, fmt.Errorf("api.timeout must be positive, got %s", timeout)
		}
	}
	headers := make(map[string]string, len(raw.Headers))
	for name, value := range raw.Headers {
		// Viper lowercases YAML keys; MIME-canonicalize so `content-type`
		// behaves like the `Content-Type` the user wrote.
		canonical := textproto.CanonicalMIMEHeaderKey(name)
		if !validHeaderFieldName(canonical) {
			return RotateAPI{}, errors.New("api.headers contains an invalid header name")
		}
		if !validHeaderFieldValue(value) {
			return RotateAPI{}, errors.New("api.headers contains an invalid header value")
		}
		headers[canonical] = value
	}
	return RotateAPI{URL: u, Method: method, Headers: headers, Body: raw.Body, Timeout: timeout}, nil
}

// validHeaderFieldName checks the RFC 9110 token shape used for header field
// names.
func validHeaderFieldName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", r):
		default:
			return false
		}
	}
	return true
}

// validHeaderFieldValue checks the RFC 9110 field-value shape: visible ASCII
// plus SP and HTAB, with no control characters.
func validHeaderFieldValue(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		switch {
		case r == '\t' || r == ' ':
		case r >= 0x21 && r <= 0x7e:
		default:
			return false
		}
	}
	return true
}

// validHTTPMethod checks the RFC 9110 token shape after canonical uppercasing.
func validHTTPMethod(method string) bool {
	if method == "" || len(method) > 32 {
		return false
	}
	for _, r := range method {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", r):
		default:
			return false
		}
	}
	return true
}

// parseKindedProxy is the shared proxy+kind validation for both route origins.
func parseKindedProxy(proxy, kind string) (RouteSpec, error) {
	parsed := EgressKind(kind)
	if parsed != EgressV4 && parsed != EgressV6 {
		return RouteSpec{}, fmt.Errorf("kind must be exactly v4 or v6")
	}
	u, err := parseProxyLine(proxy)
	if err != nil {
		return RouteSpec{}, err
	}
	if err := validateProxyURL(u); err != nil {
		return RouteSpec{}, err
	}
	return RouteSpec{URL: u, Kind: parsed}, nil
}

func validateProxyURL(u *url.URL) error {
	switch {
	case u.Scheme != "socks5":
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
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("log-level must be one of debug, info, warn, error, got %q", c.LogLevel))
	}
	if len(c.Routes) == 0 && len(c.ManualRoutes) == 0 {
		errs = append(errs, errors.New("proxies must contain at least one route (auto or manual)"))
	}
	// One identity namespace across both origins: a route reachable through
	// two entries would be selectable twice per request and hold two rotation
	// states for one endpoint.
	seen := make(map[string]struct{}, len(c.Routes)+len(c.ManualRoutes))
	for _, route := range c.AllRoutes() {
		id := CanonicalRouteID(route.URL)
		if _, duplicate := seen[id]; duplicate {
			errs = append(errs, errors.New("proxies contains a duplicate route"))
		}
		seen[id] = struct{}{}
	}
	return errors.Join(errs...)
}
