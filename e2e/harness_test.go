package e2e_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// lockedBuffer is a goroutine-safe sink for gateway process output.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// RouteConfig is one static SOCKS route in the generated gateway config.
type RouteConfig struct {
	Proxy  string
	Kind   string
	Weight int // 0 omits the weight key; the gateway defaults to 1
}

// ManualRouteConfig is one API-driven rotation route in the generated config.
type ManualRouteConfig struct {
	Proxy          string
	Kind           string
	Weight         int // 0 omits the weight key; the gateway defaults to 1
	RotateInterval string
	API            ManualAPIConfig
}

// ManualAPIConfig is the provider rotate endpoint of one manual route.
type ManualAPIConfig struct {
	URL     string
	Method  string
	Headers map[string]string
	Body    string
	Timeout string
}

// RotationConfig is the global rotation block; nil in GatewayConfig omits it.
type RotationConfig struct {
	MaxConcurrent   string // raw: fixed count or "NN%"
	DrainTimeout    string
	RotateOnStart   bool
	IPCheckURL      string
	IPCheckTimeout  string
	IPCheckInterval string
	RetryBackoffMax string
}

// BalanceConfig is the family-split block; nil in GatewayConfig omits it. A
// zero share omits the key, leaving that family as standby.
type BalanceConfig struct {
	V4 int
	V6 int
}

// GatewayConfig is the full runtime YAML written for one gateway instance.
type GatewayConfig struct {
	LogLevel     string
	MaxRetries   int
	CooldownBase string
	CooldownMax  string
	DialTimeout  string
	Routes       []RouteConfig
	Manual       []ManualRouteConfig
	Rotation     *RotationConfig
	Balance      *BalanceConfig
	WarmPool     *WarmPoolConfig
}

// WarmPoolConfig renders the warm-pool runtime block; zero fields fall back
// to the documented defaults.
type WarmPoolConfig struct {
	Enabled                 bool
	MinIdlePerProxy         int
	MaxIdlePerProxy         int
	MaxTotalIdle            int
	MaxReplenishConcurrency int
	MaxReplenishPerRoute    int
	IdleTTL                 string
}

func defaultGatewayConfig(routes []RouteConfig) GatewayConfig {
	return GatewayConfig{
		LogLevel:     "info",
		MaxRetries:   3,
		CooldownBase: "5s",
		CooldownMax:  "1m",
		DialTimeout:  "5s",
		Routes:       routes,
	}
}

// PoolEntry is the redacted per-route view from /status.
type PoolEntry struct {
	Proxy               string        `json:"proxy"`
	Kind                string        `json:"kind"`
	Origin              string        `json:"origin"`
	Weight              uint64        `json:"weight"`
	Available           bool          `json:"available"`
	InFlight            int           `json:"inFlight"`
	ConsecutiveFailures int           `json:"consecutiveFailures"`
	CooldownFor         string        `json:"cooldownFor"`
	Successes           uint64        `json:"successes"`
	Failures            uint64        `json:"failures"`
	AuthFailures        uint64        `json:"authFailures"`
	AuthBlocked         bool          `json:"authBlocked"`
	TargetCooldowns     int           `json:"targetCooldowns"`
	TargetFailures      uint64        `json:"targetFailures"`
	Rotation            *RotationView `json:"rotation,omitempty"`
}

// RotationView is the manual-route rotation state in one pool entry.
type RotationView struct {
	State             string `json:"state"`
	LastIP            string `json:"lastIP"`
	LastRotationAt    string `json:"lastRotationAt"`
	NextRetryIn       string `json:"nextRetryIn"`
	ConsecutiveSameIP int    `json:"consecutiveSameIP"`
}

// BalanceView is the active family split reported by /status when configured.
type BalanceView struct {
	V4 int `json:"v4"`
	V6 int `json:"v6"`
}

// Status is the decoded /status body.
type Status struct {
	Version   string `json:"version"`
	Requests  uint64 `json:"requests"`
	Failovers uint64 `json:"failovers"`
	Rotations uint64 `json:"rotations"`
	Listeners map[string]struct {
		Requests  uint64 `json:"requests"`
		Failovers uint64 `json:"failovers"`
	} `json:"listeners"`
	Pool     []PoolEntry  `json:"pool"`
	Balance  *BalanceView `json:"balance,omitempty"`
	WarmPool *WarmView    `json:"warmPool,omitempty"`
}

// WarmView is the warm-pool section of /status.
type WarmView struct {
	Enabled               bool            `json:"enabled"`
	IdleTotal             int             `json:"idleTotal"`
	MaxReplenishPerRoute  int             `json:"maxReplenishPerRoute"`
	Created               uint64          `json:"created"`
	Borrowed              uint64          `json:"borrowed"`
	DiscardedStale        uint64          `json:"discardedStale"`
	DiscardedOverflow     uint64          `json:"discardedOverflow"`
	GenerationInvalidated uint64          `json:"generationInvalidated"`
	ConnectFailed         uint64          `json:"connectFailed"`
	ReplenishAttempts     uint64          `json:"replenishAttempts"`
	Routes                []WarmRouteView `json:"routes"`
}

// WarmRouteView is one route's warm-pool gauge.
type WarmRouteView struct {
	Upstream string `json:"upstream"`
	Idle     int    `json:"idle"`
	Pending  int    `json:"pending"`
	Flying   int    `json:"flying"`
}

// Gateway is one real gateway subprocess with its own config file and ports.
type Gateway struct {
	t          testing.TB
	dir        string
	configPath string
	cmd        *exec.Cmd
	output     *lockedBuffer

	AdminAddr string
	MixedAddr string
	V4Addr    string
	V6Addr    string
}

// handedOut records every loopback address freeAddr returned in this process.
// The OS can hand back a just-closed ephemeral port immediately, which would
// collide two listeners of one gateway (or of parallel gateways); the registry
// makes every allocation unique for the test run.
var (
	handedOutMu sync.Mutex
	handedOut   = map[string]bool{}
)

func freeAddr(t testing.TB) string {
	t.Helper()
	handedOutMu.Lock()
	defer handedOutMu.Unlock()
	for {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		if !handedOut[addr] {
			handedOut[addr] = true
			return addr
		}
	}
}

func yamlQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func renderConfig(cfg GatewayConfig) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "log-level: %s\n", cfg.LogLevel)
	fmt.Fprintf(&sb, "max-retries: %d\n", cfg.MaxRetries)
	fmt.Fprintf(&sb, "cooldown:\n  base: %s\n  max: %s\n", cfg.CooldownBase, cfg.CooldownMax)
	fmt.Fprintf(&sb, "dial-timeout: %s\n", cfg.DialTimeout)
	if cfg.Rotation != nil {
		fmt.Fprintf(&sb, "rotation:\n  max-concurrent: %s\n", cfg.Rotation.MaxConcurrent)
		fmt.Fprintf(&sb, "  drain-timeout: %s\n", cfg.Rotation.DrainTimeout)
		fmt.Fprintf(&sb, "  rotate-on-start: %v\n", cfg.Rotation.RotateOnStart)
		if cfg.Rotation.IPCheckURL != "" {
			fmt.Fprintf(&sb, "  ip-check-url: %s\n", cfg.Rotation.IPCheckURL)
		}
		if cfg.Rotation.IPCheckTimeout != "" {
			fmt.Fprintf(&sb, "  ip-check-timeout: %s\n", cfg.Rotation.IPCheckTimeout)
		}
		if cfg.Rotation.IPCheckInterval != "" {
			fmt.Fprintf(&sb, "  ip-check-interval: %s\n", cfg.Rotation.IPCheckInterval)
		}
		if cfg.Rotation.RetryBackoffMax != "" {
			fmt.Fprintf(&sb, "  retry-backoff-max: %s\n", cfg.Rotation.RetryBackoffMax)
		}
	}
	if cfg.Balance != nil {
		sb.WriteString("balance:\n")
		if cfg.Balance.V4 > 0 {
			fmt.Fprintf(&sb, "  v4: %d\n", cfg.Balance.V4)
		}
		if cfg.Balance.V6 > 0 {
			fmt.Fprintf(&sb, "  v6: %d\n", cfg.Balance.V6)
		}
	}
	if cfg.WarmPool != nil {
		w := cfg.WarmPool
		sb.WriteString("warm-pool:\n")
		fmt.Fprintf(&sb, "  enabled: %v\n", w.Enabled)
		if w.MinIdlePerProxy > 0 {
			fmt.Fprintf(&sb, "  min-idle-per-proxy: %d\n", w.MinIdlePerProxy)
		}
		if w.MaxIdlePerProxy > 0 {
			fmt.Fprintf(&sb, "  max-idle-per-proxy: %d\n", w.MaxIdlePerProxy)
		}
		if w.MaxTotalIdle > 0 {
			fmt.Fprintf(&sb, "  max-total-idle: %d\n", w.MaxTotalIdle)
		}
		if w.MaxReplenishConcurrency > 0 {
			fmt.Fprintf(&sb, "  max-replenish-concurrency: %d\n", w.MaxReplenishConcurrency)
		}
		if w.MaxReplenishPerRoute > 0 {
			fmt.Fprintf(&sb, "  max-replenish-per-route: %d\n", w.MaxReplenishPerRoute)
		}
		if w.IdleTTL != "" {
			fmt.Fprintf(&sb, "  idle-ttl: %s\n", w.IdleTTL)
		}
	}
	sb.WriteString("proxies:\n  auto:\n")
	for _, r := range cfg.Routes {
		fmt.Fprintf(&sb, "    - proxy: %s\n      kind: %s\n", yamlQuote(r.Proxy), r.Kind)
		if r.Weight > 0 {
			fmt.Fprintf(&sb, "      weight: %d\n", r.Weight)
		}
	}
	if len(cfg.Manual) == 0 {
		sb.WriteString("  manual: []\n")
		return sb.String()
	}
	sb.WriteString("  manual:\n")
	for _, m := range cfg.Manual {
		fmt.Fprintf(&sb, "    - proxy: %s\n      kind: %s\n", yamlQuote(m.Proxy), m.Kind)
		if m.Weight > 0 {
			fmt.Fprintf(&sb, "      weight: %d\n", m.Weight)
		}
		fmt.Fprintf(&sb, "      rotate-interval: %s\n", m.RotateInterval)
		fmt.Fprintf(&sb, "      api:\n        url: %s\n", m.API.URL)
		if m.API.Method != "" {
			fmt.Fprintf(&sb, "        method: %s\n", m.API.Method)
		}
		if m.API.Timeout != "" {
			fmt.Fprintf(&sb, "        timeout: %s\n", m.API.Timeout)
		}
		if len(m.API.Headers) > 0 {
			sb.WriteString("        headers:\n")
			for k, v := range m.API.Headers {
				fmt.Fprintf(&sb, "          %s: %s\n", k, yamlQuote(v))
			}
		}
		if m.API.Body != "" {
			fmt.Fprintf(&sb, "        body: %s\n", yamlQuote(m.API.Body))
		}
	}
	return sb.String()
}

// NewGateway writes cfg to a temp config file, starts the real binary, and
// waits for /healthz. Every instance owns its ports so tests run in parallel.
func NewGateway(t testing.TB, cfg GatewayConfig) *Gateway {
	return newGateway(t, cfg, nil)
}

// NewGatewayWithEnv is NewGateway with extra bootstrap environment entries
// (for example "SHUTDOWN_GRACE=1s") appended to the standard set.
func NewGatewayWithEnv(t testing.TB, cfg GatewayConfig, extraEnv ...string) *Gateway {
	return newGateway(t, cfg, extraEnv)
}

func newGateway(t testing.TB, cfg GatewayConfig, extraEnv []string) *Gateway {
	t.Helper()
	if testBinaryPath == "" {
		t.Skip("e2e binary not built (short mode?)")
	}
	dir := t.TempDir()
	g := &Gateway{
		t:          t,
		dir:        dir,
		configPath: filepath.Join(dir, "config.yaml"),
		output:     &lockedBuffer{},
		AdminAddr:  freeAddr(t),
		MixedAddr:  freeAddr(t),
		V4Addr:     freeAddr(t),
		V6Addr:     freeAddr(t),
	}
	g.writeConfig(cfg)
	cmd := exec.Command(testBinaryPath)
	cmd.Dir = dir
	cmd.Env = append([]string{
		"CONFIG_FILE=" + g.configPath,
		"ADMIN_ADDR=" + g.AdminAddr,
		"MIXED_LISTEN_ADDR=" + g.MixedAddr,
		"V4_LISTEN_ADDR=" + g.V4Addr,
		"V6_LISTEN_ADDR=" + g.V6Addr,
		"PATH=" + os.Getenv("PATH"),
	}, extraEnv...)
	cmd.Stdout = g.output
	cmd.Stderr = g.output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start gateway: %v", err)
	}
	g.cmd = cmd
	t.Cleanup(g.stop)
	// 30s only matters on a machine that stalls: a healthy gateway answers
	// healthz in milliseconds, but a shared box can freeze for ~10s and a
	// tight budget turns environmental noise into a harness failure.
	g.waitHealthy(30 * time.Second)
	return g
}

// writeConfig atomically replaces the config file (temp + rename) so the
// gateway's poller never reads a partial write.
func (g *Gateway) writeConfig(cfg GatewayConfig) {
	g.t.Helper()
	tmp := filepath.Join(g.dir, "config.yaml.tmp")
	if err := os.WriteFile(tmp, []byte(renderConfig(cfg)), 0o600); err != nil {
		g.t.Fatalf("write config: %v", err)
	}
	if err := os.Rename(tmp, g.configPath); err != nil {
		g.t.Fatalf("install config: %v", err)
	}
}

// WriteRaw replaces the config with literal content for invalid-config tests.
func (g *Gateway) WriteRaw(content string) {
	g.t.Helper()
	tmp := filepath.Join(g.dir, "config.yaml.tmp")
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		g.t.Fatalf("write raw config: %v", err)
	}
	if err := os.Rename(tmp, g.configPath); err != nil {
		g.t.Fatalf("install raw config: %v", err)
	}
}

func (g *Gateway) waitHealthy(timeout time.Duration) {
	g.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if g.cmd.ProcessState != nil && g.cmd.ProcessState.Exited() {
			g.t.Fatalf("gateway exited during startup; output:\n%s", g.output.String())
		}
		resp, err := http.Get("http://" + g.AdminAddr + "/healthz")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK && string(body) == "ok\n" {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	g.t.Fatalf("gateway never became healthy; output:\n%s", g.output.String())
}

// ReloadConfig rewrites the config file (atomic tmp+rename, modeling an editor
// or bind-mount update) and relies on the gateway's content-hash config poller
// to apply it. It fails when /status does not report exactly wantProxies
// within one poll cycle.
func (g *Gateway) ReloadConfig(cfg GatewayConfig, wantProxies []string) {
	g.t.Helper()
	g.writeConfig(cfg)
	g.WaitForPool(wantProxies, reloadSettle)
}

// ReloadConfigRaw installs literal content and returns without waiting: callers
// assert either that the pool stays unchanged (invalid input) or that a warn
// line appeared in the logs.
func (g *Gateway) ReloadConfigRaw(content string) {
	g.t.Helper()
	g.WriteRaw(content)
}

// reloadSettle bounds one poll cycle: the gateway's 1s content-hash poll
// interval plus reload work, with comfortable headroom for slow CI machines.
const reloadSettle = 6 * time.Second

// WaitForPool polls /status until the pool reports exactly want in order.
func (g *Gateway) WaitForPool(want []string, timeout time.Duration) {
	g.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := g.Status()
		if err == nil {
			got := make([]string, 0, len(st.Pool))
			for _, e := range st.Pool {
				got = append(got, e.Proxy)
			}
			if equalStrings(got, want) {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	st, _ := g.Status()
	g.t.Fatalf("pool never became %v; status=%+v\nlogs:\n%s", want, st, g.output.String())
}

// WaitForCondition polls until cond holds on the live /status.
func (g *Gateway) WaitForCondition(timeout time.Duration, what string, cond func(*Status) bool) *Status {
	g.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := g.Status()
		if err == nil && cond(st) {
			return st
		}
		time.Sleep(50 * time.Millisecond)
	}
	st, _ := g.Status()
	g.t.Fatalf("condition %q never held; status=%+v\nlogs:\n%s", what, st, g.output.String())
	return nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Status fetches and decodes /status.
func (g *Gateway) Status() (*Status, error) {
	resp, err := http.Get("http://" + g.AdminAddr + "/status")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var st Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Logs returns captured gateway stdout/stderr.
func (g *Gateway) Logs() string { return g.output.String() }

func (g *Gateway) stop() {
	if g.cmd == nil || (g.cmd.ProcessState != nil && g.cmd.ProcessState.Exited()) {
		return
	}
	_ = g.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _ = g.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = g.cmd.Process.Kill()
		<-done
	}
}

// ProxyClient returns an HTTP client routing through one gateway listener.
// The transport dials every connection as an inbound SOCKS5 tunnel (RFC 1928,
// no auth), so HTTP and TLS run inside the tunnel and the gateway is a pure
// TCP relay from the client's point of view. Keep-alives are disabled so one
// HTTP request is one CONNECT: requests counter, route picks, and health
// effects keep their historical per-request granularity. Tests that want to
// exercise client-owned tunnel reuse build their own transport instead.
func ProxyClient(proxyAddr string) *http.Client {
	tr := socksTransport(proxyAddr, false)
	tr.DisableKeepAlives = true
	return &http.Client{Transport: tr, Timeout: 15 * time.Second}
}

// ProxyClientInsecureTLS is ProxyClient with TLS verification disabled for
// tunnel tests against httptest TLS targets.
func ProxyClientInsecureTLS(proxyAddr string) *http.Client {
	tr := socksTransport(proxyAddr, true)
	tr.DisableKeepAlives = true
	return &http.Client{Transport: tr, Timeout: 15 * time.Second}
}

// GetVia is a small helper asserting a proxied GET succeeds with wantBody.
func GetVia(t *testing.T, client *http.Client, targetURL, wantBody string) (int, []byte) {
	t.Helper()
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET %s: %v", targetURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if wantBody != "" && string(body) != wantBody {
		t.Fatalf("GET %s: body=%q, want %q (status=%d)", targetURL, body, wantBody, resp.StatusCode)
	}
	return resp.StatusCode, body
}
