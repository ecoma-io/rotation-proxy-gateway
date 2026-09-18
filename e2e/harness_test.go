package e2e_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
	Proxy string
	Kind  string
}

// GatewayConfig is the full runtime YAML written for one gateway instance.
type GatewayConfig struct {
	LogLevel      string
	MaxRetries    int
	CooldownBase  string
	CooldownMax   string
	DialTimeout   string
	TLSInsecure   bool
	MaxBodyBuffer int64
	Routes        []RouteConfig
}

func defaultGatewayConfig(routes []RouteConfig) GatewayConfig {
	return GatewayConfig{
		LogLevel:      "info",
		MaxRetries:    3,
		CooldownBase:  "5s",
		CooldownMax:   "1m",
		DialTimeout:   "5s",
		TLSInsecure:   false,
		MaxBodyBuffer: 64 << 20,
		Routes:        routes,
	}
}

// PoolEntry is the redacted per-route view from /status.
type PoolEntry struct {
	Proxy               string `json:"proxy"`
	Kind                string `json:"kind"`
	Available           bool   `json:"available"`
	ConsecutiveFailures int    `json:"consecutiveFailures"`
	CooldownFor         string `json:"cooldownFor"`
	Successes           uint64 `json:"successes"`
	Failures            uint64 `json:"failures"`
	AuthFailures        uint64 `json:"authFailures"`
	AuthBlocked         bool   `json:"authBlocked"`
}

// Status is the decoded /status body.
type Status struct {
	Version   string `json:"version"`
	Requests  uint64 `json:"requests"`
	Rotations uint64 `json:"rotations"`
	Listeners map[string]struct {
		Requests  uint64 `json:"requests"`
		Rotations uint64 `json:"rotations"`
	} `json:"listeners"`
	Pool []PoolEntry `json:"pool"`
}

// Gateway is one real gateway subprocess with its own config file and ports.
type Gateway struct {
	t          *testing.T
	dir        string
	configPath string
	cmd        *exec.Cmd
	output     *lockedBuffer

	AdminAddr string
	MixedAddr string
	V4Addr    string
	V6Addr    string
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
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
	fmt.Fprintf(&sb, "global:\n  target-tls-insecure: %v\n  max-body-buffer: %d\n", cfg.TLSInsecure, cfg.MaxBodyBuffer)
	sb.WriteString("proxies:\n  auto:\n")
	for _, r := range cfg.Routes {
		fmt.Fprintf(&sb, "    - proxy: %s\n      kind: %s\n", yamlQuote(r.Proxy), r.Kind)
	}
	sb.WriteString("  manual: []\n")
	return sb.String()
}

// NewGateway writes cfg to a temp config file, starts the real binary, and
// waits for /healthz. Every instance owns its ports so tests run in parallel.
func NewGateway(t *testing.T, cfg GatewayConfig) *Gateway {
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
	cmd.Env = []string{
		"CONFIG_FILE=" + g.configPath,
		"ADMIN_ADDR=" + g.AdminAddr,
		"MIXED_LISTEN_ADDR=" + g.MixedAddr,
		"V4_LISTEN_ADDR=" + g.V4Addr,
		"V6_LISTEN_ADDR=" + g.V6Addr,
		"PATH=" + os.Getenv("PATH"),
	}
	cmd.Stdout = g.output
	cmd.Stderr = g.output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start gateway: %v", err)
	}
	g.cmd = cmd
	t.Cleanup(g.stop)
	g.waitHealthy(10 * time.Second)
	return g
}

// writeConfig atomically replaces the config file (temp + rename) so the
// watcher never parses a partial write.
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
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && string(body) == "ok\n" {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	g.t.Fatalf("gateway never became healthy; output:\n%s", g.output.String())
}

// SignalReload sends SIGHUP (deterministic reload, no watch debounce) and
// waits until /status reports exactly wantProxies in order.
func (g *Gateway) SignalReload(cfg GatewayConfig, wantProxies []string) {
	g.t.Helper()
	g.writeConfig(cfg)
	if err := g.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		g.t.Fatalf("SIGHUP: %v", err)
	}
	g.WaitForPool(wantProxies, 10*time.Second)
}

// SignalRawReload installs literal content, sends SIGHUP, and waits until the
// pool is unchanged (invalid input) or matches wantProxies (valid input).
func (g *Gateway) SignalRawReload(content string, wantProxies []string) {
	g.t.Helper()
	g.WriteRaw(content)
	if err := g.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		g.t.Fatalf("SIGHUP: %v", err)
	}
	g.WaitForPool(wantProxies, 10*time.Second)
}

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
	defer resp.Body.Close()
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
func ProxyClient(proxyAddr string) *http.Client {
	pu, _ := url.Parse("http://" + proxyAddr)
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
		Timeout:   15 * time.Second,
	}
}

// ProxyClientInsecureTLS is ProxyClient with TLS verification disabled for
// CONNECT-tunnel tests against httptest TLS targets.
func ProxyClientInsecureTLS(proxyAddr string) *http.Client {
	pu, _ := url.Parse("http://" + proxyAddr)
	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(pu),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test-only target
		},
		Timeout: 15 * time.Second,
	}
}

// RawProxyRequest sends a manually written absolute-form request to a gateway
// listener. Go's http client always uses CONNECT for https targets, so the
// gateway's own absolute-form https path (SOCKS tunnel + in-tunnel target TLS)
// is only reachable this way.
func RawProxyRequest(t *testing.T, proxyAddr, method, targetURL string, header http.Header, body []byte) (int, http.Header, []byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	u, err := url.Parse(targetURL)
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, targetURL, u.Host)
	if header.Get("Content-Length") == "" && len(body) > 0 {
		fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))
	}
	for k, vv := range header {
		for _, v := range vv {
			fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
		}
	}
	sb.WriteString("Connection: close\r\n\r\n")
	if _, err := io.WriteString(conn, sb.String()); err != nil {
		t.Fatalf("write proxy request: %v", err)
	}
	if len(body) > 0 {
		if _, err := conn.Write(body); err != nil {
			t.Fatalf("write proxy body: %v", err)
		}
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: method})
	if err != nil {
		t.Fatalf("read proxy response: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, respBody
}

// GetVia is a small helper asserting a proxied GET succeeds with wantBody.
func GetVia(t *testing.T, client *http.Client, targetURL, wantBody string) (int, []byte) {
	t.Helper()
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET %s: %v", targetURL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if wantBody != "" && string(body) != wantBody {
		t.Fatalf("GET %s: body=%q, want %q (status=%d)", targetURL, body, wantBody, resp.StatusCode)
	}
	return resp.StatusCode, body
}
