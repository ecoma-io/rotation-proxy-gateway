package e2e_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"testing"
	"time"
)

func waitForLog(t *testing.T, g *Gateway, want string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if out := g.Logs(); strings.Contains(out, want) {
			return out
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("logs missing %q:\n%s", want, g.Logs())
	return ""
}

// isConnResetError reports connection-reset errors seen when the server closes
// a socket that still holds unread client bytes (no reply frame was written).
func isConnResetError(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		if oe, ok := ne.(*net.OpError); ok {
			return errors.Is(oe, syscall.ECONNRESET)
		}
	}
	return errors.Is(err, syscall.ECONNRESET)
}

func deadRouteValue(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return "socks5://" + addr
}

// failedSocksTunnel asserts the gateway rejects the CONNECT attempt with the
// SOCKS general-failure reply (0x01): no-route exhaustion and setup failures
// surface to a client as a SOCKS transport error, not an HTTP status. It fails
// the test when the tunnel unexpectedly establishes; rejection is the pass.
func failedSocksTunnel(t *testing.T, proxyAddr, target string) {
	t.Helper()
	conn, err := dialSocksTunnel(context.Background(), proxyAddr, target)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("CONNECT %s through %s unexpectedly succeeded", target, proxyAddr)
	}
	if !strings.Contains(err.Error(), "reply 0x01") {
		t.Fatalf("CONNECT %s through %s: error=%v, want reply 0x01", target, proxyAddr, err)
	}
}

func TestE2E_MixedV4ForwardHTTP(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}))

	for name, addr := range map[string]string{"mixed": g.MixedAddr, "v4": g.V4Addr} {
		status, body := GetVia(t, ProxyClient(addr), target.URL+"/hello", "e2e-echo:/hello")
		if status != http.StatusOK {
			t.Fatalf("%s: status=%d", name, status)
		}
		_ = body
	}

	// v6 listener has no eligible route: the CONNECT gets the general-failure
	// reply and the tunnel fails to establish.
	failedSocksTunnel(t, g.V6Addr, target.Host)

	st, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Pool) != 1 || st.Pool[0].Proxy != socks.Addr || st.Pool[0].Kind != "v4" {
		t.Fatalf("pool=%+v", st.Pool)
	}
	if st.Pool[0].Successes != 2 {
		t.Fatalf("successes=%d, want 2 (mixed+v4)", st.Pool[0].Successes)
	}
	if st.Listeners["mixed"].Requests != 1 || st.Listeners["v4"].Requests != 1 || st.Listeners["v6"].Requests != 1 {
		t.Fatalf("per-listener counters=%+v", st.Listeners)
	}
}

func TestE2E_V6OnlyPool(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v6"},
	}))

	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/x", "e2e-echo:/x")
	GetVia(t, ProxyClient(g.V6Addr), target.URL+"/x", "e2e-echo:/x")

	failedSocksTunnel(t, g.V4Addr, target.Host)
}

// One CONNECT-to-TLS-target test through ProxyClientInsecureTLS: the gateway is
// a pure TCP relay once the tunnel is up and TLS runs inside the test client.
func TestE2E_CONNECTTunnelToTLS(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target := NewTLSEchoTarget(t)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}))

	resp, err := ProxyClientInsecureTLS(g.MixedAddr).Get(target.URL + "/")
	if err != nil {
		t.Fatalf("GET through tunnel: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "e2e-tls-echo" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	st, _ := g.Status()
	if st.Pool[0].Successes != 1 {
		t.Fatalf("pool=%+v", st.Pool)
	}
}

func TestE2E_DialFailureFallsBackWithCooldown(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	good := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: deadRouteValue(t), Kind: "v4"},
		{Proxy: good.RouteValue(), Kind: "v4"},
	}))

	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/", "e2e-echo:/")

	st := g.WaitForCondition(5*time.Second, "dial fallback recorded", func(st *Status) bool {
		return len(st.Pool) == 2 && st.Pool[0].Failures == 1 && st.Pool[1].Successes == 1
	})
	if st.Failovers < 1 {
		t.Fatalf("failovers=%d, want >=1", st.Failovers)
	}
	if st.Pool[0].CooldownFor == "0s" {
		t.Fatalf("dead route should cool down: %+v", st.Pool[0])
	}
	out := waitForLog(t, g, "error_kind=proxy_connect", 5*time.Second)
	if !strings.Contains(out, "attempts=2") {
		t.Fatalf("logs missing fallback attempts=2:\n%s", out)
	}
}

func TestE2E_AuthFailureFallsBackWithoutCooldown(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	bad := NewSocksSim(t, SocksAuthRequired, "e2e-user", "e2e-pass")
	good := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	// Gateway offers no credentials: the simulator demands them.
	badNoCreds := "socks5://" + bad.Addr
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: badNoCreds, Kind: "v4"},
		{Proxy: good.RouteValue(), Kind: "v4"},
	}))

	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/", "e2e-echo:/")

	st := g.WaitForCondition(5*time.Second, "auth fallback recorded", func(st *Status) bool {
		return len(st.Pool) == 2 && st.Pool[0].AuthBlocked && st.Pool[1].Successes == 1
	})
	if st.Pool[0].Failures != 0 {
		t.Fatalf("auth failure must not count as dial failure: %+v", st.Pool[0])
	}
	if st.Pool[0].CooldownFor != "0s" {
		t.Fatalf("auth failure must not create cooldown: %+v", st.Pool[0])
	}
	out := waitForLog(t, g, "error_kind=auth_route", 5*time.Second)
	if strings.Contains(out, "cooldown=") {
		// auth lines never carry cooldown; the dial line is absent in this test.
		t.Fatalf("auth fallback logged a cooldown:\n%s", out)
	}
}

// With a single route whose SOCKS CONNECT fails, the route is excluded within
// the request: the pool exhausts to the no-route general-failure reply while
// the failure is recorded in route health.
func TestE2E_SocksHandshakeFailureExhaustsToNoRoute(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	reject := NewSocksSim(t, SocksRejectTarget, "", "")
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: reject.RouteValue(), Kind: "v4"},
	}))

	failedSocksTunnel(t, g.MixedAddr, "example.com:80")
	if got := reject.Hits.Load(); got != 1 {
		t.Fatalf("SOCKS attempts=%d, want 1 (route excluded after one handshake failure)", got)
	}

	st := g.WaitForCondition(5*time.Second, "handshake failure recorded", func(st *Status) bool {
		return len(st.Pool) == 1 && st.Pool[0].Failures == 1
	})
	if st.Pool[0].CooldownFor == "0s" {
		t.Fatalf("rejecting route should cool down: %+v", st.Pool[0])
	}
	out := waitForLog(t, g, "error_kind=socks_connect", 5*time.Second)
	if !strings.Contains(out, "cooldown=") {
		t.Fatalf("handshake failure line missing cooldown:\n%s", out)
	}
}

func TestE2E_HandshakeFailureFallsBackWithCooldown(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	reject := NewSocksSim(t, SocksRejectTarget, "", "")
	good := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: reject.RouteValue(), Kind: "v4"},
		{Proxy: good.RouteValue(), Kind: "v4"},
	}))

	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/", "e2e-echo:/")

	st := g.WaitForCondition(5*time.Second, "handshake fallback recorded", func(st *Status) bool {
		return len(st.Pool) == 2 && st.Pool[0].Failures == 1 && st.Pool[1].Successes == 1
	})
	if st.Failovers < 1 {
		t.Fatalf("failovers=%d, want >=1", st.Failovers)
	}
	if st.Pool[0].CooldownFor == "0s" {
		t.Fatalf("rejecting route should cool down: %+v", st.Pool[0])
	}
	out := waitForLog(t, g, "error_kind=socks_connect", 5*time.Second)
	if !strings.Contains(out, "attempts=2") {
		t.Fatalf("logs missing fallback attempts=2:\n%s", out)
	}
}

func TestE2E_ConnectTunnelHandshakeFailureFallsBack(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	reject := NewSocksSim(t, SocksRejectTarget, "", "")
	good := NewSocksSim(t, SocksOK, "", "")
	target := NewTLSEchoTarget(t)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: reject.RouteValue(), Kind: "v4"},
		{Proxy: good.RouteValue(), Kind: "v4"},
	}))

	resp, err := ProxyClientInsecureTLS(g.MixedAddr).Get(target.URL + "/")
	if err != nil {
		t.Fatalf("GET through tunnel: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "e2e-tls-echo" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}

	st := g.WaitForCondition(5*time.Second, "tunnel handshake fallback recorded", func(st *Status) bool {
		return len(st.Pool) == 2 && st.Pool[0].Failures == 1 && st.Pool[1].Successes == 1
	})
	if st.Pool[0].CooldownFor == "0s" {
		t.Fatalf("rejecting route should cool down: %+v", st.Pool[0])
	}
	out := waitForLog(t, g, "error_kind=socks_connect", 5*time.Second)
	if !strings.Contains(out, "attempts=2") {
		t.Fatalf("logs missing fallback attempts=2:\n%s", out)
	}
}

// Target HTTP statuses pass through the tunnel untouched: the gateway is a pure
// TCP relay once CONNECT succeeds, so a 407/429/5xx from the origin reaches the
// client as-is and never touches route health. There is no hop-by-hop header
// processing in the gateway (the tunnel carries client HTTP verbatim), so the
// old Proxy-Authorization assertion now lives in the tunnel relay overhang.
func TestE2E_TargetStatusesPassThrough(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	for _, status := range []int{http.StatusProxyAuthRequired, http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			socks := NewSocksSim(t, SocksOK, "", "")
			target := NewStatusTarget(t, status, "e2e-status")
			g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
				{Proxy: socks.RouteValue(), Kind: "v4"},
			}))

			resp, err := ProxyClient(g.MixedAddr).Get(target.URL + "/")
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != status || string(body) != "e2e-status" {
				t.Fatalf("status=%d body=%q", resp.StatusCode, body)
			}
			st, _ := g.Status()
			if st.Pool[0].Successes != 1 || st.Pool[0].Failures != 0 {
				t.Fatalf("target status changed health: %+v", st.Pool[0])
			}
			if got := socks.Hits.Load(); got != 1 {
				t.Fatalf("SOCKS attempts=%d, want 1", got)
			}
		})
	}
}

func TestE2E_NoCredentialLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	user, pass := "e2e-leak-user", "e2e-leak-pass-9f8"
	route := fmt.Sprintf("socks5://%s:%s@%s", user, pass, socks.Addr)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: route, Kind: "v4"},
	}))

	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/", "e2e-echo:/")
	waitForLog(t, g, "msg=tunnel", 5*time.Second)

	resp, err := http.Get("http://" + g.AdminAddr + "/status")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{user, pass} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("/status leaked credential %q: %s", secret, raw)
		}
		if strings.Contains(g.Logs(), secret) {
			t.Fatalf("logs leaked credential %q:\n%s", secret, g.Logs())
		}
	}
}

// Manual routes serve traffic like auto routes, but their credentials,
// rotate-API URL, headers, and body never reach /status or logs. The route's
// public egress IP is the only rotation detail /status exposes.
func TestE2E_ManualRouteServesWithoutExposingSecrets(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	const proxySecret, apiToken, apiHeader = "e2e-manual-secret", "e2e-api-token", "e2e-api-header"
	socks := NewSocksSim(t, SocksOK, "manual-user", proxySecret)
	target := NewEchoTarget(t)
	trace := NewTraceSim(t, "203.0.113.1")
	api := NewRotateAPISim(t)
	cfg := defaultGatewayConfig(nil)
	cfg.Manual = []ManualRouteConfig{{
		Proxy:          "socks5://manual-user:" + proxySecret + "@" + socks.Addr,
		Kind:           "v4",
		RotateInterval: "1h", // no rotation fires during the test
		API: ManualAPIConfig{
			URL:     api.URL,
			Method:  "POST",
			Timeout: "2s",
			Headers: map[string]string{"Content-Type": "application/json", "X-Api-Token": apiHeader},
			Body:    `{"proxy_id": 1, "token": "` + apiToken + `"}`,
		},
	}}
	cfg.Rotation = &RotationConfig{
		MaxConcurrent:   "1",
		DrainTimeout:    "2s",
		IPCheckURL:      trace.URL,
		IPCheckTimeout:  "3s",
		IPCheckInterval: "100ms",
	}
	g := NewGatewayWithEnv(t, cfg, "SSL_CERT_FILE="+trace.CAFile)

	// The pool's only route is the manual one, so a successful request
	// proves manual routes serve.
	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/", "e2e-echo:/")
	waitForLog(t, g, "msg=tunnel", 5*time.Second)
	// Wait out the boot baseline precheck so its logging is complete before
	// the leak assertions below.
	waitRotation(t, g, socks, "recorded its boot baseline", func(v *RotationView) bool {
		return v != nil && v.LastIP == "203.0.113.1"
	}, 10*time.Second)

	if api.Hits.Load() != 0 {
		t.Fatalf("rotate API called outside a rotation: %d hits", api.Hits.Load())
	}
	st, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Pool) != 1 || st.Pool[0].Proxy != socks.Addr || st.Pool[0].Kind != "v4" {
		t.Fatalf("manual route exposed its endpoint address: %+v", st.Pool)
	}
	if st.Pool[0].Origin != "manual" || st.Pool[0].Rotation == nil {
		t.Fatalf("manual route not reported as manual rotation state: %+v", st.Pool[0])
	}
	resp, err := http.Get("http://" + g.AdminAddr + "/status")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	for _, secret := range []string{proxySecret, "manual-user", apiToken, apiHeader, "api/rotate"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("/status exposed manual route secret %q: %s", secret, raw)
		}
		if strings.Contains(g.Logs(), secret) {
			t.Fatalf("logs exposed manual route secret %q:\n%s", secret, g.Logs())
		}
	}
}

// Protocol-level conformance against the real binary. These requests never
// advance the request counter and never touch the pool.

// A well-formed BIND (cmd 0x02) and UDP ASSOCIATE (cmd 0x03) get reply code
// 0x07 (command not supported).
func TestE2E_InboundUnsupportedCommandsGetCmdReply(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}))

	for _, cmd := range []byte{0x02, 0x03} {
		frame := []byte{0x05, cmd, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90}
		head, rest, err := socksProbe(t, g.MixedAddr, nil, frame)
		if err != nil {
			t.Fatalf("cmd 0x%02x: probe: %v", cmd, err)
		}
		if head[0] != 0x05 || head[1] != 0x07 {
			t.Fatalf("cmd 0x%02x: reply head %v, want 05 07", cmd, head)
		}
		_ = rest
	}

	st, _ := g.Status()
	if st.Listeners["mixed"].Requests != 0 {
		t.Fatalf("rejected commands advanced the request counter: %+v", st.Listeners)
	}
	if got := socks.Hits.Load(); got != 0 {
		t.Fatalf("SOCKS attempts=%d, want 0 (no route dialed)", got)
	}
}

// A malformed frame (bad version, unknown ATYP) gets NO reply frame: the
// connection just closes, per RFC 1928, and the pool stays untouched.
func TestE2E_InboundMalformedFramesCloseWithoutReply(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}))

	cases := map[string][]byte{
		"bad version":  {0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90},
		"unknown atyp": {0x05, 0x01, 0x00, 0x09, 127, 0, 0, 1, 0x1f, 0x90},
	}
	for name, frame := range cases {
		t.Run(name, func(t *testing.T) {
			head, _, err := socksProbe(t, g.MixedAddr, nil, frame)
			if err == nil {
				t.Fatalf("probe unexpectedly got a reply head %v", head)
			}
			// The server must send NO reply frame: the client observes a closed
			///reset connection (EOF, ErrUnexpectedEOF, or ECONNRESET), never a
			// 0x01/0x07-style reply with bytes.
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !isConnResetError(err) {
				t.Fatalf("probe error=%v, want EOF/UnexpectedEOF/reset from a closed connection", err)
			}
		})
	}

	st, _ := g.Status()
	if st.Listeners["mixed"].Requests != 0 {
		t.Fatalf("malformed requests advanced the request counter: %+v", st.Listeners)
	}
	if got := socks.Hits.Load(); got != 0 {
		t.Fatalf("SOCKS attempts=%d, want 0 (no route dialed)", got)
	}
}

// No route dialed on a greeting-level reject: the client offering no 0x00
// method gets 05 ff and the connection closes.
func TestE2E_InboundGreetingReject(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	cfg := defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	})
	cfg.LogLevel = "debug" // protocol rejects log at debug
	g := NewGateway(t, cfg)

	conn, err := net.DialTimeout("tcp", g.MixedAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	// Offer only username/password auth: the server accepts NO AUTHENTICATION
	// REQUIRED exclusively.
	_, _ = conn.Write([]byte{0x05, 0x01, 0x02})
	choice := make([]byte, 2)
	if _, err := io.ReadFull(conn, choice); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if choice[0] != 0x05 || choice[1] != 0xff {
		t.Fatalf("method selection=%v, want 05 ff", choice)
	}

	st, _ := g.Status()
	if st.Listeners["mixed"].Requests != 0 {
		t.Fatalf("greeting reject advanced the request counter: %+v", st.Listeners)
	}
	if got := socks.Hits.Load(); got != 0 {
		t.Fatalf("SOCKS attempts=%d, want 0 (no route dialed)", got)
	}
	waitForLog(t, g, "error_kind=bad_request", 5*time.Second)
}
