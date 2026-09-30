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

// logRecord is one decoded JSON log line from the gateway process. The
// gateway logs zerolog JSON on stdout, so assertions match fields, not text.
type logRecord map[string]any

func decodeLogRecords(output string) []logRecord {
	var recs []logRecord
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec logRecord
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		recs = append(recs, rec)
	}
	return recs
}

// recordHas reports whether rec carries every wanted key with an equal string
// rendering (JSON numbers decode as float64, which fmt.Sprint normalizes:
// float64(2) renders "2").
func recordHas(rec logRecord, want map[string]string) bool {
	for k, v := range want {
		got, ok := rec[k]
		if !ok || fmt.Sprint(got) != v {
			return false
		}
	}
	return true
}

func recordHasKey(rec logRecord, key string) bool {
	_, ok := rec[key]
	return ok
}

func findLogRecord(recs []logRecord, want map[string]string) (logRecord, bool) {
	for _, rec := range recs {
		if recordHas(rec, want) {
			return rec, true
		}
	}
	return nil, false
}

// waitForLogRecord polls the gateway log until one record carries every
// wanted key/value pair, then returns the whole decoded log for further
// record-scoped assertions.
func waitForLogRecord(t *testing.T, g *Gateway, want map[string]string, timeout time.Duration) []logRecord {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		recs := decodeLogRecords(g.Logs())
		if _, ok := findLogRecord(recs, want); ok {
			return recs
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("logs missing record %v:\n%s", want, g.Logs())
	return nil
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

// deadRouteValue produces a loopback address whose listener is already
// closed, simulating a dead route endpoint. The address flows through the
// same handedOut registry as freeAddr: the OS can re-issue the just-freed
// ephemeral port to the next bind, and an unregistered "dead" address could
// later be handed to a live sim or gateway listener — flipping dial-refusal
// assertions to successes or failing unrelated binds.
func deadRouteValue(t *testing.T) string {
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

// failedTunnel asserts the gateway rejects the request with a status the
// ingress contract allows for a request it cannot serve: no-route exhaustion
// (503) and upstream setup failures (502) surface to a client as an HTTP
// status. It fails the test when the request unexpectedly establishes; the
// rejection is the pass.
func failedTunnel(t *testing.T, proxyAddr, target string) {
	t.Helper()
	conn, err := connectTunnel(context.Background(), proxyAddr, target)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("CONNECT %s through %s unexpectedly succeeded", target, proxyAddr)
	}
	status := httpStatusOf(err)
	if !isHTTPGatewayFailure(status) {
		t.Fatalf("CONNECT %s through %s: error=%v, want 502 or 503", target, proxyAddr, err)
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

	// v6 listener has no eligible route: the CONNECT is rejected and the
	// tunnel fails to establish.
	failedTunnel(t, g.V6Addr, target.Host)

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

	failedTunnel(t, g.V4Addr, target.Host)
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
	recs := waitForLogRecord(t, g, map[string]string{"error_kind": "proxy_connect"}, 5*time.Second)
	if _, ok := findLogRecord(recs, map[string]string{"msg": "tunnel", "attempts": "2"}); !ok {
		t.Fatalf("logs missing the fallback tunnel record with attempts=2:\n%s", g.Logs())
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
	badNoCreds := bad.Addr
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
	recs := waitForLogRecord(t, g, map[string]string{"error_kind": "auth_route"}, 5*time.Second)
	for _, rec := range recs {
		// No record in this test may carry a cooldown: the only failure is the
		// auth block, which never creates dial cooldown.
		if recordHasKey(rec, "cooldown") {
			t.Fatalf("auth fallback logged a cooldown: %v", rec)
		}
	}
}

// With a single route whose SOCKS handshake dies before a CONNECT reply (the
// route-scoped socks_connect flavor), the route is excluded within the
// request: the pool exhausts to a no-route gateway reject while the failure
// is recorded in route health.
func TestE2E_SocksHandshakeFailureExhaustsToNoRoute(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	reject := NewSocksSim(t, SocksDropConnect, "", "")
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: reject.RouteValue(), Kind: "v4"},
	}))

	failedTunnel(t, g.MixedAddr, "example.com:80")
	if got := reject.Hits.Load(); got != 1 {
		t.Fatalf("SOCKS attempts=%d, want 1 (route excluded after one handshake failure)", got)
	}

	st := g.WaitForCondition(5*time.Second, "handshake failure recorded", func(st *Status) bool {
		return len(st.Pool) == 1 && st.Pool[0].Failures == 1
	})
	if st.Pool[0].CooldownFor == "0s" {
		t.Fatalf("rejecting route should cool down: %+v", st.Pool[0])
	}
	recs := waitForLogRecord(t, g, map[string]string{"error_kind": "socks_connect"}, 5*time.Second)
	rec, ok := findLogRecord(recs, map[string]string{"error_kind": "socks_connect"})
	if !ok || !recordHasKey(rec, "cooldown") {
		t.Fatalf("handshake failure record missing cooldown: %v", rec)
	}
}

func TestE2E_HandshakeFailureFallsBackWithCooldown(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	reject := NewSocksSim(t, SocksDropConnect, "", "")
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
	recs := waitForLogRecord(t, g, map[string]string{"error_kind": "socks_connect"}, 5*time.Second)
	if _, ok := findLogRecord(recs, map[string]string{"msg": "tunnel", "attempts": "2"}); !ok {
		t.Fatalf("logs missing the fallback tunnel record with attempts=2:\n%s", g.Logs())
	}
}

func TestE2E_ConnectTunnelHandshakeFailureFallsBack(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	reject := NewSocksSim(t, SocksDropConnect, "", "")
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
	recs := waitForLogRecord(t, g, map[string]string{"error_kind": "socks_connect"}, 5*time.Second)
	if _, ok := findLogRecord(recs, map[string]string{"msg": "tunnel", "attempts": "2"}); !ok {
		t.Fatalf("logs missing the fallback tunnel record with attempts=2:\n%s", g.Logs())
	}
}

// Target HTTP statuses reach the client untouched on both ingress shapes: a
// CONNECT tunnel is a pure TCP relay, and an absolute-form request keeps the
// origin's own status, so a 407/429/5xx from the origin arrives as-is and
// never touches route health. There is no hop-by-hop header processing in the
// gateway on either shape.
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
	route := fmt.Sprintf("%s:%s@%s", user, pass, socks.Addr)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: route, Kind: "v4"},
	}))

	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/", "e2e-echo:/")
	waitForLogRecord(t, g, map[string]string{"msg": "tunnel"}, 5*time.Second)

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
		Proxy:          "manual-user:" + proxySecret + "@" + socks.Addr,
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
	waitForLogRecord(t, g, map[string]string{"msg": "tunnel"}, 5*time.Second)
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

// A method an HTTP forward proxy must not act on gets 405, and a request
// version it cannot speak gets 505. Neither dials a route.
func TestE2E_InboundUnsupportedMethodAndVersionRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	cfg := defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	})
	cfg.LogLevel = "debug" // protocol rejects log at debug
	g := NewGateway(t, cfg)

	cases := []struct {
		name    string
		method  string
		request string
		want    int
	}{
		{"method not allowed", http.MethodPut,
			"PUT http://example.test/x HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n",
			http.StatusMethodNotAllowed},
		{"http version not supported", http.MethodGet,
			"GET http://example.test/x HTTP/9.9\r\nHost: example.test\r\n\r\n",
			http.StatusHTTPVersionNotSupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := httpProbe(t, g.MixedAddr, tc.method, tc.request)
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			if res.StatusCode != tc.want {
				t.Fatalf("status = %d %q, want %d (%s)", res.StatusCode, res.Status, tc.want,
					http.StatusText(tc.want))
			}
			_ = res.Rest
		})
	}

	st, _ := g.Status()
	if st.Listeners["mixed"].Requests != 0 {
		t.Fatalf("rejected requests advanced the request counter: %+v", st.Listeners)
	}
	if got := socks.Hits.Load(); got != 0 {
		t.Fatalf("SOCKS attempts=%d, want 0 (no route dialed)", got)
	}
}

// A malformed request line gets 400 and closes the connection. The gateway
// must not route it, and a client that opened a tunnel to it must see the
// close rather than hang.
func TestE2E_InboundMalformedRequestLineRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	cfg := defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	})
	cfg.LogLevel = "debug" // protocol rejects log at debug
	g := NewGateway(t, cfg)

	cases := map[string]string{
		"nonsense request line": "BOGUS\r\n\r\n",
		"no version":            "GET http://example.test/x\r\nHost: example.test\r\n\r\n",
		"empty request line":    "\r\n\r\n",
	}
	for name, request := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := httpProbe(t, g.MixedAddr, http.MethodGet, request)
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			if res.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d %q, want 400", res.StatusCode, res.Status)
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
	waitForLogRecord(t, g, map[string]string{"error_kind": "bad_request"}, 5*time.Second)
}
