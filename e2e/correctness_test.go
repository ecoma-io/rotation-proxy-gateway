package e2e_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
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

func deadRouteValue(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "socks5://" + addr
}

// postVia sends a POST with the given payload through a gateway listener and
// returns the status plus the echoed body.
func postVia(t *testing.T, client *http.Client, targetURL string, payload []byte) (int, []byte) {
	t.Helper()
	resp, err := client.Post(targetURL+"/body", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// Bodies at or under max-body-buffer are buffered and therefore replayable:
// a dial or auth fallback must still deliver the whole request body.
func TestE2E_POSTReplayAfterDialFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	good := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoBodyTarget(t)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: deadRouteValue(t), Kind: "v4"},
		{Proxy: good.RouteValue(), Kind: "v4"},
	}))

	payload := bytes.Repeat([]byte("b"), 1024) // buffered: far under the 64MiB cap
	status, body := postVia(t, ProxyClient(g.MixedAddr), target.URL, payload)
	if status != http.StatusOK || !bytes.Equal(body, payload) {
		t.Fatalf("status=%d len(body)=%d, want 200 with the full payload replayed", status, len(body))
	}

	g.WaitForCondition(5*time.Second, "POST dial fallback recorded", func(st *Status) bool {
		return len(st.Pool) == 2 && st.Pool[0].Failures == 1 && st.Pool[1].Successes == 1
	})
}

func TestE2E_POSTReplayAfterAuthFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	bad := NewSocksSim(t, SocksAuthRequired, "e2e-user", "e2e-pass")
	good := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoBodyTarget(t)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: "socks5://wrong-user:wrong-pass@" + bad.Addr, Kind: "v4"},
		{Proxy: good.RouteValue(), Kind: "v4"},
	}))

	payload := bytes.Repeat([]byte("a"), 2048)
	status, body := postVia(t, ProxyClient(g.MixedAddr), target.URL, payload)
	if status != http.StatusOK || !bytes.Equal(body, payload) {
		t.Fatalf("status=%d len(body)=%d, want 200 with the full payload replayed", status, len(body))
	}

	st := g.WaitForCondition(5*time.Second, "POST auth fallback recorded", func(st *Status) bool {
		return len(st.Pool) == 2 && st.Pool[0].AuthBlocked && st.Pool[0].AuthFailures == 1 && st.Pool[1].Successes == 1
	})
	if st.Pool[0].Failures != 0 || st.Pool[0].CooldownFor != "0s" {
		t.Fatalf("auth fallback created dial health damage: %+v", st.Pool[0])
	}
}

// A body known larger than max-body-buffer streams immediately. A setup
// failure is terminal: no fallback, the second route is never dialed.
func TestE2E_LargePOSTSetupFailureDoesNotRetry(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	reject := NewSocksSim(t, SocksRejectTarget, "", "")
	good := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoBodyTarget(t)
	cfg := defaultGatewayConfig([]RouteConfig{
		{Proxy: reject.RouteValue(), Kind: "v4"},
		{Proxy: good.RouteValue(), Kind: "v4"},
	})
	cfg.MaxBodyBuffer = 1024 // 4KiB payload is known-large: streams immediately
	g := NewGateway(t, cfg)

	payload := bytes.Repeat([]byte("s"), 4096)
	status, body := postVia(t, ProxyClient(g.MixedAddr), target.URL, payload)
	if status != http.StatusBadGateway || string(body) != "upstream SOCKS setup failed\n" {
		t.Fatalf("status=%d body=%q, want sanitized 502", status, body)
	}
	if got := good.Hits.Load(); got != 0 {
		t.Fatalf("fallback dialed the good route %d times after a setup failure", got)
	}
	st, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Pool[0].Available || st.Pool[0].Failures != 0 || st.Pool[0].Successes != 0 {
		t.Fatalf("setup failure changed health: %+v", st.Pool[0])
	}
	if st.Pool[1].Successes != 0 {
		t.Fatalf("good route recorded activity: %+v", st.Pool[1])
	}
}

// A streamed body that fails before the route is dialed must be replayed in
// full on the fallback: the echo proves no bytes were consumed.
func TestE2E_LargePOSTDialFailureRetriesWithFullBody(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	good := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoBodyTarget(t)
	cfg := defaultGatewayConfig([]RouteConfig{
		{Proxy: deadRouteValue(t), Kind: "v4"},
		{Proxy: good.RouteValue(), Kind: "v4"},
	})
	cfg.MaxBodyBuffer = 1024 // 4KiB payload streams; ContentLength is known
	g := NewGateway(t, cfg)

	payload := bytes.Repeat([]byte("d"), 4096)
	status, body := postVia(t, ProxyClient(g.MixedAddr), target.URL, payload)
	if status != http.StatusOK || !bytes.Equal(body, payload) {
		t.Fatalf("status=%d len(body)=%d, want 200 with all 4096 bytes echoed", status, len(body))
	}

	g.WaitForCondition(5*time.Second, "streamed dial fallback recorded", func(st *Status) bool {
		return len(st.Pool) == 2 && st.Pool[0].Failures == 1 && st.Pool[1].Successes == 1
	})
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

	// v6 listener has no eligible route: ordinary no-route 502.
	resp, err := ProxyClient(g.V6Addr).Get(target.URL + "/hello")
	if err != nil {
		t.Fatalf("v6 GET: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("v6 status=%d, want 502", resp.StatusCode)
	}

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

	resp, err := ProxyClient(g.V4Addr).Get(target.URL + "/x")
	if err != nil {
		t.Fatalf("v4 GET: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("v4 status=%d, want 502", resp.StatusCode)
	}
}

func TestE2E_HTTPSAbsoluteFormThroughGateway(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target := NewTLSEchoTarget(t)
	cfg := defaultGatewayConfig([]RouteConfig{{Proxy: socks.RouteValue(), Kind: "v4"}})
	cfg.TLSInsecure = true
	g := NewGateway(t, cfg)

	status, _, body := RawProxyRequest(t, g.MixedAddr, http.MethodGet, target.URL+"/secure", nil, nil)
	if status != http.StatusOK || string(body) != "e2e-tls-echo" {
		t.Fatalf("status=%d body=%q", status, body)
	}
}

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
	defer resp.Body.Close()
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
	if st.Rotations < 1 {
		t.Fatalf("rotations=%d, want >=1", st.Rotations)
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

func TestE2E_SetupFailureSingleSanitized502(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	reject := NewSocksSim(t, SocksRejectTarget, "", "")
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: reject.RouteValue(), Kind: "v4"},
	}))

	resp, err := ProxyClient(g.MixedAddr).Get("http://example.com/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status=%d, want 502", resp.StatusCode)
	}
	if string(body) != "upstream SOCKS setup failed\n" {
		t.Fatalf("502 body=%q, want sanitized message", body)
	}
	st, _ := g.Status()
	snap := st.Pool[0]
	if snap.Successes != 0 || snap.Failures != 0 || snap.AuthFailures != 0 || !snap.Available {
		t.Fatalf("setup failure changed health: %+v", snap)
	}
	if got := reject.Hits.Load(); got != 1 {
		t.Fatalf("SOCKS attempts=%d, want 1 (no retry)", got)
	}
}

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
			resp.Body.Close()
			if resp.StatusCode != status || string(body) != "e2e-status" {
				t.Fatalf("status=%d body=%q", resp.StatusCode, body)
			}
			if resp.Header.Get("Proxy-Authorization") != "" {
				t.Fatal("Proxy-Authorization response header reached client")
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

func TestE2E_HopByHopStrippedUpstream(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	seen := make(chan http.Header, 1)
	target := NewHeaderCaptureTarget(t, seen)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}))

	req, _ := http.NewRequest(http.MethodGet, target.URL+"/", nil)
	req.Header.Set("X-Keep", "1")
	req.Header.Set("Proxy-Authorization", "Basic c2VjcmV0")
	req.Header.Set("Connection", "X-Drop")
	req.Header.Set("X-Drop", "yes")
	resp, err := ProxyClient(g.MixedAddr).Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	select {
	case h := <-seen:
		if h.Get("X-Keep") != "1" {
			t.Fatal("X-Keep was stripped")
		}
		for _, name := range []string{"Proxy-Authorization", "X-Drop"} {
			if h.Get(name) != "" {
				t.Fatalf("%s reached upstream", name)
			}
		}
		// The gateway scopes each SOCKS tunnel to one request (Close=true),
		// so net/http re-adds "Connection: close" on the wire. The contract
		// is that the client's Connection tokens (X-Drop) are gone, not that
		// the header itself is absent.
		if got := h.Get("Connection"); got != "" && got != "close" {
			t.Fatalf("upstream Connection=%q, want empty or close", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("target never saw the request")
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
	waitForLog(t, g, "msg=request", 5*time.Second)

	resp, err := http.Get("http://" + g.AdminAddr + "/status")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
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

// The manual section is accepted but ignored: its contents never reach the
// pool, /status, or logs, and no API request is made on its behalf.
func TestE2E_ManualSectionIgnoredAndNeverExposed(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	cfg := defaultGatewayConfig([]RouteConfig{{Proxy: socks.RouteValue(), Kind: "v4"}})
	cfg.Manual = `    - proxy: 'socks5://manual-user:e2e-manual-secret@manual.example:1080'
      kind: v6
      interval: 90
      api:
        url: http://provider.example/api/rotate-ip
        method: POST
        headers:
          - Content-Type: application/json
        body: |
          {"proxy_id": 1, "token": "e2e-manual-secret"}`
	g := NewGateway(t, cfg)

	GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/", "e2e-echo:/")
	waitForLog(t, g, "msg=request", 5*time.Second)

	resp, err := http.Get("http://" + g.AdminAddr + "/status")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, secret := range []string{"e2e-manual-secret", "manual.example", "rotate-ip"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("/status exposed manual section entry %q: %s", secret, raw)
		}
		if strings.Contains(g.Logs(), secret) {
			t.Fatalf("logs exposed manual section entry %q:\n%s", secret, g.Logs())
		}
	}
	st, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Pool) != 1 || st.Pool[0].Proxy != socks.Addr || st.Pool[0].Kind != "v4" {
		t.Fatalf("manual section leaked into the pool: %+v", st.Pool)
	}
}

// An HTTPS target whose TLS handshake fails inside the SOCKS tunnel is a
// setup failure: one sanitized 502, no fallback, no health mutation. This
// runs with the secure default (target-tls-insecure: false), which must
// actually verify certificates.
func TestE2E_TargetTLSFailureIsSingleSanitized502(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target := NewTLSEchoTarget(t) // self-signed: the secure default rejects it
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}))

	status, _, body := RawProxyRequest(t, g.MixedAddr, http.MethodGet, target.URL+"/secure", nil, nil)
	if status != http.StatusBadGateway || string(body) != "upstream SOCKS setup failed\n" {
		t.Fatalf("status=%d body=%q, want sanitized 502", status, body)
	}
	if got := socks.Hits.Load(); got != 1 {
		t.Fatalf("SOCKS attempts=%d, want 1 (no retry)", got)
	}
	st, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Pool[0].Available || st.Pool[0].Failures != 0 || st.Pool[0].Successes != 0 {
		t.Fatalf("TLS handshake failure changed health: %+v", st.Pool[0])
	}
}

// Non-absolute-form and non-HTTP(S) request targets are rejected with 400
// before any route is dialed, leaving the pool untouched.
func TestE2E_InvalidAbsoluteFormRequestsAreRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}))

	rawGet := func(t *testing.T, requestLine, host string) (int, string) {
		t.Helper()
		conn, err := net.DialTimeout("tcp", g.MixedAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial mixed listener: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		fmt.Fprintf(conn, "%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", requestLine, host) //nolint:errcheck // the response code is the assertion
		resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
		if err != nil {
			t.Fatalf("read rejection response: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	for name, tc := range map[string]struct{ line, host string }{
		"origin-form path": {"GET /only-a-path", "example.com"},
		"ftp scheme":       {"GET ftp://example.com/file", "example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			status, body := rawGet(t, tc.line, tc.host)
			if status != http.StatusBadRequest || !strings.Contains(body, "proxy request requires") {
				t.Fatalf("status=%d body=%q, want 400 with a rejection message", status, body)
			}
		})
	}
	waitForLog(t, g, "error_kind=bad_request", 5*time.Second)
	if got := socks.Hits.Load(); got != 0 {
		t.Fatalf("SOCKS attempts=%d, want 0 for rejected requests", got)
	}
	st, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Pool[0].Successes != 0 || st.Pool[0].Failures != 0 {
		t.Fatalf("rejected requests changed health: %+v", st.Pool[0])
	}
}
