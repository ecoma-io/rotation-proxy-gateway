package e2e_test

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The HTTP forward-proxy ingress contract, against the real binary: CONNECT
// opens a byte-transparent tunnel, an absolute-form request is forwarded to its
// origin in origin form, RPGW_ACCOUNT gates both shapes with
// Proxy-Authorization, and everything the gateway must not forward — the
// client's own credentials, its own x-ecoma-* headers — is dropped on the way
// out.

// authedProxyClient is ProxyClient with Proxy-Authorization set on every
// request, which an armed RPGW_ACCOUNT requires.
func authedProxyClient(proxyAddr, username, password string) *http.Client {
	header := proxyAuthHeader(username, password)
	c := ProxyClient(proxyAddr)
	inner := c.Transport
	c.Transport = &headerTransport{base: inner, header: header}
	return c
}

// headerTransport sets one header on every request.
type headerTransport struct {
	base   http.RoundTripper
	header string
}

func (t *headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.Header.Set("Proxy-Authorization", t.header)
	return t.base.RoundTrip(clone)
}

// CONNECT then HTTP inside the tunnel: the reply is 200 and the exchange that
// follows is relayed byte for byte, so the origin sees the client's own
// request and answers with its own body.
func TestE2E_ConnectThenHTTPInsideTunnel(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target, seen := NewRequestLineEchoTarget(t)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}))

	conn := tunnelFor(t, g.MixedAddr, target.Host)
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(conn, "GET /inside HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target.Host); err != nil {
		t.Fatalf("write in-tunnel request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read in-tunnel response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "origin-ok" {
		t.Fatalf("in-tunnel status=%d body=%q, want 200 origin-ok", resp.StatusCode, body)
	}

	obs := ReadObservedRequest(t, seen, 5*time.Second)
	if obs.RequestLine != "GET /inside HTTP/1.1" {
		t.Fatalf("origin request line = %q, want the tunneled %q", obs.RequestLine, "GET /inside HTTP/1.1")
	}
	if obs.Host != target.Host {
		t.Fatalf("origin Host = %q, want %q", obs.Host, target.Host)
	}
}

// An absolute-form GET succeeds and reaches the origin in origin form: the
// gateway strips the scheme and authority, and the Host header names the
// target the client asked for.
func TestE2E_AbsoluteFormGETForwardsOriginForm(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target, seen := NewRequestLineEchoTarget(t)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}))

	status, body := GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/absolute?x=1", "origin-ok")
	if status != http.StatusOK {
		t.Fatalf("status=%d, want 200", status)
	}
	_ = body

	obs := ReadObservedRequest(t, seen, 5*time.Second)
	if obs.RequestLine != "GET /absolute?x=1 HTTP/1.1" {
		t.Fatalf("origin request line = %q, want the origin form %q", obs.RequestLine, "GET /absolute?x=1 HTTP/1.1")
	}
	if obs.Host != target.Host {
		t.Fatalf("origin Host = %q, want %q", obs.Host, target.Host)
	}
}

// An armed RPGW_ACCOUNT gates both ingress shapes: 407 with the gateway's Basic
// realm for missing and wrong credentials, and 200 once the correct pair
// arrives — on CONNECT and on an absolute-form GET alike.
func TestE2E_InboundAccountAuthsBothShapes(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	const user, pass = "e2e-user", "e2e-pass"
	socks := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	g := NewGatewayWithEnv(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}), "RPGW_ACCOUNT="+user+":"+pass)

	t.Run("connect", func(t *testing.T) {
		connect := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n%%s\r\n\r\n", target.Host, target.Host)

		for _, tc := range []struct {
			name       string
			extra      string
			wantStatus int
		}{
			{"missing credentials", "", http.StatusProxyAuthRequired},
			{"wrong credentials", "Proxy-Authorization: Basic " +
				base64.StdEncoding.EncodeToString([]byte(user+":wrong")) + "\r\n", http.StatusProxyAuthRequired},
			{"correct credentials", "Proxy-Authorization: " + proxyAuthHeader(user, pass) + "\r\n", http.StatusOK},
		} {
			t.Run(tc.name, func(t *testing.T) {
				res, err := httpProbe(t, g.MixedAddr, http.MethodConnect, fmt.Sprintf(connect, tc.extra))
				if err != nil {
					t.Fatalf("probe: %v", err)
				}
				if res.StatusCode != tc.wantStatus {
					t.Fatalf("CONNECT status = %d, want %d", res.StatusCode, tc.wantStatus)
				}
			})
		}
	})

	t.Run("absolute form", func(t *testing.T) {
		get := target.URL + "/authed"
		for _, tc := range []struct {
			name       string
			user, pass string
			wantStatus int
		}{
			{"missing credentials", "", "", http.StatusProxyAuthRequired},
			{"wrong credentials", user, "wrong", http.StatusProxyAuthRequired},
			{"correct credentials", user, pass, http.StatusOK},
		} {
			t.Run(tc.name, func(t *testing.T) {
				req, err := http.NewRequest(http.MethodGet, get, nil)
				if err != nil {
					t.Fatal(err)
				}
				if tc.user != "" || tc.pass != "" {
					req.Header.Set("Proxy-Authorization", proxyAuthHeader(tc.user, tc.pass))
				}
				resp, err := ProxyClient(g.MixedAddr).Do(req)
				if err != nil {
					t.Fatalf("GET: %v", err)
				}
				defer func() { _ = resp.Body.Close() }()
				body, _ := io.ReadAll(resp.Body)
				if resp.StatusCode != tc.wantStatus {
					t.Fatalf("GET status = %d body=%q, want %d", resp.StatusCode, body, tc.wantStatus)
				}
				if tc.wantStatus == http.StatusOK && string(body) != "e2e-echo:/authed" {
					t.Fatalf("GET body = %q, want the origin's own echo", body)
				}
			})
		}
	})

	// Only the two authenticated CONNECTs and the correct absolute-form GET
	// reach route selection. Every 407 is pre-selection.
	st, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Requests != 2 {
		t.Fatalf("gateway requests = %d, want 2 (the correct CONNECT and GET only)", st.Requests)
	}
	if len(st.Pool) != 1 || st.Pool[0].Successes != 2 {
		t.Fatalf("pool = %+v, want exactly the two authenticated successes", st.Pool)
	}
}

// An armed account answers 407 with the gateway's own realm, and the reject
// carries the header an HTTP client needs to retry with credentials.
func TestE2E_InboundAccountChallengeCarriesRealm(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	g := NewGatewayWithEnv(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}), "RPGW_ACCOUNT=e2e-user:e2e-pass")

	res, err := httpProbe(t, g.MixedAddr, http.MethodConnect,
		fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target.Host, target.Host))
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", res.StatusCode)
	}
	if got := res.Header.Get("Proxy-Authenticate"); !strings.Contains(got, `Basic realm="rotation-proxy-gateway"`) {
		t.Fatalf("Proxy-Authenticate = %q, want the gateway's Basic realm", got)
	}
}

// The client's own Proxy-Authorization is hop-by-hop: the origin must never see
// it, on either ingress shape. Only the tunneled request is in scope here —
// after a CONNECT the client cannot inject a header into the relay, so the
// absolute-form shape is what actually proves the strip.
func TestE2E_ProxyAuthorizationNotForwardedToTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	const user, pass = "e2e-user", "e2e-pass"
	socks := NewSocksSim(t, SocksOK, "", "")
	target, seen := NewRequestLineEchoTarget(t)
	g := NewGatewayWithEnv(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}), "RPGW_ACCOUNT="+user+":"+pass)

	req, err := http.NewRequest(http.MethodGet, target.URL+"/creds", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Proxy-Authorization", proxyAuthHeader(user, pass))
	resp, err := authedProxyClient(g.MixedAddr, user, pass).Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	obs := ReadObservedRequest(t, seen, 5*time.Second)
	if got := obs.Header.Get("Proxy-Authorization"); got != "" {
		t.Fatalf("origin saw Proxy-Authorization %q: the gateway forwarded a hop-by-hop header", got)
	}
}

// The gateway's x-ecoma-* headers must never reach the origin: the origin
// sees the client's request, not the gateway's bookkeeping. Do not name the
// later-phase individual headers here; this assertion holds the entire prefix
// boundary without claiming either future header exists yet.
func TestE2E_XEcomaHeadersNotForwardedToTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target, seen := NewRequestLineEchoTarget(t)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}))

	status, body := GetVia(t, ProxyClient(g.MixedAddr), target.URL+"/headers", "origin-ok")
	if status != http.StatusOK {
		t.Fatalf("status = %d body=%q, want 200", status, body)
	}

	obs := ReadObservedRequest(t, seen, 5*time.Second)
	for name, values := range obs.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-ecoma-") {
			t.Fatalf("origin saw %s: %v", name, values)
		}
	}
}

// A client that sends its CONNECT request head and its first payload in one
// write is the normal TLS-client shape, and the gateway must not lose the
// payload. net/http's parser buffers past the header block; the ingress has to
// hand the socket's own reader to the relay, or the first bytes of every
// pipelined tunnel are discarded and the tunnel stalls on its first read.
func TestE2E_PipelinedBytesAfterConnectReachTheTunnel(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target := NewPipelinedEchoTarget(t)
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}))

	conn, err := net.DialTimeout("tcp", g.MixedAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// One write: request head immediately followed by payload.
	payload := "pipelined-payload"
	head := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target.Host, target.Host)
	if _, err := fmt.Fprintf(conn, "%s%s", head, payload); err != nil {
		t.Fatalf("write pipelined CONNECT: %v", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	// Read through the same reader: the reply head and the echoed payload may
	// have arrived in one segment, and skipping buffered bytes here would
	// reproduce the bug this test exists to catch.
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(br, echoed); err != nil {
		t.Fatalf("read echoed payload: %v", err)
	}
	if string(echoed) != payload {
		t.Fatalf("echoed %q, want %q", echoed, payload)
	}
}

// A malformed request line is a local 400 on both ingress shapes, and the
// gateway must not route it.
func TestE2E_MalformedRequestLineIsBadRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	cfg := defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	})
	cfg.LogLevel = "debug" // protocol rejects log at debug
	g := NewGateway(t, cfg)

	cases := map[string]struct {
		method  string
		request string
	}{
		"connect shape": {http.MethodConnect, "CONNECT\r\n\r\n"},
		"absolute form": {http.MethodGet, "GET not-a-url HTTP/1.1\r\nHost: e2e\r\n\r\n"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := httpProbe(t, g.MixedAddr, tc.method, tc.request)
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			if res.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d %q, want 400", res.StatusCode, res.Status)
			}
		})
	}

	st, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Requests != 0 {
		t.Fatalf("malformed requests advanced the request counter: %d", st.Requests)
	}
	if got := socks.Hits.Load(); got != 0 {
		t.Fatalf("SOCKS attempts=%d, want 0 (no route dialed)", got)
	}
	// Both rejects are local setup errors, so the failure classifier keeps its
	// name rather than inheriting a route or upstream kind.
	waitForLogRecord(t, g, map[string]string{"error_kind": "bad_request"}, 5*time.Second)
}

// A target the gateway cannot reach must answer with a gateway status promptly,
// never hang: the route is dead, so the whole retry chain ends in one bounded
// refusal.
func TestE2E_UnreachableTargetRejectsPromptly(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	good := NewSocksSim(t, SocksOK, "", "")
	cfg := defaultGatewayConfig([]RouteConfig{
		{Proxy: deadRouteValue(t), Kind: "v4"},
		{Proxy: good.RouteValue(), Kind: "v4"},
	})
	cfg.DialTimeout = "5s"
	g := NewGateway(t, cfg)

	// Both shapes: the CONNECT the client opens itself, and an absolute-form
	// request through the proxy transport.
	t.Run("connect", func(t *testing.T) {
		start := time.Now()
		failedTunnel(t, g.MixedAddr, "example.test:80")
		if elapsed := time.Since(start); elapsed > 20*time.Second {
			t.Fatalf("CONNECT refusal took %s, want a bounded rejection", elapsed)
		}
	})
	t.Run("absolute form", func(t *testing.T) {
		start := time.Now()
		resp, err := ProxyClient(g.MixedAddr).Get("http://example.test/unreachable")
		if err != nil {
			t.Fatalf("absolute-form request: %v", err)
		}
		_ = resp.Body.Close()
		if !isHTTPGatewayFailure(resp.StatusCode) {
			t.Fatalf("status = %d, want 502 or 503", resp.StatusCode)
		}
		if elapsed := time.Since(start); elapsed > 20*time.Second {
			t.Fatalf("absolute-form refusal took %s, want a bounded rejection", elapsed)
		}
	})

	// A dead route must not stay hot: the refusal cools it and the healthy
	// route is admitted on the next request. /status lists the pool by recency
	// pass, so the cooled route is not necessarily index 0 — the assertion is
	// "exactly one route is cooling and the other still serves".
	st := g.WaitForCondition(20*time.Second, "the dead route to cool down", func(st *Status) bool {
		if len(st.Pool) != 2 {
			return false
		}
		cooling, available := 0, 0
		for _, route := range st.Pool {
			if route.Available {
				available++
			}
			if route.CooldownFor != "0s" {
				cooling++
			}
		}
		return cooling == 1 && available == 1
	})
	_ = st
}
