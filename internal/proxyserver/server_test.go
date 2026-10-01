package proxyserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/logging"
	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/socksdial"

	"github.com/rs/zerolog"
)

func testLogger() zerolog.Logger {
	return logging.Nop()
}

func captureLogger(w io.Writer) zerolog.Logger {
	return logging.New(w)
}

type safeLogBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *safeLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *safeLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// record is one decoded JSON log line.
type record map[string]any

func decodeRecords(output string) []record {
	var recs []record
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec record
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		recs = append(recs, rec)
	}
	return recs
}

// recordMatches reports whether rec carries every wanted key with an equal
// string rendering (JSON numbers decode as float64, which fmt.Sprint
// normalizes: float64(2) renders "2").
func recordMatches(rec record, want map[string]string) bool {
	for k, v := range want {
		got, ok := rec[k]
		if !ok || fmt.Sprint(got) != v {
			return false
		}
	}
	return true
}

func findRecord(output string, want map[string]string) (record, bool) {
	for _, rec := range decodeRecords(output) {
		if recordMatches(rec, want) {
			return rec, true
		}
	}
	return nil, false
}

func countRecords(output string, want map[string]string) int {
	n := 0
	for _, rec := range decodeRecords(output) {
		if recordMatches(rec, want) {
			n++
		}
	}
	return n
}

// waitForRecord polls the captured log until one record carries every wanted
// key/value pair, then returns the whole output for further checks.
func waitForRecord(t *testing.T, logs *safeLogBuffer, want map[string]string) string {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		output := logs.String()
		if _, ok := findRecord(output, want); ok {
			return output
		}
		if time.Now().After(deadline) {
			t.Fatalf("logs missing record %v:\n%s", want, output)
		}
		time.Sleep(time.Millisecond)
	}
}

func defaultRuntime() *config.RuntimeConfig {
	return &config.RuntimeConfig{
		MaxRetries:   3,
		DialTimeout:  2 * time.Second,
		CooldownBase: 30 * time.Second,
		CooldownMax:  time.Minute,
	}
}

func mixedRoutes(urls ...*url.URL) []config.RouteSpec {
	routes := make([]config.RouteSpec, 0, len(urls))
	for _, u := range urls {
		routes = append(routes, config.RouteSpec{URL: u, Kind: config.EgressV4})
	}
	return routes
}

func newRuntimeServer(pl *pool.Pool, runtime *config.RuntimeConfig, log zerolog.Logger, allowed ...config.EgressKind) *Server {
	// The store shares the test pool pointer so health assertions on pl keep
	// observing the serving pool until a test publishes a new generation.
	return NewRuntime(pool.NewStore(runtime, pl), log, "test", "mixed", allowed...)
}

// startServer runs srv on a live loopback listener and returns its address.
// Cleanup closes the listener, force-closes any session a test left parked,
// and waits for the accept loop to return.
func startServer(t *testing.T, srv *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(ln)
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		srv.CloseConns()
		select {
		case <-served:
		case <-time.After(time.Second):
			t.Errorf("Serve did not return after the listener closed")
		}
	})
	return ln.Addr().String()
}

// newProxyServer is the common "serve on a live loopback listener" shorthand
// every end-to-end unit test starts from.
func newProxyServer(t *testing.T, pl *pool.Pool, runtime *config.RuntimeConfig, log zerolog.Logger, allowed ...config.EgressKind) (*Server, string) {
	t.Helper()
	srv := newRuntimeServer(pl, runtime, log, allowed...)
	return srv, startServer(t, srv)
}

// --- HTTP ingress client helpers -------------------------------------------
//
// The data plane speaks HTTP forward proxy: one CONNECT or one absolute-form
// request per connection, each answered with a bodyless status line. These
// helpers replace the former SOCKS greeting and frame builders.

func dialGateway(t *testing.T, gatewayAddr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", gatewayAddr)
	if err != nil {
		t.Fatalf("dial gateway %s: %v", gatewayAddr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

// httpConnectRequest renders a conforming CONNECT request line and headers for
// an authority-form target ("host:port"). The Host header repeats the tunnel
// authority, so a well-behaved client never disagrees with its own request
// line; tests that need a disagreement build the frame themselves.
func httpConnectRequest(target string) []byte {
	return []byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n")
}

// httpForwardRequest renders one absolute-form forward-proxy request. Every
// header is passed verbatim — including a disagreeing Host, or none at all —
// so a test controls the authority it wants the gateway to see.
func httpForwardRequest(method, rawURL string, headers ...string) []byte {
	var frame strings.Builder
	frame.WriteString(method + " " + rawURL + " HTTP/1.1\r\n")
	for _, header := range headers {
		frame.WriteString(header + "\r\n")
	}
	frame.WriteString("\r\n")
	return []byte(frame.String())
}

// requestMethodOf recovers the request method from a rendered request frame so
// the response is parsed in the same conversation it belongs to.
func requestMethodOf(frame []byte) string {
	method, _, _ := bytes.Cut(frame, []byte(" "))
	return string(method)
}

// readIngressResponse parses one response header block. Every response the
// gateway itself writes is bodyless, so the caller may immediately reuse the
// connection as a raw tunnel byte stream; a relayed absolute-form response
// carries a real body, which the caller reads through the returned response.
func readIngressResponse(t *testing.T, br *bufio.Reader, method string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, "http://ingress.invalid/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("read ingress response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// httpTunnel is a CONNECT tunnel the gateway already answered 200 for. Reads go
// through br because the HTTP parser may have pulled the client's first tunnel
// bytes into its own buffer while framing headers; writes and closes go
// straight to the socket, which is what the server relays over.
type httpTunnel struct {
	net.Conn
	br *bufio.Reader
}

func (tun *httpTunnel) Read(p []byte) (int, error) { return tun.br.Read(p) }

// httpConnectReply sends one CONNECT request and returns the connection, the
// reader that still owns any bytes the header parser read ahead, and the
// status the gateway answered. It never judges the status: callers decide what
// a test expects.
func httpConnectReply(t *testing.T, gatewayAddr, target string) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	conn := dialGateway(t, gatewayAddr)
	if _, err := conn.Write(httpConnectRequest(target)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	return conn, br, readIngressResponse(t, br, http.MethodConnect).StatusCode
}

// httpConnectStatus sends one CONNECT and returns only the status it drew.
func httpConnectStatus(t *testing.T, gatewayAddr, target string) int {
	t.Helper()
	_, _, status := httpConnectReply(t, gatewayAddr, target)
	return status
}

// httpDialVia opens a CONNECT tunnel and fails the test unless the gateway
// answered 200.
func httpDialVia(t *testing.T, gatewayAddr, target string) *httpTunnel {
	t.Helper()
	conn, br, status := httpConnectReply(t, gatewayAddr, target)
	if status != http.StatusOK {
		t.Fatalf("CONNECT %s = %d, want 200", target, status)
	}
	// Established tunnels carry no timeouts.
	_ = conn.SetDeadline(time.Time{})
	return &httpTunnel{Conn: conn, br: br}
}

// parkClient sends one CONNECT and returns without reading a reply: the session
// is now parked wherever the server's dial seam puts it. The caller owns
// closing, and reads the parked session's answer through the returned reader.
func parkClient(t *testing.T, gatewayAddr, target string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn := dialGateway(t, gatewayAddr)
	if _, err := conn.Write(httpConnectRequest(target)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	return conn, bufio.NewReader(conn)
}

// httpForward sends one absolute-form request through the gateway and returns
// the response exactly as the client received it — the origin's own status,
// body, and headers.
func httpForward(t *testing.T, gatewayAddr string, frame []byte, method string) *http.Response {
	t.Helper()
	conn := dialGateway(t, gatewayAddr)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write forward request: %v", err)
	}
	return readIngressResponse(t, bufio.NewReader(conn), method)
}

// readBanner consumes the echo target's greeting bytes, proving the tunnel
// carries data from the upstream to the client before the client writes. It
// takes an io.Reader rather than a net.Conn because the HTTP header parser may
// have read the client's first tunnel bytes ahead: a test that already holds a
// *bufio.Reader must read through it or it would drop those bytes.
func readBanner(t *testing.T, conn io.Reader) string {
	t.Helper()
	banner := make([]byte, len("banner\n"))
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	return string(banner)
}

// --- raw protocol helpers --------------------------------------------------

// httpRejectCase is one inbound request the gateway must answer before route
// selection ever happens.
type httpRejectCase struct {
	name    string
	request []byte
	// wantStatus is the protocol status the gateway answers.
	wantStatus int
	// truncated marks an incomplete header block: the gateway cannot know the
	// request has ended, so the only correct behavior is to keep waiting for
	// the rest rather than to answer (its handshake deadline closes the session
	// later).
	truncated bool
}

// httpRejectExchange runs one reject conversation and returns the status the
// gateway answered.
func httpRejectExchange(t *testing.T, addr string, tc httpRejectCase) int {
	t.Helper()
	conn := dialGateway(t, addr)
	if _, err := conn.Write(tc.request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	// An incomplete block is never answered, so that silence is what is pinned:
	// the exact read error (EOF, reset, or the test's own deadline) is OS
	// dependent. Every other reject is asserted by its status.
	window := 2 * time.Second
	if tc.truncated {
		window = 200 * time.Millisecond
	}
	_ = conn.SetReadDeadline(time.Now().Add(window))
	status, err := tryReadIngressStatus(bufio.NewReader(conn), requestMethodOf(tc.request))
	if tc.truncated {
		if err == nil {
			t.Fatal("an incomplete header block must not be answered")
		}
		return 0
	}
	if err != nil {
		t.Fatalf("read reject reply: %v", err)
	}
	return status
}

// tryReadIngressStatus parses one response header block without failing the
// test, for the conversation shapes where no reply is the correct outcome.
//
// Every protocol reject the gateway writes is a bodyless, header-only response,
// so the method attached to the synthetic request is irrelevant to parsing. It
// is deliberately not taken from the request frame: a malformed request line
// ("NOT-A-REQUEST") is not a legal method, and http.NewRequest would reject the
// probe itself before the gateway's own status could be read.
func tryReadIngressStatus(br *bufio.Reader, _ string) (int, error) {
	req, err := http.NewRequest(http.MethodGet, "http://ingress.invalid/", nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// --- test targets ----------------------------------------------------------

func startRawEchoTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return serveEchoTarget(t, ln)
}

// serveEchoTarget turns ln into an echo target: every accepted connection gets
// a short banner and then each byte back, until the peer closes. The banner
// proves the upstream-to-client direction independent of client traffic.
func serveEchoTarget(t *testing.T, ln net.Listener) string {
	t.Helper()
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go echoConn(conn)
		}
	}()
	return ln.Addr().String()
}

func echoConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("banner\n")); err != nil {
		return
	}
	_, _ = io.Copy(conn, conn)
}

// startParkedTarget accepts connections and never writes or closes them,
// modeling a target that holds its tunnel open.
func startParkedTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range held {
			_ = conn.Close()
		}
	})
	return ln.Addr().String()
}

// startHalfCloseTarget accepts connections, holds them until the peer ends
// its write side (EOF), optionally delays, then writes one banner and closes:
// a target whose reply arrives only after the client half-closed. delay may
// be zero; banner may be empty for a pure parked-then-close target.
func startHalfCloseTarget(t *testing.T, delay time.Duration, banner string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				// Hold the tunnel until the peer's FIN arrives.
				if _, err := io.Copy(io.Discard, conn); err != nil {
					return
				}
				if delay > 0 {
					time.Sleep(delay)
				}
				if banner != "" {
					_, _ = conn.Write([]byte(banner))
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// startAbortTarget answers each tunnel with a few bytes and then resets the
// connection, modeling a target that drops a live stream mid-flight.
func startAbortTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				_, _ = conn.Write([]byte("partial"))
				// Let the gateway's SOCKS success reply reach the dialer
				// before the reset: a too-early RST can destroy the unread
				// reply in flight, which would be a handshake failure instead.
				time.Sleep(100 * time.Millisecond)
				if tc, ok := conn.(*net.TCPConn); ok {
					_ = tc.SetLinger(0) // reset instead of a clean close
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// --- target classification -------------------------------------------------

// The ingress never resolves a name: an IP literal stays its literal address
// type and everything else stays a domain, so the outbound SOCKS5H hop is the
// only place DNS happens. targetFromAuthority is the one place that decides,
// from HTTP authority syntax alone.
func TestTargetFromAuthorityClassifiesWithoutResolving(t *testing.T) {
	for _, tc := range []struct {
		name      string
		authority string
		// omitPortAllowed marks an absolute-form authority, which inherits
		// the scheme's default port 80. CONNECT may never omit it.
		omitPortAllowed bool
		wantAddr        string
		wantType        socksdial.AddrType
	}{
		{name: "ipv4 literal", authority: "127.0.0.1:8080", wantAddr: "127.0.0.1:8080", wantType: socksdial.AddrIPv4},
		{name: "domain name", authority: "example.test:443", wantAddr: "example.test:443", wantType: socksdial.AddrDomain},
		{name: "ipv6 literal", authority: "[2001:db8::1]:443", wantAddr: "[2001:db8::1]:443", wantType: socksdial.AddrIPv6},
		{name: "dotted quad is a literal", authority: "1.2.3.4:443", wantAddr: "1.2.3.4:443", wantType: socksdial.AddrIPv4},
		{name: "absolute form inherits port 80", authority: "example.test", omitPortAllowed: true,
			wantAddr: "example.test:80", wantType: socksdial.AddrDomain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := targetFromAuthority(tc.authority, !tc.omitPortAllowed)
			if err != nil {
				t.Fatalf("targetFromAuthority(%q): %v", tc.authority, err)
			}
			if got.Addr() != tc.wantAddr || got.Type != tc.wantType {
				t.Fatalf("targetFromAuthority(%q) = %+v, want %q of type %d", tc.authority, got, tc.wantAddr, tc.wantType)
			}
		})
	}
}

// The port rules are strict in both directions: CONNECT names a TCP tunnel and
// must carry a port, an empty or out-of-range port is never a target, and no
// authority may smuggle userinfo, a path, a query, or a fragment.
func TestTargetFromAuthorityRejectsUnusableAuthorities(t *testing.T) {
	for _, tc := range []struct {
		name      string
		authority string
	}{
		{name: "connect without a port", authority: "example.test"},
		{name: "empty port", authority: "example.test:"},
		{name: "zero port", authority: "example.test:0"},
		{name: "port above the range", authority: "example.test:65536"},
		{name: "non-numeric port", authority: "example.test:https"},
		{name: "userinfo", authority: "user:pass@example.test:443"},
		{name: "path", authority: "example.test:443/tunnel"},
		{name: "query", authority: "example.test:443?a=1"},
		{name: "fragment", authority: "example.test:443#f"},
		{name: "embedded space", authority: "example.test 443"},
		{name: "empty authority", authority: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := targetFromAuthority(tc.authority, true); err == nil {
				t.Fatalf("targetFromAuthority(%q) accepted an unusable authority", tc.authority)
			}
		})
	}
}

// A protocol response is deliberately bodyless: the status is the useful
// information to a proxy client, and echoing parser, credential, or target
// detail would only risk disclosing what the client itself supplied.
func TestWriteHTTPErrorShape(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusProxyAuthRequired, http.StatusNotImplemented,
		http.StatusHTTPVersionNotSupported, http.StatusBadGateway, http.StatusServiceUnavailable} {
		var wire bytes.Buffer
		if err := writeHTTPError(&wire, status); err != nil {
			t.Fatalf("writeHTTPError(%d): %v", status, err)
		}
		// Connection: close is set inside WriteHeader, so the header block is
		// written through http.Header.Write and its fields come out in
		// canonical (alphabetical) order: Connection before Content-Length.
		want := fmt.Sprintf("HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
			status, http.StatusText(status))
		if wire.String() != want {
			t.Fatalf("writeHTTPError(%d) wrote %q, want %q", status, wire.String(), want)
		}
	}
}

// A CONNECT success reply must leave Connection unmodified: the tunnel's
// arbitrary bytes follow immediately on the same socket, so advertising close
// there would contradict what the gateway just established.
func TestConnectSuccessReplyLeavesConnectionUnmodified(t *testing.T) {
	var wire bytes.Buffer
	if err := (&connectReplier{conn: &wire}).ok(); err != nil {
		t.Fatalf("writeHTTPError-free success reply: %v", err)
	}
	want := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	if wire.String() != want {
		t.Fatalf("CONNECT success wrote %q, want %q", wire.String(), want)
	}
}

// An absolute-form success writes nothing at all: the ReverseProxy starts the
// sole client response only after the origin answers, so an invented 200 here
// would turn one request into two responses.
func TestForwardSuccessReplyStaysSilent(t *testing.T) {
	var wire bytes.Buffer
	if err := (&forwardReplier{conn: &wire}).ok(); err != nil {
		t.Fatalf("forwardReplier.ok(): %v", err)
	}
	if wire.Len() != 0 {
		t.Fatalf("forward success wrote %q, want nothing", wire.String())
	}
}

// --- relaying --------------------------------------------------------------

// A CONNECT tunnel must carry bytes both ways for every authority shape a
// client may name: an IPv4 literal, a domain name, and an IPv6 literal.
func TestHTTPConnectRelaysBothDirections(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), 30*time.Second, time.Minute)
	s, addr := newProxyServer(t, pl, defaultRuntime(), testLogger())

	t.Run("ipv4", func(t *testing.T) {
		relayRoundTrip(t, addr, startRawEchoTarget(t))
	})
	t.Run("domain", func(t *testing.T) {
		// "localhost" is the one name that resolves locally and it is not an
		// IP literal, so the ingress forwards it as a domain target while the
		// fake upstream dials it for real. This proves domain framing end to
		// end, not just on refusal paths.
		_, port, err := net.SplitHostPort(startRawEchoTarget(t))
		if err != nil {
			t.Fatal(err)
		}
		relayRoundTrip(t, addr, net.JoinHostPort("localhost", port))
	})
	t.Run("ipv6", func(t *testing.T) {
		ln, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skipf("loopback IPv6 unavailable: %v", err)
		}
		relayRoundTrip(t, addr, serveEchoTarget(t, ln))
	})

	snap := pl.Snapshot()[0]
	if snap.Successes != 3 || snap.Failures != 0 || snap.AuthFailures != 0 {
		t.Fatalf("pool state = %+v, want three successes", snap)
	}
	if status := s.ListenerStatus(); status.Requests != 3 || status.Failovers != 0 {
		t.Fatalf("listener status = %+v", status)
	}
}

func relayRoundTrip(t *testing.T, gatewayAddr, target string) {
	t.Helper()
	relayRoundTripOnConn(t, httpDialVia(t, gatewayAddr, target))
}

// relayRoundTripOnConn proves an established tunnel carries bytes both ways.
func relayRoundTripOnConn(t *testing.T, conn net.Conn) {
	t.Helper()
	defer func() { _ = conn.Close() }()
	if got := readBanner(t, conn); got != "banner\n" {
		t.Fatalf("banner = %q", got)
	}
	payload := []byte("ping-through-tunnel")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatalf("echo = %q, want %q", echo, payload)
	}
}

// The tunnel is a raw byte stream: a plain HTTP round trip over it must work
// exactly as it would over a direct connection.
func TestTunnelCarriesHTTPTraffic(t *testing.T) {
	target := startEchoTarget(t)
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), 30*time.Second, time.Minute)
	_, addr := newProxyServer(t, pl, defaultRuntime(), testLogger())

	conn := httpDialVia(t, addr, target)
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", target); err != nil {
		t.Fatalf("write request: %v", err)
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(string(body), "dial-via-ok") {
		t.Fatalf("response = %q, want the target body", body)
	}
	if snap := pl.Snapshot()[0]; snap.Successes != 1 || snap.Failures != 0 || snap.AuthFailures != 0 {
		t.Fatalf("HTTP round trip changed route health: %+v", snap)
	}
}

// A client may pipeline payload behind its CONNECT headers in one write. The
// framing reader captures those bytes, so they must reach the upstream relay
// rather than being dropped with the handshake buffers.
func TestPipelinedBytesAfterConnectReachRelay(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), 30*time.Second, time.Minute)
	_, addr := newProxyServer(t, pl, defaultRuntime(), testLogger())
	target := startRawEchoTarget(t)

	conn := dialGateway(t, addr)
	payload := []byte("pipelined-payload")
	// One write: the CONNECT request and the first tunnel bytes together — a
	// single socket segment is exactly the case a header-only reader breaks.
	if _, err := conn.Write(append(httpConnectRequest(target), payload...)); err != nil {
		t.Fatalf("write burst: %v", err)
	}
	br := bufio.NewReader(conn)
	if status := readIngressResponse(t, br, http.MethodConnect).StatusCode; status != http.StatusOK {
		t.Fatalf("CONNECT = %d, want 200", status)
	}
	// The echo target's banner crosses the tunnel first; the payload follows.
	if got := readBanner(t, br); got != "banner\n" {
		t.Fatalf("banner = %q", got)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(br, echo); err != nil {
		t.Fatalf("read echoed payload: %v", err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatalf("echoed payload = %q, want %q", echo, payload)
	}
}

// countingConn counts how many reads the server's framing performed on the
// client socket.
type countingConn struct {
	net.Conn
	reads atomic.Int64
}

func (c *countingConn) Read(b []byte) (int, error) {
	c.reads.Add(1)
	return c.Conn.Read(b)
}

// A complete CONNECT request must be framed with at most two client reads: the
// buffered header reader captures the whole exchange in one fill, and one extra
// read is the split-burst allowance for real TCP fragmentation.
func TestInboundFramingReadBudget(t *testing.T) {
	pl := pool.NewRoutes(nil, 30*time.Second, time.Minute)
	s := newRuntimeServer(pl, defaultRuntime(), testLogger())

	// A real TCP socket, not net.Pipe: the pipe is synchronous, so a burst
	// write would deadlock against the server's own reply. TCP buffers decouple
	// the directions and keep the server-side read count exact — each framing
	// read is one syscall however the segments land.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan *countingConn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		cc := &countingConn{Conn: c}
		if s.beginSession(cc) {
			s.serveConn(cc)
		}
		accepted <- cc
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(httpConnectRequest("127.0.0.1:1")); err != nil {
		t.Fatalf("write burst: %v", err)
	}
	// No routes exist, so the request ends in the no_route reply.
	br := bufio.NewReader(conn)
	if status := readIngressResponse(t, br, http.MethodConnect).StatusCode; status != http.StatusServiceUnavailable {
		t.Fatalf("CONNECT with no routes = %d, want 503", status)
	}
	cc := <-accepted
	if n := cc.reads.Load(); n == 0 || n > 2 {
		t.Fatalf("framing used %d reads for one burst, want 1-2", n)
	}
}

// --- protocol rejects ------------------------------------------------------

// Every malformed or unsupported inbound request must be answered before the
// request counter and before pool selection: route health and counters stay
// untouched, no upstream is contacted, and each reject logs one bad_request
// line that reflects no request detail back.
func TestProtocolRejectsNeverTouchPoolOrCounters(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute)
	var logs safeLogBuffer
	s, addr := newProxyServer(t, pl, defaultRuntime(), captureLogger(&logs))

	host := "Host: example.test"
	cases := []httpRejectCase{
		{name: "unparsable request line", request: []byte("NOT-A-REQUEST\r\n\r\n"), wantStatus: http.StatusBadRequest},
		{name: "malformed header syntax", request: []byte("GET http://example.test/ HTTP/1.1\r\n" + host + "\r\nBad Header\r\n\r\n"),
			wantStatus: http.StatusBadRequest},
		{name: "duplicate host headers", request: []byte("GET http://example.test/ HTTP/1.1\r\n" + host + "\r\nHost: other.test\r\n\r\n"),
			wantStatus: http.StatusBadRequest},
		{name: "http/1.0 version", request: []byte("GET http://example.test/ HTTP/1.0\r\n" + host + "\r\n\r\n"),
			wantStatus: http.StatusHTTPVersionNotSupported},
		{name: "origin-form target", request: []byte("GET / HTTP/1.1\r\n" + host + "\r\n\r\n"),
			wantStatus: http.StatusBadRequest},
		{name: "asterisk-form target", request: []byte("OPTIONS * HTTP/1.1\r\n" + host + "\r\n\r\n"),
			wantStatus: http.StatusNotImplemented},
		{name: "https scheme", request: []byte("GET https://example.test/ HTTP/1.1\r\n" + host + "\r\n\r\n"),
			wantStatus: http.StatusNotImplemented},
		{name: "connect target with a path", request: []byte("CONNECT example.test:443/tunnel HTTP/1.1\r\nHost: example.test:443\r\n\r\n"),
			wantStatus: http.StatusBadRequest},
		{name: "connect without a port", request: []byte("CONNECT example.test HTTP/1.1\r\nHost: example.test\r\n\r\n"),
			wantStatus: http.StatusBadRequest},
		{name: "connect host mismatch", request: []byte("CONNECT example.test:443 HTTP/1.1\r\nHost: other.test:443\r\n\r\n"),
			wantStatus: http.StatusBadRequest},
		{name: "connect host port mismatch", request: []byte("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:8443\r\n\r\n"),
			wantStatus: http.StatusBadRequest},
		{name: "connect host carrying userinfo", request: []byte("CONNECT example.test:443 HTTP/1.1\r\nHost: TESTUSER:TESTPASS@example.test:443\r\n\r\n"),
			wantStatus: http.StatusBadRequest},
		{name: "connect zero port", request: []byte("CONNECT example.test:0 HTTP/1.1\r\nHost: example.test:0\r\n\r\n"),
			wantStatus: http.StatusBadRequest},
		{name: "absolute host mismatch", request: []byte("GET http://example.test/ HTTP/1.1\r\nHost: other.test\r\n\r\n"),
			wantStatus: http.StatusBadRequest},
		{name: "absolute url carrying userinfo", request: []byte("GET http://TESTUSER:TESTPASS@example.test/ HTTP/1.1\r\n" + host + "\r\n\r\n"),
			wantStatus: http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := httpRejectExchange(t, addr, tc); got != tc.wantStatus {
				t.Fatalf("reject status = %d, want %d", got, tc.wantStatus)
			}
			snap := pl.Snapshot()[0]
			if snap.Successes != 0 || snap.Failures != 0 || snap.AuthFailures != 0 || !snap.Available {
				t.Fatalf("reject changed route health: %+v", snap)
			}
			if got := len(fs.hits); got != 0 {
				t.Fatalf("reject dialed the upstream %d times", got)
			}
			if status := s.ListenerStatus(); status.Requests != 0 || status.Failovers != 0 {
				t.Fatalf("reject advanced listener counters: %+v", status)
			}
		})
	}

	// Rejects are handled in per-connection goroutines, so the final record can
	// land after the last client exchange returns; poll for the full set.
	var output string
	deadline := time.Now().Add(time.Second)
	for {
		output = logs.String()
		if countRecords(output, map[string]string{"error_kind": "bad_request"}) == len(cases) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("bad_request records = %d, want %d:\n%s",
				countRecords(output, map[string]string{"error_kind": "bad_request"}), len(cases), output)
		}
		time.Sleep(time.Millisecond)
	}
	if _, ok := findRecord(output, map[string]string{"msg": "HTTP proxy request rejected", "error_kind": "bad_request"}); !ok {
		t.Fatalf("rejects were not logged as rejections:\n%s", output)
	}
	// A reject states only the stable protocol outcome: reflecting parser,
	// credential, or target text would repeat data the client already holds.
	for _, rec := range decodeRecords(output) {
		if !recordMatches(rec, map[string]string{"error_kind": "bad_request"}) {
			continue
		}
		if _, has := rec["error"]; has {
			t.Errorf("bad_request record reflected a request detail: %v", rec)
		}
	}
	for _, secret := range []string{"TESTUSER", "TESTPASS"} {
		if strings.Contains(output, secret) {
			t.Errorf("logs leaked the planted credential %q:\n%s", secret, output)
		}
	}

	// An incomplete header block is not a rejected request: the gateway cannot
	// know the request has ended, so answering would invent a verdict.
	t.Run("incomplete header block is not answered", func(t *testing.T) {
		got := httpRejectExchange(t, addr, httpRejectCase{
			request:   []byte("GET http://example.test/ HTTP/1.1\r\n" + host + "\r\n"),
			truncated: true,
		})
		if got != 0 {
			t.Fatalf("incomplete header block drew status %d, want silence", got)
		}
		if status := s.ListenerStatus(); status.Requests != 0 || status.Failovers != 0 {
			t.Fatalf("incomplete header block advanced listener counters: %+v", status)
		}
	})
}

// An inbound header block larger than the ingress bound must never become a
// serving request: the gateway cannot hold unbounded header storage for a peer
// that keeps writing, so it stops reading and rejects. The status is asserted
// only through the log, because answering and closing while the oversized
// block is still in flight can reset the client before it reads the reply.
func TestOversizedRequestHeaderNeverReachesRouteSelection(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute)
	var logs safeLogBuffer
	s, addr := newProxyServer(t, pl, defaultRuntime(), captureLogger(&logs))

	conn := dialGateway(t, addr)
	oversized := append([]byte("GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\nX-Fill: "),
		bytes.Repeat([]byte("a"), maxInboundHeaderBytes)...)
	oversized = append(oversized, []byte("\r\n\r\n")...)
	// A write error is expected: the gateway answers and closes while the
	// oversized block is still going out.
	_, _ = conn.Write(oversized)
	_, _ = io.Copy(io.Discard, conn)

	if snap := pl.Snapshot()[0]; snap.Successes != 0 || snap.Failures != 0 || !snap.Available {
		t.Fatalf("oversized header changed route health: %+v", snap)
	}
	if got := len(fs.hits); got != 0 {
		t.Fatalf("oversized header dialed the upstream %d times", got)
	}
	if status := s.ListenerStatus(); status.Requests != 0 || status.Failovers != 0 {
		t.Fatalf("oversized header advanced listener counters: %+v", status)
	}
	waitForRecord(t, &logs, map[string]string{"msg": "HTTP proxy request rejected", "error_kind": "bad_request"})
}

// The second accepted shape: an absolute-form request is relayed as one HTTP
// exchange over one tunnel, and the client receives the origin's own status,
// body, and headers. The gateway's own control material — the consumed client
// credential and the reserved x-ecoma- namespace — must never reach the origin.
func TestAbsoluteFormRelaysOriginStatusAndStripsControlHeaders(t *testing.T) {
	var seen http.Header
	var seenRequestURI string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		seenRequestURI = r.RequestURI
		w.Header().Set("X-Origin", "yes")
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "origin-body")
	}))
	t.Cleanup(origin.Close)
	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}

	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), 30*time.Second, time.Minute)
	_, addr := newProxyServer(t, pl, defaultRuntime(), testLogger())

	resp := httpForward(t, addr, httpForwardRequest(http.MethodGet, origin.URL+"/probe",
		"Host: "+originURL.Host,
		"Proxy-Authorization: Basic Z3ctdXNlcjpnd3ctcGFzcw==",
		"X-Ecoma-Probe: control-secret",
	), http.MethodGet)
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("relayed status = %d, want the origin's own 418", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Origin"); got != "yes" {
		t.Fatalf("origin header = %q, want it relayed", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read relayed body: %v", err)
	}
	if string(body) != "origin-body" {
		t.Fatalf("relayed body = %q, want the origin body unchanged", body)
	}

	if got := seen.Get("Proxy-Authorization"); got != "" {
		t.Errorf("origin saw Proxy-Authorization %q; the client credential crossed the credential boundary", got)
	}
	if got := seen.Get("X-Ecoma-Probe"); got != "" {
		t.Errorf("origin saw the reserved control header %q", got)
	}
	// The gateway rewrites the absolute target into origin form for the origin
	// while still naming the right authority and path.
	if seenRequestURI != "/probe" {
		t.Errorf("origin RequestURI = %q, want the origin form %q", seenRequestURI, "/probe")
	}
	if got := seen.Get("Host"); got != "" && got != originURL.Host {
		t.Errorf("origin Host = %q, want %q", got, originURL.Host)
	}
	snap := pl.Snapshot()[0]
	if snap.Successes != 1 || snap.Failures != 0 {
		t.Fatalf("relayed exchange changed route health: %+v", snap)
	}
}

// An absolute-form request whose authority is a domain is forwarded as a name,
// never resolved at the gateway: the origin sees a name, and the SOCKS5H hop is
// where DNS happens.
func TestAbsoluteFormTargetStaysADomainName(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "named")
	}))
	t.Cleanup(origin.Close)
	_, port, err := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), 30*time.Second, time.Minute)
	var logs safeLogBuffer
	_, addr := newProxyServer(t, pl, defaultRuntime(), captureLogger(&logs))

	resp := httpForward(t, addr,
		httpForwardRequest(http.MethodGet, "http://localhost:"+port+"/named", "Host: localhost:"+port),
		http.MethodGet)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read relayed body: %v", err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "named" {
		t.Fatalf("relayed %d %q, want the origin's own 200 named", resp.StatusCode, body)
	}
	// A domain target is never reclassified into an IP literal: the log names
	// the authority the client asked for.
	output := waitForRecord(t, &logs, map[string]string{"msg": "tunnel"})
	if !strings.Contains(output, "localhost:"+port) {
		t.Errorf("logs did not record the domain target:\n%s", output)
	}
	snap := pl.Snapshot()[0]
	if snap.Successes != 1 || snap.Failures != 0 {
		t.Fatalf("relayed exchange changed route health: %+v", snap)
	}
}

// The absolute-form failure statuses are the same wire contract as CONNECT's:
// the split follows the route chain, not the request shape. A chain that never
// obtains a usable route — empty, or every route cooling on another kind — ends
// in 503 no_route. A chain that DID pick a route and then hit a gateway-side
// local setup failure ends in 502, answers immediately, and retries nothing.
func TestAbsoluteFormTerminalFailureStatuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		// routes builds the pool; setup optionally replaces the dial seam.
		routes func(t *testing.T) *pool.Pool
		setup  func(t *testing.T, s *Server)
		// allowed is the listener's egress-kind view. An empty slice means the
		// mixed listener that can serve every route kind.
		allowed  []config.EgressKind
		wantKind string
		want     int
	}{
		{
			name: "no eligible route is 503",
			routes: func(t *testing.T) *pool.Pool {
				u, err := url.Parse("socks5://v4.test:1080")
				if err != nil {
					t.Fatal(err)
				}
				// A v6-only listener can never serve the only v4 route.
				return pool.NewRoutes([]config.RouteSpec{{URL: u, Kind: config.EgressV4}}, time.Second, time.Minute)
			},
			allowed:  []config.EgressKind{config.EgressV6},
			want:     http.StatusServiceUnavailable,
			wantKind: errorKindNoRoute,
		},
		{
			// A selected route that fails at the gateway rather than at the
			// endpoint — here an unencodable configured route credential — is
			// ours, not the client's, and never becomes route health.
			name: "gateway-side setup failure after a pick is 502",
			routes: func(t *testing.T) *pool.Pool {
				u, err := url.Parse("socks5://u.test:1080")
				if err != nil {
					t.Fatal(err)
				}
				return pool.NewRoutes(mixedRoutes(u), time.Second, time.Minute)
			},
			setup: func(_ *testing.T, s *Server) {
				s.dial = func(context.Context, *url.URL, socksdial.Target, time.Duration) (net.Conn, error) {
					return nil, &SocksProtocolError{Op: "encode target", Err: errors.New("oversized configured credentials")}
				}
			},
			want:     http.StatusBadGateway,
			wantKind: errorKindSetup,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pl := tc.routes(t)
			var logs safeLogBuffer
			s, addr := newProxyServer(t, pl, defaultRuntime(), captureLogger(&logs), tc.allowed...)
			if tc.setup != nil {
				tc.setup(t, s)
			}
			resp := httpForward(t, addr,
				httpForwardRequest(http.MethodGet, "http://example.test/thing", "Host: example.test"),
				http.MethodGet)
			if resp.StatusCode != tc.want {
				t.Fatalf("absolute-form terminal status = %d, want %d", resp.StatusCode, tc.want)
			}
			// The failure is terminal and bodyless: the gateway never invents a
			// client response beyond the status it owes.
			if got := resp.Header.Get("Content-Length"); got != "0" {
				t.Errorf("terminal Content-Length = %q, want 0", got)
			}
			if status := s.ListenerStatus(); status.Requests != 1 {
				t.Errorf("listener status = %+v, want exactly the one valid request", status)
			}
			// The 503 case ends the chain with no route; the 502 case is the
			// immediate gateway-side setup failure. Neither may be logged as
			// the other: that split is the whole point of the two statuses.
			waitForRecord(t, &logs, map[string]string{"error_kind": tc.wantKind})
		})
	}
}

// --- retry and health semantics -------------------------------------------

// An endpoint dial failure cools the route down, excludes it, and falls back
// to the next eligible route; the client sees only the successful tunnel.
func TestDialFailureCooldownsRouteExcludedAndFallsBack(t *testing.T) {
	dead := &url.URL{Scheme: "socks5", User: url.UserPassword("route-user", "route-password"), Host: "dead.test:1080"}
	good := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(dead, good.URL), 30*time.Second, time.Minute)
	var logs safeLogBuffer
	s := newRuntimeServer(pl, defaultRuntime(), captureLogger(&logs))
	s.dial = func(ctx context.Context, pu *url.URL, target socksdial.Target, timeout time.Duration) (net.Conn, error) {
		if pu.Host == dead.Host {
			return nil, &ProxyDialError{Err: errors.New("connect refused")}
		}
		return dialVia(ctx, pu, target, timeout)
	}
	addr := startServer(t, s)

	conn := httpDialVia(t, addr, startRawEchoTarget(t))
	readBanner(t, conn)
	_ = conn.Close()

	snap := pl.Snapshot()
	if snap[0].Failures != 1 || snap[0].Successes != 0 || snap[0].Available {
		t.Fatalf("failed route state = %+v", snap[0])
	}
	if snap[1].Successes != 1 || snap[1].Failures != 0 {
		t.Fatalf("fallback route state = %+v", snap[1])
	}
	if status := s.ListenerStatus(); status.Requests != 1 || status.Failovers != 1 {
		t.Fatalf("listener status = %+v, want one request and one fallback", status)
	}
	output := waitForRecord(t, &logs, map[string]string{"msg": "tunnel"})
	if _, ok := findRecord(output, map[string]string{
		"msg": "upstream dial failed", "request_id": "1",
		"error_kind": "proxy_connect", "cooldown": "30s",
	}); !ok {
		t.Errorf("logs missing the dial-failure record:\n%s", output)
	}
	if _, ok := findRecord(output, map[string]string{"msg": "tunnel", "request_id": "1", "attempts": "2"}); !ok {
		t.Errorf("logs missing the tunnel record with attempts=2:\n%s", output)
	}
	for _, secret := range []string{"route-user", "route-password"} {
		if strings.Contains(output, secret) {
			t.Errorf("logs leaked %q:\n%s", secret, output)
		}
	}
}

// An upstream SOCKS handshake failure before the tunnel exists is socks_connect:
// the same cooldown-and-fallback treatment as an endpoint dial failure. The
// route-scoped flavor needs a failure the endpoint did not answer with a clean
// refusal — a malformed CONNECT reply — because an explicit refusal is the
// target-scoped connect_target case.
func TestHandshakeFailureFallsBackWithSocksConnectKind(t *testing.T) {
	reject := startSocks5Proxy(t, socksOptions{connectRaw: []byte{0x05, 0x00, 0x00, 0x06}})
	good := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(reject.URL, good.URL), time.Second, time.Minute)
	var logs safeLogBuffer
	_, addr := newProxyServer(t, pl, defaultRuntime(), captureLogger(&logs))

	conn := httpDialVia(t, addr, startRawEchoTarget(t))
	readBanner(t, conn)
	_ = conn.Close()

	snap := pl.Snapshot()
	if snap[0].Failures != 1 || snap[0].Available || snap[1].Successes != 1 {
		t.Fatalf("pool state = %+v", snap)
	}
	output := waitForRecord(t, &logs, map[string]string{"msg": "tunnel"})
	if _, ok := findRecord(output, map[string]string{
		"msg": "upstream handshake failed", "request_id": "1",
		"error_kind": "socks_connect", "cooldown": "1s",
	}); !ok {
		t.Errorf("logs missing the handshake-failure record:\n%s", output)
	}
	if _, ok := findRecord(output, map[string]string{"msg": "tunnel", "request_id": "1", "attempts": "2"}); !ok {
		t.Errorf("logs missing the tunnel record with attempts=2:\n%s", output)
	}
}

// An upstream authentication failure blocks the route for auth and allows a
// fallback, but never creates dial cooldown.
func TestAuthFailureFallsBackWithoutDialCooldown(t *testing.T) {
	bad := startSocks5Proxy(t, socksOptions{user: "TEST-user", pass: "TEST-pass"})
	good := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(bad.URL, good.URL), time.Second, time.Minute)
	var logs safeLogBuffer
	_, addr := newProxyServer(t, pl, defaultRuntime(), captureLogger(&logs))

	conn := httpDialVia(t, addr, startRawEchoTarget(t))
	readBanner(t, conn)
	_ = conn.Close()

	snap := pl.Snapshot()
	if !snap[0].AuthBlocked || snap[0].AuthFailures != 1 || snap[0].Failures != 0 || snap[0].CooldownFor != "0s" {
		t.Fatalf("auth-blocked route state = %+v", snap[0])
	}
	if snap[1].Successes != 1 || snap[1].Failures != 0 {
		t.Fatalf("fallback route state = %+v", snap[1])
	}
	output := waitForRecord(t, &logs, map[string]string{"msg": "tunnel"})
	authRec, ok := findRecord(output, map[string]string{
		"msg": "upstream auth failed", "request_id": "1", "error_kind": "auth_route",
	})
	if !ok {
		t.Errorf("logs missing the auth-failure record:\n%s", output)
	} else {
		if !strings.Contains(fmt.Sprint(authRec["error"]), "endpoint accepted no offered authentication method") {
			t.Errorf("auth record lost the reason: %v", authRec["error"])
		}
		if _, has := authRec["cooldown"]; has {
			t.Errorf("auth fallback logged a cooldown: %v", authRec)
		}
	}
	if _, ok := findRecord(output, map[string]string{"msg": "tunnel", "request_id": "1", "attempts": "2"}); !ok {
		t.Errorf("logs missing the tunnel record with attempts=2:\n%s", output)
	}
	for _, secret := range []string{"TEST-user", "TEST-pass"} {
		if strings.Contains(output, secret) {
			t.Errorf("logs leaked %q:\n%s", secret, output)
		}
	}
}

// With one route that refuses CONNECT to the requested target, the request
// exhausts the pool: the client gets 503 and the log names no_route. The
// refusal is target-scoped: the pair cools, the route itself stays available.
func TestSingleRejectingRouteExhaustsToServiceUnavailable(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{connectRep: 0x05})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute)
	var logs safeLogBuffer
	s, addr := newProxyServer(t, pl, defaultRuntime(), captureLogger(&logs))

	if status := httpConnectStatus(t, addr, "example.test:443"); status != http.StatusServiceUnavailable {
		t.Fatalf("CONNECT status = %d, want 503", status)
	}

	snap := pl.Snapshot()[0]
	if snap.TargetFailures != 1 || snap.TargetCooldowns != 1 || snap.Failures != 0 || !snap.Available {
		t.Fatalf("connect-target refusal did not record pair-scoped health: %+v", snap)
	}
	if snap.Successes != 0 || snap.AuthFailures != 0 || snap.CooldownFor != "0s" {
		t.Fatalf("route-level state moved on a target-scoped refusal: %+v", snap)
	}
	if got := len(fs.hits); got != 1 {
		t.Fatalf("upstream attempts = %d, want 1", got)
	}
	if status := s.ListenerStatus(); status.Requests != 1 || status.Failovers != 1 {
		t.Fatalf("listener status = %+v", status)
	}
	output := waitForRecord(t, &logs, map[string]string{"msg": "tunnel failed"})
	if _, ok := findRecord(output, map[string]string{
		"msg": "upstream refused connect target", "error_kind": "connect_target", "cooldown": "1s",
	}); !ok {
		t.Errorf("logs missing the connect_target record:\n%s", output)
	}
	if _, ok := findRecord(output, map[string]string{
		"msg": "tunnel failed", "error_kind": "no_route", "attempts": "1",
	}); !ok {
		t.Errorf("logs missing the no_route record:\n%s", output)
	}
}

// The issue #5 scenario in miniature: one route that serves every target
// except one. The refusal cools only the (route, target) pair — the same route
// immediately serves a different target, and the pair's cooldown never touches
// route-level health.
func TestConnectTargetRefusalKeepsRouteForOtherTargets(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{connectRep: 0x05, refuseHost: "blocked.test"})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute)
	var logs safeLogBuffer
	s, addr := newProxyServer(t, pl, defaultRuntime(), captureLogger(&logs))

	// First request: the refused target exhausts the single-route pool.
	if status := httpConnectStatus(t, addr, "blocked.test:443"); status != http.StatusServiceUnavailable {
		t.Fatalf("blocked target status = %d, want 503", status)
	}

	// The route never cooled: an unrelated target is served by the same route
	// without touching the all-cooling fallback.
	conn := httpDialVia(t, addr, startRawEchoTarget(t))
	_ = conn.Close()

	snap := pl.Snapshot()[0]
	if !snap.Available || snap.Failures != 0 || snap.Successes != 1 ||
		snap.TargetFailures != 1 || snap.TargetCooldowns != 1 {
		t.Fatalf("pair-scoped state = %+v, want a healthy route with one cooled pair", snap)
	}
	if status := s.ListenerStatus(); status.Requests != 2 || status.Failovers != 1 {
		t.Fatalf("listener status = %+v, want 2 requests and 1 failover", status)
	}
	output := waitForRecord(t, &logs, map[string]string{"msg": "tunnel"})
	if _, ok := findRecord(output, map[string]string{
		"msg": "upstream refused connect target", "error_kind": "connect_target",
	}); !ok {
		t.Errorf("logs missing the connect_target record:\n%s", output)
	}
	if _, ok := findRecord(output, map[string]string{"msg": "tunnel", "upstream": fs.URL.Host}); !ok {
		t.Errorf("logs missing the successful tunnel through the refusing route:\n%s", output)
	}
}

// A local setup failure answers once, retries nothing, and mutates no health:
// every route would fail identically, so cooldown would only poison the pool.
// It is still a gateway-side failure of an already-valid request, so the client
// gets 502 rather than the 503 an empty chain would produce.
func TestSetupErrorRepliesBadGatewayWithoutPoolMutation(t *testing.T) {
	good := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(good.URL), time.Second, time.Minute)
	var logs safeLogBuffer
	s := newRuntimeServer(pl, defaultRuntime(), captureLogger(&logs))
	dials := 0
	s.dial = func(context.Context, *url.URL, socksdial.Target, time.Duration) (net.Conn, error) {
		dials++
		return nil, &SocksProtocolError{Op: "encode target", Err: errors.New("TEST oversized configured credentials")}
	}
	addr := startServer(t, s)

	if status := httpConnectStatus(t, addr, "example.test:443"); status != http.StatusBadGateway {
		t.Fatalf("CONNECT status = %d, want 502 for a gateway-side setup failure", status)
	}
	if dials != 1 {
		t.Fatalf("dial attempts = %d, want 1 (setup errors never retry)", dials)
	}
	snap := pl.Snapshot()[0]
	if snap.Successes != 0 || snap.Failures != 0 || snap.AuthFailures != 0 || !snap.Available {
		t.Fatalf("setup error mutated route health: %+v", snap)
	}
	if status := s.ListenerStatus(); status.Requests != 1 || status.Failovers != 0 {
		t.Fatalf("listener status = %+v", status)
	}
	output := waitForRecord(t, &logs, map[string]string{"msg": "upstream setup failed"})
	if _, ok := findRecord(output, map[string]string{
		"msg": "upstream setup failed", "request_id": "1",
		"error_kind": "setup", "upstream": good.URL.Host,
	}); !ok {
		t.Errorf("logs missing the setup-failure record:\n%s", output)
	}
}
