package proxyserver

import (
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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/logging"
	"rotation-proxy-gateway/internal/pool"

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

func newSocksServer(t *testing.T, pl *pool.Pool, runtime *config.RuntimeConfig, log zerolog.Logger, allowed ...config.EgressKind) (*Server, string) {
	t.Helper()
	srv := newRuntimeServer(pl, runtime, log, allowed...)
	return srv, startServer(t, srv)
}

// newRunningServer builds the common fixture: one SOCKS server over a pool
// holding the given upstream routes, already listening.
func newRunningServer(t *testing.T, log zerolog.Logger, socks ...*fakeSocks) (*Server, string, *pool.Pool) {
	t.Helper()
	urls := make([]*url.URL, 0, len(socks))
	for _, fs := range socks {
		urls = append(urls, fs.URL)
	}
	pl := pool.NewRoutes(mixedRoutes(urls...), 30*time.Second, time.Minute, config.KindBalance{})
	s, addr := newSocksServer(t, pl, defaultRuntime(), log)
	return s, addr, pl
}

// --- SOCKS5 client helpers -------------------------------------------------

// socksGreetingFrame encodes VER NMETHODS METHODS...
func socksGreetingFrame(methods ...byte) []byte {
	return append([]byte{socksVersion, byte(len(methods))}, methods...)
}

// socksRequestFrame encodes one request for host:port. IPv4 and IPv6 literals
// are binary encoded; anything else becomes a domain name, so a test can send
// a textual name without resolving it.
func socksRequestFrame(cmd byte, target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("split target %q: %w", target, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("target %q has no usable port", target)
	}
	var atyp byte
	var addr []byte
	switch {
	case len(host) > 255:
		return nil, fmt.Errorf("target host %q is too long for a domain name", host)
	default:
		if ip := net.ParseIP(host); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				atyp, addr = socksAtypIPv4, v4
			} else {
				atyp, addr = socksAtypIPv6, ip.To16()
			}
		} else {
			atyp = socksAtypDomain
			addr = append([]byte{byte(len(host))}, host...)
		}
	}
	frame := make([]byte, 0, len(addr)+6)
	frame = append(frame, socksVersion, cmd, 0x00, atyp)
	frame = append(frame, addr...)
	return append(frame, byte(port>>8), byte(port)), nil
}

// socksConnectReply performs the RFC 1928 greeting plus one request against
// the gateway and returns the connection with its reply code. It never judges
// the code: callers decide what a test expects.
func socksConnectReply(t *testing.T, gatewayAddr, target string, cmd byte) (net.Conn, byte) {
	t.Helper()
	conn, err := net.Dial("tcp", gatewayAddr)
	if err != nil {
		t.Fatalf("dial gateway %s: %v", gatewayAddr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(socksGreetingFrame(socksAuthNone)); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if method[0] != socksVersion || method[1] != socksAuthNone {
		t.Fatalf("method selection = %#02x %#02x, want 05 00", method[0], method[1])
	}
	frame, err := socksRequestFrame(cmd, target)
	if err != nil {
		t.Fatalf("encode request for %s: %v", target, err)
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write request: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read SOCKS reply: %v", err)
	}
	if reply[0] != socksVersion {
		t.Fatalf("reply version = %#02x, want 05", reply[0])
	}
	// Established tunnels carry no timeouts.
	_ = conn.SetDeadline(time.Time{})
	return conn, reply[1]
}

// socksDialVia connects through the gateway to target and returns the tunnel
// after checking the success reply.
func socksDialVia(t *testing.T, gatewayAddr, target string) net.Conn {
	t.Helper()
	conn, code := socksConnectReply(t, gatewayAddr, target, socksCmdConnect)
	if code != socksReplySuccess {
		t.Fatalf("CONNECT reply = 0x%02x, want success 0x00", code)
	}
	return conn
}

// readBanner consumes the echo target's greeting bytes, proving the tunnel
// carries data from the upstream to the client before the client writes.
func readBanner(t *testing.T, conn net.Conn) string {
	t.Helper()
	banner := make([]byte, len("banner\n"))
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	return string(banner)
}

// --- raw protocol helpers --------------------------------------------------

// socksRejectCase is one inbound conversation the server must reject.
type socksRejectCase struct {
	name        string
	greeting    []byte
	methodReply bool   // consume the 2-byte method selection reply first
	request     []byte // sent after the method selection reply
	wantReply   []byte // bytes the server writes before closing; nil = silent close
	// truncated marks an incomplete frame: the server cannot know its length,
	// so the only correct behavior is to keep waiting (its handshake deadline
	// closes the session later) rather than to reply.
	truncated bool
}

// socksRejectExchange runs one reject conversation and returns the reply bytes
// the server wrote before closing (nothing for a silent parse rejection).
func socksRejectExchange(t *testing.T, addr string, tc socksRejectCase) []byte {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(tc.greeting); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	if tc.methodReply {
		method := make([]byte, 2)
		if _, err := io.ReadFull(conn, method); err != nil {
			t.Fatalf("read method selection: %v", err)
		}
		if method[0] != socksVersion || method[1] != socksAuthNone {
			t.Fatalf("method selection = %#02x %#02x, want 05 00", method[0], method[1])
		}
	}
	if len(tc.request) > 0 {
		if _, err := conn.Write(tc.request); err != nil {
			t.Fatalf("write request: %v", err)
		}
	}
	if len(tc.wantReply) > 0 {
		got := make([]byte, len(tc.wantReply))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("read reject reply: %v", err)
		}
		return got
	}
	// A rejected conversation must never write a reply: a complete but invalid
	// frame closes silently, an incomplete frame keeps waiting for the rest.
	// The exact read error is OS dependent (EOF, reset, or the test's own
	// deadline), so only silence is pinned here.
	window := 2 * time.Second
	if tc.truncated {
		window = 200 * time.Millisecond
	}
	_ = conn.SetReadDeadline(time.Now().Add(window))
	var one [1]byte
	if n, _ := conn.Read(one[:]); n != 0 {
		t.Fatalf("silent reject wrote % x", one[:n])
	}
	return nil
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
				// Let the SOCKS success reply reach the gateway before the
				// reset: a too-early RST can destroy the unread reply in
				// flight, which would be a handshake failure instead.
				time.Sleep(100 * time.Millisecond)
				if tc, ok := conn.(*net.TCPConn); ok {
					_ = tc.SetLinger(0) // reset instead of a clean close
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// --- protocol surface ------------------------------------------------------

func TestReadSocksRequestAcceptsConnectTargets(t *testing.T) {
	for _, tc := range []struct{ name, target string }{
		{"ipv4", "127.0.0.1:8080"},
		{"domain", "example.test:443"},
		{"ipv6", "[2001:db8::1]:443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverSide, clientSide := net.Pipe()
			defer func() { _ = serverSide.Close(); _ = clientSide.Close() }()
			type outcome struct {
				req socksRequest
				err error
			}
			results := make(chan outcome, 1)
			go func() {
				req, err := readSocksRequest(serverSide)
				results <- outcome{req: req, err: err}
			}()
			if _, err := clientSide.Write(socksGreetingFrame(socksAuthNone)); err != nil {
				t.Fatal(err)
			}
			method := make([]byte, 2)
			if _, err := io.ReadFull(clientSide, method); err != nil {
				t.Fatalf("read method selection: %v", err)
			}
			if method[0] != socksVersion || method[1] != socksAuthNone {
				t.Fatalf("method selection = %#02x %#02x, want 05 00", method[0], method[1])
			}
			frame, err := socksRequestFrame(socksCmdConnect, tc.target)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := clientSide.Write(frame); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-results:
				if got.err != nil {
					t.Fatalf("readSocksRequest: %v", got.err)
				}
				if got.req.target != tc.target || got.req.cmd != socksCmdConnect {
					t.Fatalf("request = %+v, want target %q cmd CONNECT", got.req, tc.target)
				}
			case <-time.After(time.Second):
				t.Fatal("readSocksRequest did not finish")
			}
		})
	}
}

func TestJoinSocksTarget(t *testing.T) {
	got, err := joinSocksTarget("example.test", []byte{0x01, 0xbb})
	if err != nil || got != "example.test:443" {
		t.Fatalf("joinSocksTarget = %q, %v; want example.test:443", got, err)
	}
	if _, err := joinSocksTarget("example.test", []byte{0x00, 0x00}); err == nil || !strings.Contains(err.Error(), "zero target port") {
		t.Fatalf("zero port error = %v, want a zero-target-port failure", err)
	}
}

func TestWriteSocksReplyShape(t *testing.T) {
	var wire bytes.Buffer
	if err := writeSocksReply(&wire, socksReplyCmdUnsupported); err != nil {
		t.Fatalf("writeSocksReply: %v", err)
	}
	want := []byte{socksVersion, socksReplyCmdUnsupported, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(wire.Bytes(), want) {
		t.Fatalf("reply = % x, want % x", wire.Bytes(), want)
	}
}

// --- relaying --------------------------------------------------------------

// A CONNECT tunnel must carry bytes both ways for every address type the
// client may name: IPv4, a domain name, and IPv6.
func TestSocksConnectRelaysBothDirections(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), 30*time.Second, time.Minute, config.KindBalance{})
	s, addr := newSocksServer(t, pl, defaultRuntime(), testLogger())

	t.Run("ipv4", func(t *testing.T) {
		testRelayRoundTrip(t, addr, startRawEchoTarget(t))
	})
	t.Run("domain", func(t *testing.T) {
		target := startRawEchoTarget(t)
		_, port, err := net.SplitHostPort(target)
		if err != nil {
			t.Fatal(err)
		}
		// The upstream dials the target text as given, so a dotted quad sent
		// as a domain name exercises the domain framing without DNS.
		testRelayRoundTrip(t, addr, net.JoinHostPort("127.0.0.1", port))
	})
	t.Run("ipv6", func(t *testing.T) {
		ln, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skipf("loopback IPv6 unavailable: %v", err)
		}
		testRelayRoundTrip(t, addr, serveEchoTarget(t, ln))
	})

	snap := pl.Snapshot()[0]
	if snap.Successes != 3 || snap.Failures != 0 || snap.AuthFailures != 0 {
		t.Fatalf("pool state = %+v, want three successes", snap)
	}
	if status := s.ListenerStatus(); status.Requests != 3 || status.Failovers != 0 {
		t.Fatalf("listener status = %+v", status)
	}
}

func testRelayRoundTrip(t *testing.T, gatewayAddr, target string) {
	t.Helper()
	conn := socksDialVia(t, gatewayAddr, target)
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
	_ = conn.Close()
}

// The tunnel is a raw byte stream: a plain HTTP round trip over it must work
// exactly as it would over a direct connection.
func TestTunnelCarriesHTTPTraffic(t *testing.T) {
	target := startEchoTarget(t)
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), 30*time.Second, time.Minute, config.KindBalance{})
	_, addr := newSocksServer(t, pl, defaultRuntime(), testLogger())

	conn := socksDialVia(t, addr, target)
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

// The server reads exact frame lengths: payload bytes a client pipelines in
// the same write as its CONNECT must reach the target untouched.
func TestPipelinedClientBytesReachTarget(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute, config.KindBalance{})
	s, addr := newSocksServer(t, pl, defaultRuntime(), testLogger())
	target := startRawEchoTarget(t)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	frame, err := socksRequestFrame(socksCmdConnect, target)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("TEST-prefix")
	blob := append(socksGreetingFrame(socksAuthNone), frame...)
	blob = append(blob, payload...)
	if _, err := conn.Write(blob); err != nil {
		t.Fatal(err)
	}

	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != socksReplySuccess {
		t.Fatalf("reply code = %#02x, want success", reply[1])
	}
	if got := readBanner(t, conn); got != "banner\n" {
		t.Fatalf("banner = %q", got)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatalf("pipelined bytes arrived as %q, want %q", echo, payload)
	}
	if status := s.ListenerStatus(); status.Requests != 1 {
		t.Fatalf("requests = %d, want 1", status.Requests)
	}
}

// --- protocol rejects ------------------------------------------------------

// Every malformed or unsupported inbound conversation must close without
// dialing anything: pool health and the request counter stay untouched, and
// the server logs exactly one bad_request line per reject.
func TestProtocolRejectsNeverTouchPoolOrCounters(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute, config.KindBalance{})
	var logs safeLogBuffer
	s, addr := newSocksServer(t, pl, defaultRuntime(), captureLogger(&logs))

	greeting := socksGreetingFrame(socksAuthNone)
	cases := []socksRejectCase{
		{name: "bad greeting version", greeting: []byte{0x04, 0x01, 0x00}},
		{name: "empty method list", greeting: []byte{0x05, 0x00}},
		{name: "no acceptable method", greeting: []byte{0x05, 0x02, 0x01, 0x02},
			wantReply: []byte{socksVersion, socksAuthUnaccepted}},
		{name: "truncated method list", greeting: []byte{0x05, 0x02, 0x00}, truncated: true},
		{name: "bad request version", greeting: greeting, methodReply: true,
			request: []byte{0x04, socksCmdConnect, 0x00, socksAtypIPv4, 127, 0, 0, 1, 0, 80}},
		{name: "non-zero reserved byte", greeting: greeting, methodReply: true,
			request: []byte{socksVersion, socksCmdConnect, 0x01, socksAtypIPv4, 127, 0, 0, 1, 0, 80}},
		{name: "unknown address type", greeting: greeting, methodReply: true,
			request: []byte{socksVersion, socksCmdConnect, 0x00, 0x80, 1, 2, 3, 4}},
		{name: "truncated ipv4 target", greeting: greeting, methodReply: true, truncated: true,
			request: []byte{socksVersion, socksCmdConnect, 0x00, socksAtypIPv4, 127, 0}},
		{name: "zero target port", greeting: greeting, methodReply: true,
			request: []byte{socksVersion, socksCmdConnect, 0x00, socksAtypIPv4, 127, 0, 0, 1, 0, 0}},
		{name: "empty domain name", greeting: greeting, methodReply: true,
			request: []byte{socksVersion, socksCmdConnect, 0x00, socksAtypDomain, 0x00, 0, 0}},
		{name: "truncated domain name", greeting: greeting, methodReply: true, truncated: true,
			request: []byte{socksVersion, socksCmdConnect, 0x00, socksAtypDomain, 0x05, 'a'}},
		{name: "truncated domain port", greeting: greeting, methodReply: true, truncated: true,
			request: []byte{socksVersion, socksCmdConnect, 0x00, socksAtypDomain, 0x03, 'a', 'b', 'c', 0x01}},
	}
	cmdUnsupportedReply := []byte{socksVersion, socksReplyCmdUnsupported, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0}
	for _, command := range []struct {
		name string
		cmd  byte
	}{{"bind command", socksCmdBind}, {"udp associate command", socksCmdUDPAssociate}} {
		frame, err := socksRequestFrame(command.cmd, "example.test:443")
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, socksRejectCase{
			name: command.name, greeting: greeting, methodReply: true,
			request: frame, wantReply: cmdUnsupportedReply,
		})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := socksRejectExchange(t, addr, tc)
			if !bytes.Equal(got, tc.wantReply) {
				t.Fatalf("reject reply = % x, want % x", got, tc.wantReply)
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

	output := logs.String()
	if got := countRecords(output, map[string]string{"error_kind": "bad_request"}); got != len(cases) {
		t.Fatalf("bad_request records = %d, want %d:\n%s", got, len(cases), output)
	}
	if _, ok := findRecord(output, map[string]string{"msg": "socks request rejected", "error_kind": "bad_request"}); !ok {
		t.Fatalf("parse rejects were not logged as rejections:\n%s", output)
	}
	if _, ok := findRecord(output, map[string]string{"msg": "socks command not supported", "error_kind": "bad_request"}); !ok {
		t.Fatalf("BIND/UDP rejects were not logged as unsupported commands:\n%s", output)
	}
}

// --- retry and health semantics -------------------------------------------

// An endpoint dial failure cools the route down, excludes it, and falls back
// to the next eligible route; the client sees only the successful tunnel.
func TestDialFailureCooldownsRouteExcludedAndFallsBack(t *testing.T) {
	dead := &url.URL{Scheme: "socks5", User: url.UserPassword("route-user", "route-password"), Host: "dead.test:1080"}
	good := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(dead, good.URL), 30*time.Second, time.Minute, config.KindBalance{})
	var logs safeLogBuffer
	s := newRuntimeServer(pl, defaultRuntime(), captureLogger(&logs))
	s.dial = func(ctx context.Context, pu *url.URL, target string, timeout time.Duration) (net.Conn, error) {
		if pu.Host == dead.Host {
			return nil, &ProxyDialError{Err: errors.New("connect refused")}
		}
		return dialVia(ctx, pu, target, timeout)
	}
	addr := startServer(t, s)

	conn := socksDialVia(t, addr, startRawEchoTarget(t))
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

// A SOCKS handshake failure before the tunnel exists is socks_connect: the
// same cooldown-and-fallback treatment as an endpoint dial failure.
func TestHandshakeFailureFallsBackWithSocksConnectKind(t *testing.T) {
	reject := startSocks5Proxy(t, socksOptions{connectRep: 0x05})
	good := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(reject.URL, good.URL), time.Second, time.Minute, config.KindBalance{})
	var logs safeLogBuffer
	_, addr := newSocksServer(t, pl, defaultRuntime(), captureLogger(&logs))

	conn := socksDialVia(t, addr, startRawEchoTarget(t))
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

// An authentication failure blocks the route for auth and allows a fallback,
// but never creates dial cooldown.
func TestAuthFailureFallsBackWithoutDialCooldown(t *testing.T) {
	bad := startSocks5Proxy(t, socksOptions{user: "TEST-user", pass: "TEST-pass"})
	good := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(bad.URL, good.URL), time.Second, time.Minute, config.KindBalance{})
	var logs safeLogBuffer
	_, addr := newSocksServer(t, pl, defaultRuntime(), captureLogger(&logs))

	conn := socksDialVia(t, addr, startRawEchoTarget(t))
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

// With one route that always rejects, the request exhausts the pool: the
// client gets the general-failure reply and the log names no_route.
func TestSingleRejectingRouteExhaustsToGeneralFailure(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{connectRep: 0x05})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute, config.KindBalance{})
	var logs safeLogBuffer
	s, addr := newSocksServer(t, pl, defaultRuntime(), captureLogger(&logs))

	conn, code := socksConnectReply(t, addr, "example.test:443", socksCmdConnect)
	_ = conn.Close()
	if code != socksReplyGeneral {
		t.Fatalf("reply = 0x%02x, want general failure 0x01", code)
	}

	snap := pl.Snapshot()[0]
	if snap.Failures != 1 || snap.Successes != 0 || snap.AuthFailures != 0 || snap.Available {
		t.Fatalf("handshake failure did not record route health: %+v", snap)
	}
	if got := len(fs.hits); got != 1 {
		t.Fatalf("upstream attempts = %d, want 1", got)
	}
	if status := s.ListenerStatus(); status.Requests != 1 || status.Failovers != 1 {
		t.Fatalf("listener status = %+v", status)
	}
	output := waitForRecord(t, &logs, map[string]string{"msg": "tunnel failed"})
	if _, ok := findRecord(output, map[string]string{
		"msg": "tunnel failed", "error_kind": "no_route", "attempts": "1",
	}); !ok {
		t.Errorf("logs missing the no_route record:\n%s", output)
	}
}

// A local setup failure replies once, retries nothing, and mutates no health:
// every route would fail identically, so cooldown would only poison the pool.
func TestSetupErrorRepliesFailureWithoutPoolMutation(t *testing.T) {
	good := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(good.URL), time.Second, time.Minute, config.KindBalance{})
	var logs safeLogBuffer
	s := newRuntimeServer(pl, defaultRuntime(), captureLogger(&logs))
	dials := 0
	s.dial = func(context.Context, *url.URL, string, time.Duration) (net.Conn, error) {
		dials++
		return nil, &SocksProtocolError{Op: "encode target", Err: errors.New("TEST oversized configured credentials")}
	}
	addr := startServer(t, s)

	conn, code := socksConnectReply(t, addr, "example.test:443", socksCmdConnect)
	_ = conn.Close()
	if code != socksReplyGeneral {
		t.Fatalf("reply = 0x%02x, want general failure 0x01", code)
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

// --- relay teardown and close records --------------------------------------

// A client that ends the stream first produces a routine close record at
// debug with both byte counts, and never touches route health.
func TestCloseRecordAfterClientCloses(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute, config.KindBalance{})
	var logs safeLogBuffer
	s, addr := newSocksServer(t, pl, defaultRuntime(), captureLogger(&logs))

	conn := socksDialVia(t, addr, startRawEchoTarget(t))
	if got := readBanner(t, conn); got != "banner\n" {
		t.Fatalf("banner = %q", got)
	}
	if _, err := conn.Write([]byte("abcd")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	echo := make([]byte, 4)
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	_ = conn.Close()

	output := waitForRecord(t, &logs, map[string]string{"msg": "tunnel closed"})
	rec, ok := findRecord(output, map[string]string{
		"msg":                      "tunnel closed",
		"close_reason":             "client_closed",
		"client_to_upstream_bytes": "4",
		"upstream_to_client_bytes": "11", // banner plus echo
	})
	if !ok {
		t.Errorf("close record missing expected fields:\n%s", output)
	} else if _, has := rec["duration"]; !has {
		t.Errorf("close record missing duration: %v", rec)
	}
	snap := pl.Snapshot()[0]
	if snap.Successes != 1 || snap.Failures != 0 || snap.AuthFailures != 0 {
		t.Fatalf("closing the tunnel mutated route health: %+v", snap)
	}
	if status := s.ListenerStatus(); status.Requests != 1 {
		t.Fatalf("listener status = %+v", status)
	}
}

// An upstream that ends the tunnel abnormally logs a broken-tunnel close at
// warn and resets the client side, so a truncated stream stays truncated.
func TestUpstreamBreakLogsBrokenCloseAndResetsClient(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute, config.KindBalance{})
	var logs safeLogBuffer
	_, addr := newSocksServer(t, pl, defaultRuntime(), captureLogger(&logs))

	conn := socksDialVia(t, addr, startAbortTarget(t))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(io.Discard, conn); err == nil {
		t.Fatal("tunnel stayed open after the target aborted the stream")
	}

	output := waitForRecord(t, &logs, map[string]string{"msg": "tunnel broken"})
	rec, ok := findRecord(output, map[string]string{
		"msg": "tunnel broken", "close_reason": "upstream_broken",
	})
	if _, ok := findRecord(output, map[string]string{
		"msg": "upstream broke the tunnel; client side set to reset on close",
	}); !ok {
		t.Errorf("logs missing the SetLinger debug record:\n%s", output)
	}
	if !ok {
		t.Errorf("logs missing the broken close record:\n%s", output)
	} else {
		for _, key := range []string{"client_to_upstream_bytes", "upstream_to_client_bytes", "duration", "error"} {
			if _, has := rec[key]; !has {
				t.Errorf("broken close record missing %q: %v", key, rec)
			}
		}
	}
	snap := pl.Snapshot()[0]
	if snap.Successes != 1 || snap.Failures != 0 || snap.AuthFailures != 0 {
		t.Fatalf("broken tunnel mutated route health: %+v", snap)
	}
}

// --- connection tracking and shutdown --------------------------------------

// waitTrackedConns waits until the server has accepted and started tracking
// want client sessions. Only pre-greeting sessions need this: a tunnel is
// tracked before its success reply reaches the client.
func waitTrackedConns(t *testing.T, s *Server, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		s.cmu.Lock()
		got := len(s.conns)
		s.cmu.Unlock()
		if got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("tracked sessions = %d, want %d", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// CloseConns must close both established tunnels and sessions still inside
// their handshake.
func TestCloseConnsClosesTunnelsAndHandshakes(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute, config.KindBalance{})
	s, addr := newSocksServer(t, pl, defaultRuntime(), testLogger())

	tunnel := socksDialVia(t, addr, startParkedTarget(t))
	parked, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer func() { _ = parked.Close() }()
	waitTrackedConns(t, s, 2)

	s.CloseConns()
	for name, conn := range map[string]net.Conn{"tunnel": tunnel, "handshake": parked} {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Errorf("%s connection stayed open after CloseConns", name)
		}
	}
}

// blockingCloseConn delays Close until released, so a test can observe
// whether the connection map stays locked while a Close blocks.
type blockingCloseConn struct {
	net.Conn
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *blockingCloseConn) Close() error {
	c.once.Do(func() { close(c.started) })
	<-c.release
	return c.Conn.Close()
}

func TestCloseConnsDoesNotHoldConnectionMapLockWhileClosing(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer func() { _ = clientSide.Close() }()
	conn := &blockingCloseConn{
		Conn:    serverSide,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	s := newRuntimeServer(pool.NewRoutes(nil, time.Second, time.Minute, config.KindBalance{}), defaultRuntime(), testLogger())
	if !s.beginSession(conn) {
		t.Fatal("beginSession refused a connection on a live server")
	}

	closed := make(chan struct{})
	go func() {
		s.CloseConns()
		close(closed)
	}()
	select {
	case <-conn.started:
	case <-time.After(time.Second):
		t.Fatal("CloseConns did not call connection Close")
	}

	untracked := make(chan struct{})
	go func() {
		s.untrackConn(conn)
		close(untracked)
	}()
	select {
	case <-untracked:
	case <-time.After(time.Second):
		t.Fatal("connection map lock remained held while Close blocked")
	}

	close(conn.release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("CloseConns did not return after Close unblocked")
	}
}

func TestShutdownWithNoSessionsReturnsNil(t *testing.T) {
	s := newRuntimeServer(pool.NewRoutes(nil, time.Second, time.Minute, config.KindBalance{}), defaultRuntime(), testLogger())
	done := make(chan error, 1)
	go func() { done <- s.Shutdown(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Shutdown = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Shutdown blocked with no live sessions")
	}
}

// Shutdown waits for a live session instead of tearing it down early.
func TestShutdownWaitsForActiveSession(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute, config.KindBalance{})
	s, addr := newSocksServer(t, pl, defaultRuntime(), testLogger())

	tunnel := socksDialVia(t, addr, startParkedTarget(t))
	done := make(chan error, 1)
	go func() { done <- s.Shutdown(context.Background()) }()
	select {
	case err := <-done:
		t.Fatalf("Shutdown returned %v while a session was live", err)
	case <-time.After(100 * time.Millisecond):
	}
	_ = tunnel.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Shutdown = %v, want nil after the session drained", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not return after the session closed")
	}
}

// A drain that outlives its budget force-closes the tracked client conns and
// reports the deadline.
func TestShutdownDeadlineForceClosesActiveSession(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute, config.KindBalance{})
	s, addr := newSocksServer(t, pl, defaultRuntime(), testLogger())

	tunnel := socksDialVia(t, addr, startParkedTarget(t))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := s.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v, want the context deadline", err)
	}
	_ = tunnel.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := tunnel.Read(make([]byte, 1)); err == nil {
		t.Fatal("tunnel stayed open after the shutdown deadline force-closed it")
	}
}

// --- admin -----------------------------------------------------------------

// requests counts only valid CONNECTs (protocol rejects never advance it) and
// failovers counts in-band route fallbacks.
func TestAdminStatusCountsConnectsAndFallbacks(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := &url.URL{Scheme: "socks5", Host: closed.Addr().String()}
	_ = closed.Close()
	good := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(dead, good.URL), 30*time.Second, time.Minute, config.KindBalance{})
	s := NewRuntime(pool.NewStore(defaultRuntime(), pl), testLogger(), "9.9.9-test", "mixed", config.EgressV4, config.EgressV6)
	addr := startServer(t, s)
	admin := httptest.NewServer(s.AdminMux())
	defer admin.Close()

	// A protocol reject must not move any counter.
	if got := socksRejectExchange(t, addr, socksRejectCase{greeting: []byte{0x04, 0x01, 0x00}}); len(got) != 0 {
		t.Fatalf("reject reply = % x, want silence", got)
	}
	conn := socksDialVia(t, addr, startRawEchoTarget(t))
	readBanner(t, conn)
	_ = conn.Close()

	hresp, err := http.Get(admin.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	hbody, _ := io.ReadAll(hresp.Body)
	_ = hresp.Body.Close()
	if hresp.StatusCode != http.StatusOK || strings.TrimSpace(string(hbody)) != "ok" {
		t.Fatalf("healthz status=%d body=%q", hresp.StatusCode, hbody)
	}

	sresp, err := http.Get(admin.URL + "/status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	defer func() { _ = sresp.Body.Close() }()
	if sresp.StatusCode != http.StatusOK {
		t.Fatalf("status code=%d", sresp.StatusCode)
	}
	var got struct {
		Version   string                    `json:"version"`
		Requests  uint64                    `json:"requests"`
		Failovers uint64                    `json:"failovers"`
		Listeners map[string]ListenerStatus `json:"listeners"`
		Pool      []pool.Status             `json:"pool"`
	}
	if err := json.NewDecoder(sresp.Body).Decode(&got); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if got.Version != "9.9.9-test" {
		t.Errorf("version = %q", got.Version)
	}
	if got.Requests != 1 || got.Failovers != 1 {
		t.Errorf("totals = %+v, want one request and one fallback", got)
	}
	if want := (ListenerStatus{Requests: 1, Failovers: 1}); got.Listeners["mixed"] != want {
		t.Errorf("listeners = %+v, want %+v", got.Listeners, want)
	}
	if len(got.Pool) != 2 {
		t.Fatalf("pool len = %d, want 2", len(got.Pool))
	}
	if got.Pool[0].Failures != 1 || got.Pool[1].Successes != 1 {
		t.Errorf("pool health = %+v", got.Pool)
	}
}

func TestDialTCPCancellationIsNotEndpointFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := dialTCP(ctx, "127.0.0.1:1", time.Second)
	if !errors.Is(err, context.Canceled) || isProxyDialError(err) {
		t.Fatalf("dialTCP cancellation = %T %v, want plain context cancellation", err, err)
	}
}
